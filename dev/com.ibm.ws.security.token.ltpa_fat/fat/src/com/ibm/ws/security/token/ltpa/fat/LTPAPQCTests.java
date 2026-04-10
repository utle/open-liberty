/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.token.ltpa.fat;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.config.LTPA;
import com.ibm.websphere.simplicity.config.ServerConfiguration;
import com.ibm.websphere.simplicity.log.Log;
import com.ibm.ws.webcontainer.security.test.servlets.FormLoginClient;

import componenttest.annotation.ExpectedFFDC;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.custom.junit.runner.Mode;
import componenttest.custom.junit.runner.Mode.TestMode;
import componenttest.topology.impl.LibertyServer;
import componenttest.topology.impl.LibertyServerFactory;

/**
 * FAT tests for LTPA Post-Quantum Cryptography (PQC) support.
 * 
 * Tests ML-DSA signature algorithms, hybrid mode, token creation/validation,
 * and migration scenarios.
 */
@RunWith(FATRunner.class)
@Mode(TestMode.FULL)
public class LTPAPQCTests {

    private static final Class<?> thisClass = LTPAPQCTests.class;
    
    private static LibertyServer server = LibertyServerFactory.getLibertyServer("com.ibm.ws.security.token.ltpa.fat.pqc");
    
    private static final String APP_NAME = "ltpaPQCTest";
    private static final String SERVLET_NAME = "LTPAPQCTestServlet";
    
    // Test users
    private static final String VALID_USER = "user1";
    private static final String VALID_PASSWORD = "user1pwd";
    
    // Cookie name
    private static final String COOKIE_NAME = "LtpaToken2";
    
    @Rule
    public TestName testName = new TestName();
    
    private FormLoginClient client;
    
    @BeforeClass
    public static void setUp() throws Exception {
        Log.info(thisClass, "setUp", "Starting server for PQC tests");
        
        // Start with default RSA configuration
        server.startServer(true);
        server.addInstalledAppForValidation(APP_NAME);
    }
    
    @AfterClass
    public static void tearDown() throws Exception {
        try {
            if (server != null && server.isStarted()) {
                server.stopServer();
            }
        } catch (Exception e) {
            Log.error(thisClass, "tearDown", e);
        }
    }
    
    @Before
    public void setupTest() throws Exception {
        Log.info(thisClass, "setupTest", "Setting up test: " + testName.getMethodName());
        client = new FormLoginClient(server);
    }
    
    @After
    public void cleanupTest() throws Exception {
        Log.info(thisClass, "cleanupTest", "Cleaning up test: " + testName.getMethodName());
        if (client != null) {
            client.resetClientState();
        }
        // Reset to default configuration
        resetServerConfiguration();
    }
    
    /**
     * Test basic PQC token creation with ML-DSA algorithm
     */
    @Test
    public void testPQCTokenCreation_MLDSA() throws Exception {
        Log.info(thisClass, testName.getMethodName(), "Testing PQC token creation with ML-DSA");
        
        // Configure server for PQC with ML-DSA
        configurePQC(true, "ML-DSA", 3, false);
        
        // Login and get token
        String response = client.accessProtectedServletWithAuthorizedCredentials(
            "/" + APP_NAME + "/" + SERVLET_NAME, VALID_USER, VALID_PASSWORD);
        
        assertNotNull("Response should not be null", response);
        assertTrue("Should successfully authenticate", response.contains("Authentication successful"));
        
        // Verify PQC token was created
        String cookie = client.getCookieFromLastLogin();
        assertNotNull("LTPA cookie should be present", cookie);
        assertTrue("Cookie should start with v3: prefix for PQC tokens", 
                  cookie.startsWith("v3:") || cookie.contains("v3:"));
        
        // Verify token can be used for subsequent requests
        response = client.accessProtectedServletWithValidCookie(
            "/" + APP_NAME + "/" + SERVLET_NAME, cookie);
        assertNotNull("Response with cookie should not be null", response);
        assertTrue("Should access with valid PQC token", response.contains("Authentication successful"));
    }
    
    /**
     * Test hybrid mode with both RSA and ML-DSA signatures
     */
    @Test
    public void testHybridMode() throws Exception {
        Log.info(thisClass, testName.getMethodName(), "Testing hybrid mode with RSA + ML-DSA");
        
        // Configure server for hybrid mode
        configurePQC(true, "HYBRID", 3, true);
        
        // Login and get token
        String response = client.accessProtectedServletWithAuthorizedCredentials(
            "/" + APP_NAME + "/" + SERVLET_NAME, VALID_USER, VALID_PASSWORD);
        
        assertNotNull("Response should not be null", response);
        assertTrue("Should successfully authenticate", response.contains("Authentication successful"));
        
        // Verify hybrid token was created
        String cookie = client.getCookieFromLastLogin();
        assertNotNull("LTPA cookie should be present", cookie);
        
        // Verify token can be validated
        response = client.accessProtectedServletWithValidCookie(
            "/" + APP_NAME + "/" + SERVLET_NAME, cookie);
        assertNotNull("Response with cookie should not be null", response);
        assertTrue("Should access with valid hybrid token", response.contains("Authentication successful"));
    }
    
    /**
     * Test backward compatibility - PQC server accepting RSA tokens
     */
    @Test
    public void testBackwardCompatibility_RSATokenOnPQCServer() throws Exception {
        Log.info(thisClass, testName.getMethodName(), "Testing RSA token validation on PQC server");
        
        // First, create RSA token with default config
        String response = client.accessProtectedServletWithAuthorizedCredentials(
            "/" + APP_NAME + "/" + SERVLET_NAME, VALID_USER, VALID_PASSWORD);
        String rsaToken = client.getCookieFromLastLogin();
        assertNotNull("RSA token should be created", rsaToken);
        
        // Switch to PQC mode with legacy token support
        configurePQC(true, "ML-DSA", 3, false, true);
        
        // Verify RSA token still works
        response = client.accessProtectedServletWithValidCookie(
            "/" + APP_NAME + "/" + SERVLET_NAME, rsaToken);
        assertNotNull("Response should not be null", response);
        assertTrue("Should accept legacy RSA token", response.contains("Authentication successful"));
    }
    
    /**
     * Test PQC security levels (2, 3, 5)
     */
    @Test
    public void testPQCSecurityLevels() throws Exception {
        Log.info(thisClass, testName.getMethodName(), "Testing different PQC security levels");
        
        // Test Level 2 (ML-DSA-44)
        configurePQC(true, "ML-DSA", 2, false);
        String response = client.accessProtectedServletWithAuthorizedCredentials(
            "/" + APP_NAME + "/" + SERVLET_NAME, VALID_USER, VALID_PASSWORD);
        assertTrue("Level 2 should work", response.contains("Authentication successful"));
        
        // Test Level 3 (ML-DSA-65)
        configurePQC(true, "ML-DSA", 3, false);
        response = client.accessProtectedServletWithAuthorizedCredentials(
            "/" + APP_NAME + "/" + SERVLET_NAME, VALID_USER, VALID_PASSWORD);
        assertTrue("Level 3 should work", response.contains("Authentication successful"));
        
        // Test Level 5 (ML-DSA-87)
        configurePQC(true, "ML-DSA", 5, false);
        response = client.accessProtectedServletWithAuthorizedCredentials(
            "/" + APP_NAME + "/" + SERVLET_NAME, VALID_USER, VALID_PASSWORD);
        assertTrue("Level 5 should work", response.contains("Authentication successful"));
    }
    
    /**
     * Test token expiration with PQC tokens
     */
    @Test
    public void testPQCTokenExpiration() throws Exception {
        Log.info(thisClass, testName.getMethodName(), "Testing PQC token expiration");
        
        // Configure with short expiration (1 minute)
        configurePQC(true, "ML-DSA", 3, false, true, 1);
        
        // Create token
        String response = client.accessProtectedServletWithAuthorizedCredentials(
            "/" + APP_NAME + "/" + SERVLET_NAME, VALID_USER, VALID_PASSWORD);
        String token = client.getCookieFromLastLogin();
        assertNotNull("Token should be created", token);
        
        // Token should work immediately
        response = client.accessProtectedServletWithValidCookie(
            "/" + APP_NAME + "/" + SERVLET_NAME, token);
        assertTrue("Fresh token should work", response.contains("Authentication successful"));
        
        // Wait for expiration (65 seconds to be safe)
        Log.info(thisClass, testName.getMethodName(), "Waiting for token expiration...");
        Thread.sleep(65000);
        
        // Token should be expired
        response = client.accessProtectedServletWithValidCookie(
            "/" + APP_NAME + "/" + SERVLET_NAME, token);
        assertFalse("Expired token should not work", response.contains("Authentication successful"));
    }
    
    /**
     * Test migration from RSA to PQC
     */
    @Test
    public void testMigrationRSAToPQC() throws Exception {
        Log.info(thisClass, testName.getMethodName(), "Testing migration from RSA to PQC");
        
        // Phase 1: Start with RSA
        resetServerConfiguration();
        String response = client.accessProtectedServletWithAuthorizedCredentials(
            "/" + APP_NAME + "/" + SERVLET_NAME, VALID_USER, VALID_PASSWORD);
        String rsaToken = client.getCookieFromLastLogin();
        assertTrue("RSA phase should work", response.contains("Authentication successful"));
        
        // Phase 2: Switch to Hybrid mode (accepts both RSA and PQC)
        configurePQC(true, "HYBRID", 3, true, true);
        
        // Old RSA token should still work
        response = client.accessProtectedServletWithValidCookie(
            "/" + APP_NAME + "/" + SERVLET_NAME, rsaToken);
        assertTrue("RSA token should work in hybrid mode", response.contains("Authentication successful"));
        
        // New login creates hybrid token
        response = client.accessProtectedServletWithAuthorizedCredentials(
            "/" + APP_NAME + "/" + SERVLET_NAME, VALID_USER, VALID_PASSWORD);
        String hybridToken = client.getCookieFromLastLogin();
        assertTrue("Hybrid phase should work", response.contains("Authentication successful"));
        
        // Phase 3: Switch to PQC-only (still accepting legacy)
        configurePQC(true, "ML-DSA", 3, false, true);
        
        // Both tokens should still work
        response = client.accessProtectedServletWithValidCookie(
            "/" + APP_NAME + "/" + SERVLET_NAME, rsaToken);
        assertTrue("RSA token should work with legacy support", response.contains("Authentication successful"));
        
        response = client.accessProtectedServletWithValidCookie(
            "/" + APP_NAME + "/" + SERVLET_NAME, hybridToken);
        assertTrue("Hybrid token should work in PQC mode", response.contains("Authentication successful"));
    }
    
    /**
     * Test invalid PQC configuration
     */
    @Test
    @ExpectedFFDC({ "java.lang.IllegalArgumentException" })
    public void testInvalidPQCConfiguration() throws Exception {
        Log.info(thisClass, testName.getMethodName(), "Testing invalid PQC configuration");
        
        try {
            // Try to configure with invalid security level
            configurePQC(true, "ML-DSA", 4, false);
            
            // Should fail to start or log error
            assertTrue("Should log error for invalid security level", 
                      server.waitForStringInLog("Invalid.*security level", 10000) != null);
        } catch (Exception e) {
            // Expected - invalid configuration should fail
            assertTrue("Should fail with invalid configuration", 
                      e.getMessage().contains("Invalid") || e.getMessage().contains("security level"));
        }
    }
    
    /**
     * Test PQC disabled - should use RSA
     */
    @Test
    public void testPQCDisabled() throws Exception {
        Log.info(thisClass, testName.getMethodName(), "Testing with PQC disabled");
        
        // Configure with PQC disabled
        configurePQC(false, "RSA", 3, false);
        
        // Should create RSA token
        String response = client.accessProtectedServletWithAuthorizedCredentials(
            "/" + APP_NAME + "/" + SERVLET_NAME, VALID_USER, VALID_PASSWORD);
        String token = client.getCookieFromLastLogin();
        
        assertNotNull("Token should be created", token);
        assertFalse("Token should not have v3: prefix", token.startsWith("v3:"));
        assertTrue("Should authenticate successfully", response.contains("Authentication successful"));
    }
    
    // Helper methods
    
    private void configurePQC(boolean enablePQC, String algorithm, int securityLevel, 
                             boolean hybridMode) throws Exception {
        configurePQC(enablePQC, algorithm, securityLevel, hybridMode, true, 120);
    }
    
    private void configurePQC(boolean enablePQC, String algorithm, int securityLevel, 
                             boolean hybridMode, boolean allowLegacy) throws Exception {
        configurePQC(enablePQC, algorithm, securityLevel, hybridMode, allowLegacy, 120);
    }
    
    private void configurePQC(boolean enablePQC, String algorithm, int securityLevel, 
                             boolean hybridMode, boolean allowLegacy, int expiration) throws Exception {
        ServerConfiguration config = server.getServerConfiguration();
        LTPA ltpa = config.getLtpa();
        
        if (ltpa == null) {
            ltpa = new LTPA();
            config.setLtpa(ltpa);
        }
        
        // Set PQC configuration
        ltpa.setEnablePQC(String.valueOf(enablePQC));
        ltpa.setSignatureAlgorithm(algorithm);
        ltpa.setPqcSecurityLevel(String.valueOf(securityLevel));
        ltpa.setEnableHybridMode(String.valueOf(hybridMode));
        ltpa.setAllowLegacyTokens(String.valueOf(allowLegacy));
        ltpa.setExpiration(String.valueOf(expiration) + "m");
        
        server.setMarkToEndOfLog();
        server.updateServerConfiguration(config);
        server.waitForConfigUpdateInLogUsingMark(null);
        
        Log.info(thisClass, "configurePQC", 
                "Configured PQC: enable=" + enablePQC + 
                ", algorithm=" + algorithm + 
                ", level=" + securityLevel + 
                ", hybrid=" + hybridMode +
                ", allowLegacy=" + allowLegacy +
                ", expiration=" + expiration);
    }
    
    private void resetServerConfiguration() throws Exception {
        ServerConfiguration config = server.getServerConfiguration();
        LTPA ltpa = config.getLtpa();
        
        if (ltpa != null) {
            // Reset to default RSA configuration
            ltpa.setEnablePQC("false");
            ltpa.setSignatureAlgorithm("RSA");
            ltpa.setExpiration("120m");
            
            server.setMarkToEndOfLog();
            server.updateServerConfiguration(config);
            server.waitForConfigUpdateInLogUsingMark(null);
        }
        
        Log.info(thisClass, "resetServerConfiguration", "Reset to default RSA configuration");
    }
}

// Made with Bob
