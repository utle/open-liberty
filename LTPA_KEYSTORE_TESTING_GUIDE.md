# LTPA Keystore Testing Guide

## Overview

This document provides comprehensive testing scenarios, test cases, and validation procedures for the LTPA keystore integration feature.

## Table of Contents

1. [Test Strategy](#test-strategy)
2. [Unit Tests](#unit-tests)
3. [Integration Tests](#integration-tests)
4. [Security Tests](#security-tests)
5. [Performance Tests](#performance-tests)
6. [Migration Tests](#migration-tests)
7. [Compatibility Tests](#compatibility-tests)
8. [Test Data Setup](#test-data-setup)

## Test Strategy

### Testing Levels

1. **Unit Tests**: Test individual components in isolation
2. **Integration Tests**: Test component interactions
3. **Functional Tests**: Test end-to-end scenarios
4. **Security Tests**: Validate security requirements
5. **Performance Tests**: Measure performance impact
6. **Compatibility Tests**: Ensure backward compatibility

### Test Coverage Goals

- Code coverage: >80%
- Branch coverage: >75%
- All configuration patterns tested
- All error scenarios covered
- Security requirements validated

## Unit Tests

### Test Suite 1: LTPAKeyInfoManager Tests

**File:** `LTPAKeyInfoManagerKeystoreTest.java`

```java
package com.ibm.ws.security.token.ltpa;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.ibm.ws.ssl.KeyStoreService;

public class LTPAKeyInfoManagerKeystoreTest {
    
    @Mock
    private KeyStoreService mockKeyStoreService;
    
    @Mock
    private KeyStore mockKeyStore;
    
    private LTPAKeyInfoManager manager;
    
    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        manager = new LTPAKeyInfoManager();
        manager.setKeyStoreService(mockKeyStoreService);
    }
    
    @Test
    public void testLoadKeysFromKeystore_Success() throws Exception {
        // Setup test keys
        SecretKey secretKey = new SecretKeySpec(new byte[24], "DESede");
        PrivateKey privateKey = generateTestPrivateKey();
        Certificate cert = generateTestCertificate();
        
        when(mockKeyStoreService.getKeyStore("testKeyStore")).thenReturn(mockKeyStore);
        when(mockKeyStore.getKey("ltpaSecret", "password".toCharArray())).thenReturn(secretKey);
        when(mockKeyStore.getKey("ltpaPrivate", "password".toCharArray())).thenReturn(privateKey);
        when(mockKeyStore.getCertificate("ltpaPublic")).thenReturn(cert);
        
        // Execute
        manager.prepareLTPAKeyInfoFromKeyStore(
            "testKeyStore",
            "ltpaSecret",
            "ltpaPrivate",
            "ltpaPublic",
            "password".toCharArray()
        );
        
        // Verify
        String cacheKey = "testKeyStore:ltpaSecret";
        assertNotNull("Secret key should be cached", manager.getSecretKey(cacheKey));
        assertNotNull("Private key should be cached", manager.getPrivateKey(cacheKey));
        assertNotNull("Public key should be cached", manager.getPublicKey(cacheKey));
        assertNotNull("Realm should be cached", manager.getRealm(cacheKey));
    }
    
    @Test(expected = Exception.class)
    public void testLoadKeysFromKeystore_KeyStoreNotFound() throws Exception {
        when(mockKeyStoreService.getKeyStore("nonexistent"))
            .thenThrow(new java.security.KeyStoreException("Keystore not found"));
        
        manager.prepareLTPAKeyInfoFromKeyStore(
            "nonexistent",
            "ltpaSecret",
            "ltpaPrivate",
            "ltpaPublic",
            "password".toCharArray()
        );
    }
    
    @Test(expected = Exception.class)
    public void testLoadKeysFromKeystore_SecretKeyNotFound() throws Exception {
        when(mockKeyStoreService.getKeyStore("testKeyStore")).thenReturn(mockKeyStore);
        when(mockKeyStore.getKey("ltpaSecret", "password".toCharArray())).thenReturn(null);
        
        manager.prepareLTPAKeyInfoFromKeyStore(
            "testKeyStore",
            "ltpaSecret",
            "ltpaPrivate",
            "ltpaPublic",
            "password".toCharArray()
        );
    }
    
    @Test(expected = Exception.class)
    public void testLoadKeysFromKeystore_WrongPassword() throws Exception {
        when(mockKeyStoreService.getKeyStore("testKeyStore")).thenReturn(mockKeyStore);
        when(mockKeyStore.getKey("ltpaSecret", "wrongpassword".toCharArray()))
            .thenThrow(new java.security.UnrecoverableKeyException("Wrong password"));
        
        manager.prepareLTPAKeyInfoFromKeyStore(
            "testKeyStore",
            "ltpaSecret",
            "ltpaPrivate",
            "ltpaPublic",
            "wrongpassword".toCharArray()
        );
    }
    
    @Test
    public void testLoadKeysFromKeystore_WrongKeyType() throws Exception {
        // Setup AES key instead of 3DES
        SecretKey wrongKey = new SecretKeySpec(new byte[16], "AES");
        
        when(mockKeyStoreService.getKeyStore("testKeyStore")).thenReturn(mockKeyStore);
        when(mockKeyStore.getKey("ltpaSecret", "password".toCharArray())).thenReturn(wrongKey);
        
        try {
            manager.prepareLTPAKeyInfoFromKeyStore(
                "testKeyStore",
                "ltpaSecret",
                "ltpaPrivate",
                "ltpaPublic",
                "password".toCharArray()
            );
            // Should log warning but continue
        } catch (Exception e) {
            fail("Should handle wrong key type gracefully");
        }
    }
    
    @Test
    public void testHybridMode_KeystoreSuccess() throws Exception {
        // Setup keystore to succeed
        SecretKey secretKey = new SecretKeySpec(new byte[24], "DESede");
        PrivateKey privateKey = generateTestPrivateKey();
        Certificate cert = generateTestCertificate();
        
        when(mockKeyStoreService.getKeyStore("testKeyStore")).thenReturn(mockKeyStore);
        when(mockKeyStore.getKey(anyString(), any())).thenReturn(secretKey, privateKey);
        when(mockKeyStore.getCertificate(anyString())).thenReturn(cert);
        
        // Execute hybrid mode
        manager.prepareLTPAKeyInfoHybrid(
            null, // locService
            "ltpa.keys", // file
            "filepass".getBytes(), // file password
            "testKeyStore", // keystore
            "ltpaSecret",
            "ltpaPrivate",
            "ltpaPublic",
            "keystorepass".toCharArray(),
            true // prefer keystore
        );
        
        // Verify keystore was used
        verify(mockKeyStoreService).getKeyStore("testKeyStore");
    }
    
    @Test
    public void testHybridMode_FallbackToFile() throws Exception {
        // Setup keystore to fail
        when(mockKeyStoreService.getKeyStore("testKeyStore"))
            .thenThrow(new java.security.KeyStoreException("Not found"));
        
        // Mock file loading (would need actual implementation)
        // This test verifies fallback behavior
        
        try {
            manager.prepareLTPAKeyInfoHybrid(
                null,
                "ltpa.keys",
                "filepass".getBytes(),
                "testKeyStore",
                "ltpaSecret",
                "ltpaPrivate",
                "ltpaPublic",
                "keystorepass".toCharArray(),
                true
            );
            // Should fall back to file
        } catch (Exception e) {
            // Expected if file also doesn't exist
        }
        
        verify(mockKeyStoreService).getKeyStore("testKeyStore");
    }
    
    private PrivateKey generateTestPrivateKey() throws Exception {
        java.security.KeyPairGenerator keyGen = 
            java.security.KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair().getPrivate();
    }
    
    private Certificate generateTestCertificate() throws Exception {
        java.security.KeyPairGenerator keyGen = 
            java.security.KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        java.security.KeyPair keyPair = keyGen.generateKeyPair();
        
        // Generate self-signed certificate
        return CertificateGenerator.generateSelfSignedCertificate(
            keyPair.getPrivate(),
            keyPair.getPublic(),
            "CN=Test,O=TestRealm",
            365
        );
    }
}
```

### Test Suite 2: LTPAConfigurationImpl Tests

```java
package com.ibm.ws.security.token.ltpa.internal;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.osgi.service.component.ComponentContext;

import com.ibm.ws.ssl.KeyStoreService;
import com.ibm.wsspi.kernel.service.utils.SerializableProtectedString;

public class LTPAConfigurationImplKeystoreTest {
    
    @Mock
    private ComponentContext mockContext;
    
    @Mock
    private KeyStoreService mockKeyStoreService;
    
    private LTPAConfigurationImpl config;
    
    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        config = new LTPAConfigurationImpl();
    }
    
    @Test
    public void testKeystoreConfiguration_Valid() {
        Map<String, Object> props = new HashMap<>();
        props.put("keyStoreRef", "ltpaKeyStore");
        props.put("keyAlias", "ltpaKey");
        props.put("useKeyStore", true);
        props.put(LTPAConfiguration.CFG_KEY_TOKEN_EXPIRATION, 120L);
        props.put(LTPAConfiguration.CFG_KEY_MONITOR_INTERVAL, 0L);
        props.put(LTPAConfiguration.CFG_KEY_MONITOR_VALIDATION_KEYS_DIR, false);
        props.put(LTPAConfiguration.CFG_KEY_UPDATE_TRIGGER, "disabled");
        props.put("expirationDifferenceAllowed", 0L);
        
        // Should not throw exception
        config.loadConfig(props);
        
        assertEquals("ltpaKeyStore", config.getKeyStoreRef());
        assertEquals("ltpaKey", config.getKeyAlias());
        assertEquals("ltpaKeySecret", config.getSecretKeyAlias());
        assertEquals("ltpaKeyPrivate", config.getPrivateKeyAlias());
        assertEquals("ltpaKeyPublic", config.getPublicKeyAlias());
        assertTrue(config.isUseKeyStore());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testKeystoreConfiguration_MissingKeyStoreRef() {
        Map<String, Object> props = new HashMap<>();
        props.put("useKeyStore", true);
        // Missing keyStoreRef
        
        config.loadConfig(props);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testKeystoreConfiguration_MissingKeyAliases() {
        Map<String, Object> props = new HashMap<>();
        props.put("keyStoreRef", "ltpaKeyStore");
        props.put("useKeyStore", true);
        // Missing keyAlias and specific aliases
        
        config.loadConfig(props);
    }
    
    @Test
    public void testKeystoreConfiguration_SpecificAliases() {
        Map<String, Object> props = new HashMap<>();
        props.put("keyStoreRef", "ltpaKeyStore");
        props.put("secretKeyAlias", "mySecret");
        props.put("privateKeyAlias", "myPrivate");
        props.put("publicKeyAlias", "myPublic");
        props.put("useKeyStore", true);
        props.put(LTPAConfiguration.CFG_KEY_TOKEN_EXPIRATION, 120L);
        props.put(LTPAConfiguration.CFG_KEY_MONITOR_INTERVAL, 0L);
        props.put(LTPAConfiguration.CFG_KEY_MONITOR_VALIDATION_KEYS_DIR, false);
        props.put(LTPAConfiguration.CFG_KEY_UPDATE_TRIGGER, "disabled");
        props.put("expirationDifferenceAllowed", 0L);
        
        config.loadConfig(props);
        
        assertEquals("mySecret", config.getSecretKeyAlias());
        assertEquals("myPrivate", config.getPrivateKeyAlias());
        assertEquals("myPublic", config.getPublicKeyAlias());
    }
    
    @Test
    public void testHybridMode_Detection() {
        Map<String, Object> props = new HashMap<>();
        props.put(LTPAConfiguration.CFG_KEY_IMPORT_FILE, "ltpa.keys");
        props.put(LTPAConfiguration.CFG_KEY_PASSWORD, 
            new SerializableProtectedString("password".toCharArray()));
        props.put("keyStoreRef", "ltpaKeyStore");
        props.put("keyAlias", "ltpaKey");
        props.put("useKeyStore", true);
        props.put(LTPAConfiguration.CFG_KEY_TOKEN_EXPIRATION, 120L);
        props.put(LTPAConfiguration.CFG_KEY_MONITOR_INTERVAL, 0L);
        props.put(LTPAConfiguration.CFG_KEY_MONITOR_VALIDATION_KEYS_DIR, false);
        props.put(LTPAConfiguration.CFG_KEY_UPDATE_TRIGGER, "disabled");
        props.put("expirationDifferenceAllowed", 0L);
        
        config.loadConfig(props);
        
        assertTrue("Should detect hybrid mode", config.isHybridMode());
    }
}
```

## Integration Tests

### Test Suite 3: End-to-End LTPA Token Tests

```java
package com.ibm.ws.security.token.ltpa.fat;

import static org.junit.Assert.*;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import componenttest.annotation.Server;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.topology.impl.LibertyServer;

@RunWith(FATRunner.class)
public class LTPAKeystoreIntegrationTest {
    
    @Server("ltpaKeystoreServer")
    public static LibertyServer server;
    
    @BeforeClass
    public static void setUp() throws Exception {
        // Setup keystore with LTPA keys
        setupTestKeystore();
        
        // Start server with keystore configuration
        server.setServerConfigurationFile("ltpa_keystore.xml");
        server.startServer();
        
        // Wait for LTPA to be ready
        assertNotNull("LTPA should load from keystore",
            server.waitForStringInLog("CWWKS4128I.*ltpaKeyStore"));
    }
    
    @AfterClass
    public static void tearDown() throws Exception {
        server.stopServer();
    }
    
    @Test
    public void testCreateAndValidateToken_KeystoreKeys() throws Exception {
        // Create LTPA token
        String token = createLTPAToken("testuser", "testgroup");
        assertNotNull("Token should be created", token);
        
        // Validate token
        Subject subject = validateLTPAToken(token);
        assertNotNull("Subject should be created", subject);
        
        // Verify user
        String username = getUserFromSubject(subject);
        assertEquals("testuser", username);
    }
    
    @Test
    public void testTokenExpiration_KeystoreKeys() throws Exception {
        // Create token with short expiration
        String token = createLTPATokenWithExpiration("testuser", 1); // 1 minute
        
        // Validate immediately - should succeed
        Subject subject = validateLTPAToken(token);
        assertNotNull(subject);
        
        // Wait for expiration
        Thread.sleep(65000); // 65 seconds
        
        // Validate again - should fail
        try {
            validateLTPAToken(token);
            fail("Should reject expired token");
        } catch (Exception e) {
            assertTrue("Should be expiration error", 
                e.getMessage().contains("expired"));
        }
    }
    
    @Test
    public void testMultipleServers_SharedKeystore() throws Exception {
        // Start second server with same keystore
        LibertyServer server2 = LibertyServerFactory.getLibertyServer("ltpaKeystoreServer2");
        server2.setServerConfigurationFile("ltpa_keystore_shared.xml");
        server2.startServer();
        
        try {
            // Create token on server1
            String token = createLTPAToken("testuser");
            
            // Validate on server2
            Subject subject = validateLTPATokenOnServer(server2, token);
            assertNotNull("Token should be valid on server2", subject);
            
        } finally {
            server2.stopServer();
        }
    }
    
    @Test
    public void testValidationKeys_MultipleKeystores() throws Exception {
        // Configure server with validation keys from different keystore
        server.setMarkToEndOfLog();
        server.setServerConfigurationFile("ltpa_keystore_validation.xml");
        server.waitForConfigUpdateInLogUsingMark(null);
        
        // Create token with old key
        String oldToken = createLTPATokenWithKeystore("oldKeyStore", "testuser");
        
        // Validate with new primary key and old validation key
        Subject subject = validateLTPAToken(oldToken);
        assertNotNull("Old token should validate with validation key", subject);
    }
    
    private static void setupTestKeystore() throws Exception {
        // Use migration tool to create test keystore
        String[] args = {
            "--ltpaKeysFile=" + server.getServerRoot() + "/ltpa.keys",
            "--ltpaKeysPassword=password",
            "--keyStore=" + server.getServerRoot() + "/resources/security/ltpa.p12",
            "--keyStorePassword=keystorePassword",
            "--keyAlias=ltpaKey"
        };
        
        MigrateLTPAKeysTask task = new MigrateLTPAKeysTask();
        task.execute(args);
    }
}
```

### Test Suite 4: Configuration Update Tests

```java
@Test
public void testDynamicConfigUpdate_SwitchToKeystore() throws Exception {
    // Start with file-based configuration
    server.setServerConfigurationFile("ltpa_file.xml");
    server.startServer();
    
    // Create token with file-based keys
    String token1 = createLTPAToken("testuser");
    
    // Switch to keystore configuration
    server.setMarkToEndOfLog();
    server.setServerConfigurationFile("ltpa_keystore.xml");
    server.waitForConfigUpdateInLogUsingMark(null);
    
    // Wait for keystore to load
    assertNotNull(server.waitForStringInLog("CWWKS4128I.*ltpaKeyStore"));
    
    // Old token should still validate (same keys)
    Subject subject = validateLTPAToken(token1);
    assertNotNull(subject);
    
    // New token should be created with keystore keys
    String token2 = createLTPAToken("testuser2");
    subject = validateLTPAToken(token2);
    assertNotNull(subject);
}
```

## Security Tests

### Test Suite 5: Security Validation Tests

```java
package com.ibm.ws.security.token.ltpa.security;

import org.junit.Test;
import static org.junit.Assert.*;

public class LTPAKeystoreSecurityTest {
    
    @Test
    public void testPasswordProtection_KeystoreAccess() throws Exception {
        // Attempt to access keystore with wrong password
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream("ltpa.p12"), "wrongpassword".toCharArray());
            fail("Should reject wrong password");
        } catch (IOException e) {
            assertTrue("Should be password error", 
                e.getCause() instanceof UnrecoverableKeyException);
        }
    }
    
    @Test
    public void testKeyAccess_WrongPassword() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("ltpa.p12"), "correctpassword".toCharArray());
        
        try {
            ks.getKey("ltpaKeySecret", "wrongpassword".toCharArray());
            fail("Should reject wrong key password");
        } catch (UnrecoverableKeyException e) {
            // Expected
        }
    }
    
    @Test
    public void testKeyType_Validation() throws Exception {
        // Verify secret key is 3DES
        KeyStore ks = loadTestKeystore();
        SecretKey key = (SecretKey) ks.getKey("ltpaKeySecret", "password".toCharArray());
        
        assertEquals("DESede", key.getAlgorithm());
        assertEquals(24, key.getEncoded().length); // 192 bits
    }
    
    @Test
    public void testPrivateKey_RSA() throws Exception {
        // Verify private key is RSA with sufficient strength
        KeyStore ks = loadTestKeystore();
        PrivateKey key = (PrivateKey) ks.getKey("ltpaKeyPrivate", "password".toCharArray());
        
        assertEquals("RSA", key.getAlgorithm());
        
        // Verify key size >= 2048 bits
        if (key instanceof java.security.interfaces.RSAPrivateKey) {
            java.security.interfaces.RSAPrivateKey rsaKey = 
                (java.security.interfaces.RSAPrivateKey) key;
            assertTrue("Key size should be >= 2048 bits", 
                rsaKey.getModulus().bitLength() >= 2048);
        }
    }
    
    @Test
    public void testHSM_Integration() throws Exception {
        // Test with PKCS11 provider (if available)
        try {
            KeyStore ks = KeyStore.getInstance("PKCS11");
            // HSM-specific test
        } catch (KeyStoreException e) {
            // Skip if PKCS11 not available
            System.out.println("PKCS11 not available, skipping HSM test");
        }
    }
    
    @Test
    public void testCertificate_Validation() throws Exception {
        KeyStore ks = loadTestKeystore();
        Certificate cert = ks.getCertificate("ltpaKeyPublic");
        
        assertNotNull("Certificate should exist", cert);
        assertTrue("Should be X509 certificate", 
            cert instanceof X509Certificate);
        
        X509Certificate x509 = (X509Certificate) cert;
        
        // Verify certificate is not expired
        x509.checkValidity();
        
        // Verify signature algorithm
        String sigAlg = x509.getSigAlgName();
        assertFalse("Should not use weak signature algorithm", 
            sigAlg.contains("MD5") || sigAlg.contains("SHA1"));
    }
}
```

## Performance Tests

### Test Suite 6: Performance Benchmarks

```java
package com.ibm.ws.security.token.ltpa.performance;

import org.junit.Test;
import static org.junit.Assert.*;

public class LTPAKeystorePerformanceTest {
    
    @Test
    public void testKeyLoading_Performance() throws Exception {
        LTPAKeyInfoManager manager = new LTPAKeyInfoManager();
        manager.setKeyStoreService(getKeyStoreService());
        
        // Warm up
        for (int i = 0; i < 100; i++) {
            manager.prepareLTPAKeyInfoFromKeyStore(
                "testKeyStore", "ltpaSecret", "ltpaPrivate", "ltpaPublic",
                "password".toCharArray());
        }
        
        // Measure
        long start = System.nanoTime();
        for (int i = 0; i < 1000; i++) {
            manager.prepareLTPAKeyInfoFromKeyStore(
                "testKeyStore", "ltpaSecret", "ltpaPrivate", "ltpaPublic",
                "password".toCharArray());
        }
        long end = System.nanoTime();
        
        double avgMs = (end - start) / 1000000.0 / 1000;
        System.out.println("Average key loading time: " + avgMs + " ms");
        
        assertTrue("Key loading should be fast", avgMs < 1.0); // < 1ms average
    }
    
    @Test
    public void testTokenCreation_Throughput() throws Exception {
        // Measure token creation rate
        int iterations = 10000;
        long start = System.currentTimeMillis();
        
        for (int i = 0; i < iterations; i++) {
            createLTPAToken("user" + i);
        }
        
        long end = System.currentTimeMillis();
        double tokensPerSecond = iterations / ((end - start) / 1000.0);
        
        System.out.println("Token creation rate: " + tokensPerSecond + " tokens/sec");
        assertTrue("Should create at least 1000 tokens/sec", tokensPerSecond > 1000);
    }
    
    @Test
    public void testTokenValidation_Throughput() throws Exception {
        // Pre-create tokens
        String[] tokens = new String[1000];
        for (int i = 0; i < tokens.length; i++) {
            tokens[i] = createLTPAToken("user" + i);
        }
        
        // Measure validation rate
        int iterations = 10000;
        long start = System.currentTimeMillis();
        
        for (int i = 0; i < iterations; i++) {
            validateLTPAToken(tokens[i % tokens.length]);
        }
        
        long end = System.currentTimeMillis();
        double validationsPerSecond = iterations / ((end - start) / 1000.0);
        
        System.out.println("Token validation rate: " + validationsPerSecond + " validations/sec");
        assertTrue("Should validate at least 5000 tokens/sec", validationsPerSecond > 5000);
    }
    
    @Test
    public void testMemoryUsage_KeyCaching() throws Exception {
        Runtime runtime = Runtime.getRuntime();
        runtime.gc();
        long memBefore = runtime.totalMemory() - runtime.freeMemory();
        
        // Load keys from 100 different keystores
        LTPAKeyInfoManager manager = new LTPAKeyInfoManager();
        for (int i = 0; i < 100; i++) {
            manager.prepareLTPAKeyInfoFromKeyStore(
                "keystore" + i, "secret", "private", "public",
                "password".toCharArray());
        }
        
        runtime.gc();
        long memAfter = runtime.totalMemory() - runtime.freeMemory();
        long memUsed = (memAfter - memBefore) / 1024 / 1024; // MB
        
        System.out.println("Memory used for 100 keystores: " + memUsed + " MB");
        assertTrue("Memory usage should be reasonable", memUsed < 50); // < 50MB
    }
}
```

## Migration Tests

### Test Suite 7: Migration Tool Tests

```java
package com.ibm.ws.security.utility.tasks;

import org.junit.Test;
import static org.junit.Assert.*;

public class MigrateLTPAKeysTaskTest {
    
    @Test
    public void testMigration_BasicScenario() throws Exception {
        // Create test LTPA keys file
        File ltpaFile = createTestLTPAKeysFile();
        File keystoreFile = new File("test-ltpa.p12");
        keystoreFile.deleteOnExit();
        
        // Run migration
        String[] args = {
            "--ltpaKeysFile=" + ltpaFile.getAbsolutePath(),
            "--ltpaKeysPassword=password",
            "--keyStore=" + keystoreFile.getAbsolutePath(),
            "--keyStorePassword=keystorePassword",
            "--keyAlias=ltpaKey"
        };
        
        MigrateLTPAKeysTask task = new MigrateLTPAKeysTask();
        task.execute(args);
        
        // Verify keystore was created
        assertTrue("Keystore should exist", keystoreFile.exists());
        
        // Verify keys in keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            ks.load(fis, "keystorePassword".toCharArray());
        }
        
        assertTrue("Secret key should exist", ks.containsAlias("ltpaKeySecret"));
        assertTrue("Private key should exist", ks.containsAlias("ltpaKeyPrivate"));
        assertTrue("Public key should exist", ks.containsAlias("ltpaKeyPublic"));
    }
    
    @Test
    public void testMigration_PreservesKeyData() throws Exception {
        // Load original keys
        Properties originalProps = loadLTPAKeysFile("test-ltpa.keys");
        byte[][] originalKeys = decryptKeys(originalProps, "password");
        
        // Migrate
        migrateKeys("test-ltpa.keys", "password", "test.p12", "kspassword");
        
        // Load from keystore
        KeyStore ks = loadKeystore("test.p12", "kspassword");
        SecretKey secretKey = (SecretKey) ks.getKey("ltpaKeySecret", "kspassword".toCharArray());
        PrivateKey privateKey = (PrivateKey) ks.getKey("ltpaKeyPrivate", "kspassword".toCharArray());
        Certificate cert = ks.getCertificate("ltpaKeyPublic");
        
        // Verify keys match
        assertArrayEquals("Secret key should match", 
            originalKeys[0], secretKey.getEncoded());
        assertArrayEquals("Private key should match", 
            originalKeys[1], privateKey.getEncoded());
        assertArrayEquals("Public key should match", 
            originalKeys[2], cert.getPublicKey().getEncoded());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testMigration_MissingRequiredArg() throws Exception {
        String[] args = {
            "--ltpaKeysFile=test.keys"
            // Missing password
        };
        
        MigrateLTPAKeysTask task = new MigrateLTPAKeysTask();
        task.execute(args);
    }
    
    @Test
    public void testMigration_OverwriteMode() throws Exception {
        // Create initial keystore
        File keystoreFile = new File("test-overwrite.p12");
        createTestKeystore(keystoreFile, "password");
        
        // Migrate with overwrite
        String[] args = {
            "--ltpaKeysFile=test.keys",
            "--ltpaKeysPassword=password",
            "--keyStore=" + keystoreFile.getAbsolutePath(),
            "--keyStorePassword=password",
            "--keyAlias=ltpaKey",
            "--overwrite"
        };
        
        MigrateLTPAKeysTask task = new MigrateLTPAKeysTask();
        task.execute(args);
        
        // Verify new keys replaced old ones
        KeyStore ks = loadKeystore(keystoreFile.getAbsolutePath(), "password");
        assertTrue(ks.containsAlias("ltpaKeySecret"));
    }
}
```

## Compatibility Tests

### Test Suite 8: Backward Compatibility Tests

```java
package com.ibm.ws.security.token.ltpa.compat;

import org.junit.Test;
import static org.junit.Assert.*;

public class LTPABackwardCompatibilityTest {
    
    @Test
    public void testFileBasedConfig_StillWorks() throws Exception {
        // Start server with traditional file-based config
        server.setServerConfigurationFile("ltpa_file_traditional.xml");
        server.startServer();
        
        // Verify LTPA loads from file
        assertNotNull(server.waitForStringInLog("CWWKS4130I.*ltpa.keys"));
        
        // Create and validate token
        String token = createLTPAToken("testuser");
        Subject subject = validateLTPAToken(token);
        assertNotNull(subject);
    }
    
    @Test
    public void testTokenInteroperability_FileToKeystore() throws Exception {
        // Create token with file-based keys
        server.setServerConfigurationFile("ltpa_file.xml");
        server.startServer();
        String token = createLTPAToken("testuser");
        server.stopServer();
        
        // Migrate keys to keystore (same keys)
        migrateKeysToKeystore();
        
        // Start with keystore config
        server.setServerConfigurationFile("ltpa_keystore.xml");
        server.startServer();
        
        // Validate old token with keystore keys
        Subject subject = validateLTPAToken(token);
        assertNotNull("Old token should validate", subject);
    }
    
    @Test
    public void testTokenInteroperability_KeystoreToFile() throws Exception {
        // Create token with keystore keys
        server.setServerConfigurationFile("ltpa_keystore.xml");
        server.startServer();
        String token = createLTPAToken("testuser");
        server.stopServer();
        
        // Export keys back to file (same keys)
        exportKeystoreToFile();
        
        // Start with file config
        server.setServerConfigurationFile("ltpa_file.xml");
        server.startServer();
        
        // Validate keystore token with file keys
        Subject subject = validateLTPAToken(token);
        assertNotNull("Keystore token should validate", subject);
    }
    
    @Test
    public void testExistingApplications_NoChanges() throws Exception {
        // Deploy application that uses LTPA
        server.setServerConfigurationFile("ltpa_keystore.xml");
        server.addInstalledAppForValidation("testApp");
        server.startServer();
        
        // Application should work without modifications
        String response = accessProtectedResource("testApp", "testuser", "password");
        assertTrue("Application should work", response.contains("Success"));
    }
}
```

## Test Data Setup

### Test Keystore Creation

```bash
#!/bin/bash
# create-test-keystores.sh

# Create test LTPA keystore
keytool -genkeypair \
    -alias ltpaKeyPrivate \
    -keyalg RSA \
    -keysize 2048 \
    -validity 3650 \
    -dname "CN=Test LTPA,O=TestRealm,C=US" \
    -keystore test-ltpa.p12 \
    -storetype PKCS12 \
    -storepass password \
    -keypass password

# Generate 3DES secret key
keytool -genseckey \
    -alias ltpaKeySecret \
    -keyalg DESede \
    -keysize 168 \
    -keystore test-ltpa.p12 \
    -storetype PKCS12 \
    -storepass password \
    -keypass password

# Export certificate for public key
keytool -exportcert \
    -alias ltpaKeyPrivate \
    -keystore test-ltpa.p12 \
    -storetype PKCS12 \
    -storepass password \
    -file ltpa-cert.der

# Import as trusted certificate
keytool -importcert \
    -alias ltpaKeyPublic \
    -file ltpa-cert.der \
    -keystore test-ltpa.p12 \
    -storetype PKCS12 \
    -storepass password \
    -noprompt

# Create HSM test keystore (PKCS11)
# Requires HSM configuration file
```

### Test Configuration Files

**ltpa_keystore.xml:**
```xml
<server>
    <featureManager>
        <feature>appSecurity-3.0</feature>
        <feature>ssl-1.0</feature>
    </featureManager>
    
    <keyStore id="ltpaKeyStore" 
              location="${server.config.dir}/resources/security/test-ltpa.p12"
              type="PKCS12" 
              password="password" />
    
    <ltpa keyStoreRef="ltpaKeyStore"
          keyAlias="ltpaKey"
          useKeyStore="true"
          expiration="120m" />
</server>
```

## Test Execution

### Running All Tests

```bash
# Run unit tests
./gradlew test --tests "*LTPAKeystore*Test"

# Run integration tests
./gradlew test --tests "*LTPAKeystoreIntegration*"

# Run security tests
./gradlew test --tests "*LTPAKeystoreSecurity*"

# Run performance tests
./gradlew test --tests "*LTPAKeystorePerformance*"

# Run all LTPA keystore tests
./gradlew test --tests "*LTPAKeystore*"
```

### Test Coverage Report

```bash
# Generate coverage report
./gradlew jacocoTestReport

# View report
open build/reports/jacoco/test/html/index.html
```

## Success Criteria

### Functional Requirements
- ✅ All unit tests pass
- ✅ All integration tests pass
- ✅ Tokens created with keystore keys validate correctly
- ✅ Tokens created with file keys still validate
- ✅ Migration tool successfully migrates keys
- ✅ Configuration validation works correctly

### Security Requirements
- ✅ Keys are properly protected in keystore
- ✅ Wrong passwords are rejected
- ✅ Key types are validated
- ✅ HSM integration works (if available)
- ✅ No sensitive data in logs

### Performance Requirements
- ✅ Key loading < 1ms average
- ✅ Token creation > 1000/sec
- ✅ Token validation > 5000/sec
- ✅ Memory usage < 50MB for 100 keystores

### Compatibility Requirements
- ✅ File-based configuration still works
- ✅ Tokens interoperate between file and keystore
- ✅ Existing applications work without changes
- ✅ Configuration updates work dynamically

## Conclusion

This testing guide provides comprehensive test coverage for the LTPA keystore integration feature. Follow these test scenarios to ensure the feature meets all functional, security, performance, and compatibility requirements.