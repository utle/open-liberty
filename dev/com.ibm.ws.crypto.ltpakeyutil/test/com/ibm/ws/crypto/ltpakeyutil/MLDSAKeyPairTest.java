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
package com.ibm.ws.crypto.ltpakeyutil;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import test.common.SharedOutputManager;

/**
 * Unit tests for MLDSAKeyPair
 */
public class MLDSAKeyPairTest {
    
    @Rule
    public SharedOutputManager outputMgr = SharedOutputManager.getInstance();
    
    private MLDSAPublicKey publicKeyLevel2;
    private MLDSAPrivateKey privateKeyLevel2;
    private MLDSAPublicKey publicKeyLevel3;
    private MLDSAPrivateKey privateKeyLevel3;
    private MLDSAPublicKey publicKeyLevel5;
    private MLDSAPrivateKey privateKeyLevel5;
    
    @Before
    public void setUp() throws Exception {
        // Create test keys for each security level
        byte[] pubBytes2 = new byte[1312];
        byte[] privBytes2 = new byte[2560];
        Arrays.fill(pubBytes2, (byte) 0x42);
        Arrays.fill(privBytes2, (byte) 0x42);
        publicKeyLevel2 = new MLDSAPublicKey(pubBytes2, 2);
        privateKeyLevel2 = new MLDSAPrivateKey(privBytes2, 2);
        
        byte[] pubBytes3 = new byte[1952];
        byte[] privBytes3 = new byte[4032];
        Arrays.fill(pubBytes3, (byte) 0x43);
        Arrays.fill(privBytes3, (byte) 0x43);
        publicKeyLevel3 = new MLDSAPublicKey(pubBytes3, 3);
        privateKeyLevel3 = new MLDSAPrivateKey(privBytes3, 3);
        
        byte[] pubBytes5 = new byte[2592];
        byte[] privBytes5 = new byte[4896];
        Arrays.fill(pubBytes5, (byte) 0x45);
        Arrays.fill(privBytes5, (byte) 0x45);
        publicKeyLevel5 = new MLDSAPublicKey(pubBytes5, 5);
        privateKeyLevel5 = new MLDSAPrivateKey(privBytes5, 5);
    }
    
    @Test
    public void testConstructor_Level2() {
        final String methodName = "testConstructor_Level2";
        try {
            MLDSAKeyPair keyPair = new MLDSAKeyPair(publicKeyLevel2, privateKeyLevel2);
            assertNotNull("KeyPair should not be null", keyPair);
            assertEquals("Security level should be 2", 2, keyPair.getSecurityLevel());
            assertEquals("Variant should be ML-DSA-44", "ML-DSA-44", keyPair.getVariant());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testConstructor_Level3() {
        final String methodName = "testConstructor_Level3";
        try {
            MLDSAKeyPair keyPair = new MLDSAKeyPair(publicKeyLevel3, privateKeyLevel3);
            assertNotNull("KeyPair should not be null", keyPair);
            assertEquals("Security level should be 3", 3, keyPair.getSecurityLevel());
            assertEquals("Variant should be ML-DSA-65", "ML-DSA-65", keyPair.getVariant());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testConstructor_Level5() {
        final String methodName = "testConstructor_Level5";
        try {
            MLDSAKeyPair keyPair = new MLDSAKeyPair(publicKeyLevel5, privateKeyLevel5);
            assertNotNull("KeyPair should not be null", keyPair);
            assertEquals("Security level should be 5", 5, keyPair.getSecurityLevel());
            assertEquals("Variant should be ML-DSA-87", "ML-DSA-87", keyPair.getVariant());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testConstructor_NullPublicKey() {
        final String methodName = "testConstructor_NullPublicKey";
        try {
            new MLDSAKeyPair(null, privateKeyLevel3);
            fail("Should have thrown IllegalArgumentException for null public key");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should mention public key", 
                      e.getMessage().contains("Public key"));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testConstructor_NullPrivateKey() {
        final String methodName = "testConstructor_NullPrivateKey";
        try {
            new MLDSAKeyPair(publicKeyLevel3, null);
            fail("Should have thrown IllegalArgumentException for null private key");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should mention private key", 
                      e.getMessage().contains("Private key"));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testConstructor_MismatchedSecurityLevels() {
        final String methodName = "testConstructor_MismatchedSecurityLevels";
        try {
            new MLDSAKeyPair(publicKeyLevel2, privateKeyLevel3);
            fail("Should have thrown IllegalArgumentException for mismatched security levels");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should mention security level", 
                      e.getMessage().contains("security level"));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetPublicKey() {
        final String methodName = "testGetPublicKey";
        try {
            MLDSAKeyPair keyPair = new MLDSAKeyPair(publicKeyLevel3, privateKeyLevel3);
            MLDSAPublicKey actualPublicKey = keyPair.getPublicKey();
            assertEquals("The actual public key must be the same as the one used to construct the KeyPair", 
                        publicKeyLevel3, actualPublicKey);
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetPrivateKey() {
        final String methodName = "testGetPrivateKey";
        try {
            MLDSAKeyPair keyPair = new MLDSAKeyPair(publicKeyLevel3, privateKeyLevel3);
            MLDSAPrivateKey actualPrivateKey = keyPair.getPrivateKey();
            assertEquals("The actual private key must be the same as the one used to construct the KeyPair", 
                        privateKeyLevel3, actualPrivateKey);
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetSecurityLevel() {
        final String methodName = "testGetSecurityLevel";
        try {
            MLDSAKeyPair keyPair = new MLDSAKeyPair(publicKeyLevel3, privateKeyLevel3);
            assertEquals("Security level should match keys", 3, keyPair.getSecurityLevel());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetVariant() {
        final String methodName = "testGetVariant";
        try {
            MLDSAKeyPair keyPair2 = new MLDSAKeyPair(publicKeyLevel2, privateKeyLevel2);
            assertEquals("Variant should be ML-DSA-44", "ML-DSA-44", keyPair2.getVariant());
            
            MLDSAKeyPair keyPair3 = new MLDSAKeyPair(publicKeyLevel3, privateKeyLevel3);
            assertEquals("Variant should be ML-DSA-65", "ML-DSA-65", keyPair3.getVariant());
            
            MLDSAKeyPair keyPair5 = new MLDSAKeyPair(publicKeyLevel5, privateKeyLevel5);
            assertEquals("Variant should be ML-DSA-87", "ML-DSA-87", keyPair5.getVariant());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetCreationTime() {
        final String methodName = "testGetCreationTime";
        try {
            long beforeCreation = System.currentTimeMillis();
            MLDSAKeyPair keyPair = new MLDSAKeyPair(publicKeyLevel3, privateKeyLevel3);
            long afterCreation = System.currentTimeMillis();
            
            long creationTime = keyPair.getCreationTime();
            assertTrue("Creation time should be after beforeCreation", 
                      creationTime >= beforeCreation);
            assertTrue("Creation time should be before afterCreation", 
                      creationTime <= afterCreation);
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testToKeyPair() {
        final String methodName = "testToKeyPair";
        try {
            MLDSAKeyPair mldsaKeyPair = new MLDSAKeyPair(publicKeyLevel3, privateKeyLevel3);
            KeyPair javaKeyPair = mldsaKeyPair.toKeyPair();
            
            assertNotNull("Java KeyPair should not be null", javaKeyPair);
            assertEquals("Public key should match", publicKeyLevel3, javaKeyPair.getPublic());
            assertEquals("Private key should match", privateKeyLevel3, javaKeyPair.getPrivate());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testDestroy() {
        final String methodName = "testDestroy";
        try {
            byte[] privBytes = new byte[4032];
            Arrays.fill(privBytes, (byte) 0x43);
            MLDSAPrivateKey privateKey = new MLDSAPrivateKey(privBytes, 3);
            MLDSAKeyPair keyPair = new MLDSAKeyPair(publicKeyLevel3, privateKey);
            
            // Verify private key has data before destroy
            byte[] beforeDestroy = privateKey.getRawKey();
            boolean hasNonZero = false;
            for (byte b : beforeDestroy) {
                if (b != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            assertTrue("Private key should have non-zero bytes before destroy", hasNonZero);
            
            // Destroy the key pair
            keyPair.destroy();
            
            // Verify private key is zeroed after destroy
            byte[] afterDestroy = privateKey.getRawKey();
            for (byte b : afterDestroy) {
                assertEquals("All bytes should be zero after destroy", 0, b);
            }
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testToString() {
        final String methodName = "testToString";
        try {
            MLDSAKeyPair keyPair = new MLDSAKeyPair(publicKeyLevel3, privateKeyLevel3);
            String str = keyPair.toString();
            
            assertNotNull("toString should not return null", str);
            assertTrue("toString should contain variant", str.contains("ML-DSA-65"));
            assertTrue("toString should contain security level", str.contains("3"));
            assertTrue("toString should contain 'created'", str.contains("created"));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testMultipleKeyPairs() {
        final String methodName = "testMultipleKeyPairs";
        try {
            MLDSAKeyPair keyPair2 = new MLDSAKeyPair(publicKeyLevel2, privateKeyLevel2);
            MLDSAKeyPair keyPair3 = new MLDSAKeyPair(publicKeyLevel3, privateKeyLevel3);
            MLDSAKeyPair keyPair5 = new MLDSAKeyPair(publicKeyLevel5, privateKeyLevel5);
            
            assertEquals("Level 2 security level", 2, keyPair2.getSecurityLevel());
            assertEquals("Level 3 security level", 3, keyPair3.getSecurityLevel());
            assertEquals("Level 5 security level", 5, keyPair5.getSecurityLevel());
            
            assertEquals("Level 2 variant", "ML-DSA-44", keyPair2.getVariant());
            assertEquals("Level 3 variant", "ML-DSA-65", keyPair3.getVariant());
            assertEquals("Level 5 variant", "ML-DSA-87", keyPair5.getVariant());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
}

// Made with Bob
