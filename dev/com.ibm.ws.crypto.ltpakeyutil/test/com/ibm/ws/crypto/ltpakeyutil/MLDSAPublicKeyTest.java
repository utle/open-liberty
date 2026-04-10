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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import test.common.SharedOutputManager;

/**
 * Unit tests for MLDSAPublicKey
 */
public class MLDSAPublicKeyTest {
    
    @Rule
    public SharedOutputManager outputMgr = SharedOutputManager.getInstance();
    
    private byte[] testKeyBytesLevel2;
    private byte[] testKeyBytesLevel3;
    private byte[] testKeyBytesLevel5;
    
    @Before
    public void setUp() throws Exception {
        // Create test key bytes for each security level
        testKeyBytesLevel2 = new byte[1312]; // ML-DSA-44
        testKeyBytesLevel3 = new byte[1952]; // ML-DSA-65
        testKeyBytesLevel5 = new byte[2592]; // ML-DSA-87
        
        // Fill with test data
        Arrays.fill(testKeyBytesLevel2, (byte) 0x42);
        Arrays.fill(testKeyBytesLevel3, (byte) 0x43);
        Arrays.fill(testKeyBytesLevel5, (byte) 0x45);
    }
    
    @Test
    public void testConstructor_Level2() {
        final String methodName = "testConstructor_Level2";
        try {
            MLDSAPublicKey key = new MLDSAPublicKey(testKeyBytesLevel2, 2);
            assertNotNull("Key should not be null", key);
            assertEquals("Security level should be 2", 2, key.getSecurityLevel());
            assertEquals("Variant should be ML-DSA-44", "ML-DSA-44", key.getVariant());
            assertEquals("Key size should be 1312", 1312, key.getKeySize());
            assertEquals("Signature size should be 2420", 2420, key.getExpectedSignatureSize());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testConstructor_Level3() {
        final String methodName = "testConstructor_Level3";
        try {
            MLDSAPublicKey key = new MLDSAPublicKey(testKeyBytesLevel3, 3);
            assertNotNull("Key should not be null", key);
            assertEquals("Security level should be 3", 3, key.getSecurityLevel());
            assertEquals("Variant should be ML-DSA-65", "ML-DSA-65", key.getVariant());
            assertEquals("Key size should be 1952", 1952, key.getKeySize());
            assertEquals("Signature size should be 3309", 3309, key.getExpectedSignatureSize());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testConstructor_Level5() {
        final String methodName = "testConstructor_Level5";
        try {
            MLDSAPublicKey key = new MLDSAPublicKey(testKeyBytesLevel5, 5);
            assertNotNull("Key should not be null", key);
            assertEquals("Security level should be 5", 5, key.getSecurityLevel());
            assertEquals("Variant should be ML-DSA-87", "ML-DSA-87", key.getVariant());
            assertEquals("Key size should be 2592", 2592, key.getKeySize());
            assertEquals("Signature size should be 4627", 4627, key.getExpectedSignatureSize());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testConstructor_NullKeyBytes() {
        final String methodName = "testConstructor_NullKeyBytes";
        try {
            new MLDSAPublicKey(null, 2);
            fail("Should have thrown IllegalArgumentException for null key bytes");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should mention null", 
                      e.getMessage().contains("null"));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testConstructor_EmptyKeyBytes() {
        final String methodName = "testConstructor_EmptyKeyBytes";
        try {
            new MLDSAPublicKey(new byte[0], 2);
            fail("Should have thrown IllegalArgumentException for empty key bytes");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should mention empty", 
                      e.getMessage().contains("empty"));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testConstructor_InvalidSecurityLevel() {
        final String methodName = "testConstructor_InvalidSecurityLevel";
        try {
            new MLDSAPublicKey(testKeyBytesLevel2, 4);
            fail("Should have thrown IllegalArgumentException for invalid security level");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should mention security level", 
                      e.getMessage().contains("Security level"));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetAlgorithm() {
        final String methodName = "testGetAlgorithm";
        try {
            MLDSAPublicKey key = new MLDSAPublicKey(testKeyBytesLevel3, 3);
            assertEquals("Algorithm should be ML-DSA", "ML-DSA", key.getAlgorithm());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetFormat() {
        final String methodName = "testGetFormat";
        try {
            MLDSAPublicKey key = new MLDSAPublicKey(testKeyBytesLevel3, 3);
            assertEquals("Format should be RAW", "RAW", key.getFormat());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetEncoded() {
        final String methodName = "testGetEncoded";
        try {
            MLDSAPublicKey key = new MLDSAPublicKey(testKeyBytesLevel3, 3);
            byte[] encoded = key.getEncoded();
            assertNotNull("Encoded bytes should not be null", encoded);
            assertArrayEquals("Encoded bytes should match original", testKeyBytesLevel3, encoded);
            
            // Verify it's a copy, not the original
            encoded[0] = (byte) 0xFF;
            byte[] encoded2 = key.getEncoded();
            assertFalse("Should return a copy, not original", encoded[0] == encoded2[0]);
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetRawKey() {
        final String methodName = "testGetRawKey";
        try {
            MLDSAPublicKey key = new MLDSAPublicKey(testKeyBytesLevel3, 3);
            byte[] rawKey = key.getRawKey();
            assertNotNull("Raw key should not be null", rawKey);
            assertArrayEquals("Raw key should match original", testKeyBytesLevel3, rawKey);
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testEquals_SameObject() {
        final String methodName = "testEquals_SameObject";
        try {
            MLDSAPublicKey key = new MLDSAPublicKey(testKeyBytesLevel3, 3);
            assertTrue("Key should equal itself", key.equals(key));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testEquals_EqualKeys() {
        final String methodName = "testEquals_EqualKeys";
        try {
            MLDSAPublicKey key1 = new MLDSAPublicKey(testKeyBytesLevel3, 3);
            MLDSAPublicKey key2 = new MLDSAPublicKey(testKeyBytesLevel3, 3);
            assertTrue("Equal keys should be equal", key1.equals(key2));
            assertEquals("Equal keys should have same hashCode", 
                        key1.hashCode(), key2.hashCode());
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testEquals_DifferentKeys() {
        final String methodName = "testEquals_DifferentKeys";
        try {
            MLDSAPublicKey key1 = new MLDSAPublicKey(testKeyBytesLevel2, 2);
            MLDSAPublicKey key2 = new MLDSAPublicKey(testKeyBytesLevel3, 3);
            assertFalse("Different keys should not be equal", key1.equals(key2));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testEquals_Null() {
        final String methodName = "testEquals_Null";
        try {
            MLDSAPublicKey key = new MLDSAPublicKey(testKeyBytesLevel3, 3);
            assertFalse("Key should not equal null", key.equals(null));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testEquals_DifferentType() {
        final String methodName = "testEquals_DifferentType";
        try {
            MLDSAPublicKey key = new MLDSAPublicKey(testKeyBytesLevel3, 3);
            assertFalse("Key should not equal different type", key.equals("not a key"));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testToString() {
        final String methodName = "testToString";
        try {
            MLDSAPublicKey key = new MLDSAPublicKey(testKeyBytesLevel3, 3);
            String str = key.toString();
            assertNotNull("toString should not return null", str);
            assertTrue("toString should contain variant", str.contains("ML-DSA-65"));
            assertTrue("toString should contain security level", str.contains("3"));
            assertTrue("toString should contain key size", str.contains("1952"));
            assertTrue("toString should contain signature size", str.contains("3309"));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetPublicKeySize() {
        final String methodName = "testGetPublicKeySize";
        try {
            assertEquals("Level 2 public key size should be 1312", 
                        1312, MLDSAPublicKey.getPublicKeySize(2));
            assertEquals("Level 3 public key size should be 1952", 
                        1952, MLDSAPublicKey.getPublicKeySize(3));
            assertEquals("Level 5 public key size should be 2592", 
                        2592, MLDSAPublicKey.getPublicKeySize(5));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetSignatureSize() {
        final String methodName = "testGetSignatureSize";
        try {
            assertEquals("Level 2 signature size should be 2420", 
                        2420, MLDSAPublicKey.getSignatureSize(2));
            assertEquals("Level 3 signature size should be 3309", 
                        3309, MLDSAPublicKey.getSignatureSize(3));
            assertEquals("Level 5 signature size should be 4627", 
                        4627, MLDSAPublicKey.getSignatureSize(5));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetPublicKeySize_InvalidLevel() {
        final String methodName = "testGetPublicKeySize_InvalidLevel";
        try {
            MLDSAPublicKey.getPublicKeySize(4);
            fail("Should have thrown IllegalArgumentException for invalid level");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should mention invalid level", 
                      e.getMessage().contains("Invalid"));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
    
    @Test
    public void testGetSignatureSize_InvalidLevel() {
        final String methodName = "testGetSignatureSize_InvalidLevel";
        try {
            MLDSAPublicKey.getSignatureSize(4);
            fail("Should have thrown IllegalArgumentException for invalid level");
        } catch (IllegalArgumentException e) {
            assertTrue("Exception message should mention invalid level", 
                      e.getMessage().contains("Invalid"));
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }
}

// Made with Bob
