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
package com.ibm.ws.security.audit.encryption;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import com.ibm.ws.crypto.ltpakeyutil.MLDSAKeyPair;
import com.ibm.ws.crypto.ltpakeyutil.MLDSAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.MLDSAPublicKey;

/**
 * Unit tests for AuditPQCCrypto
 */
public class AuditPQCCryptoTest {
    
    private byte[] testData;
    private byte[] aes256Key;
    private MLDSAKeyPair pqcKeyPair;
    private KeyPair rsaKeyPair;
    
    @Before
    public void setUp() throws Exception {
        // Test data
        testData = "This is test audit data for PQC encryption and signing".getBytes();
        
        // Generate AES-256 key
        aes256Key = AuditPQCCrypto.generateAES256Key();
        
        // Generate PQC key pair (security level 3)
        pqcKeyPair = AuditPQCCrypto.generateMLDSAKeyPair(3);
        
        // Generate RSA key pair for hybrid tests
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        rsaKeyPair = rsaGen.generateKeyPair();
    }
    
    @Test
    public void testGenerateAES256Key() {
        byte[] key = AuditPQCCrypto.generateAES256Key();
        
        assertNotNull("Key should not be null", key);
        assertEquals("Key should be 32 bytes (256 bits)", 32, key.length);
        
        // Generate another key and verify they're different
        byte[] key2 = AuditPQCCrypto.generateAES256Key();
        assertFalse("Keys should be different", Arrays.equals(key, key2));
    }
    
    @Test
    public void testEncryptDecryptAES256GCM() {
        byte[] encrypted = AuditPQCCrypto.encryptAES256GCM(testData, aes256Key);
        
        assertNotNull("Encrypted data should not be null", encrypted);
        assertTrue("Encrypted data should be longer than original (includes IV and tag)", 
                  encrypted.length > testData.length);
        
        byte[] decrypted = AuditPQCCrypto.decryptAES256GCM(encrypted, aes256Key);
        
        assertNotNull("Decrypted data should not be null", decrypted);
        assertArrayEquals("Decrypted data should match original", testData, decrypted);
    }
    
    @Test
    public void testEncryptAES256GCM_NullData() {
        byte[] encrypted = AuditPQCCrypto.encryptAES256GCM(null, aes256Key);
        
        assertEquals("Encrypting null data should return null", null, encrypted);
    }
    
    @Test
    public void testEncryptAES256GCM_NullKey() {
        byte[] encrypted = AuditPQCCrypto.encryptAES256GCM(testData, null);
        
        assertEquals("Encrypting with null key should return null", null, encrypted);
    }
    
    @Test
    public void testEncryptAES256GCM_InvalidKeyLength() {
        byte[] shortKey = new byte[16]; // 128-bit key instead of 256-bit
        byte[] encrypted = AuditPQCCrypto.encryptAES256GCM(testData, shortKey);
        
        assertEquals("Encrypting with invalid key length should return null", null, encrypted);
    }
    
    @Test
    public void testDecryptAES256GCM_WrongKey() {
        byte[] encrypted = AuditPQCCrypto.encryptAES256GCM(testData, aes256Key);
        
        byte[] wrongKey = AuditPQCCrypto.generateAES256Key();
        byte[] decrypted = AuditPQCCrypto.decryptAES256GCM(encrypted, wrongKey);
        
        assertEquals("Decrypting with wrong key should return null", null, decrypted);
    }
    
    @Test
    public void testDecryptAES256GCM_TamperedData() {
        byte[] encrypted = AuditPQCCrypto.encryptAES256GCM(testData, aes256Key);
        
        // Tamper with encrypted data
        encrypted[encrypted.length - 1] ^= 0x01;
        
        byte[] decrypted = AuditPQCCrypto.decryptAES256GCM(encrypted, aes256Key);
        
        assertEquals("Decrypting tampered data should return null", null, decrypted);
    }
    
    @Test
    public void testGenerateMLDSAKeyPair_Level2() {
        MLDSAKeyPair keyPair = AuditPQCCrypto.generateMLDSAKeyPair(2);
        
        assertNotNull("Key pair should not be null", keyPair);
        assertEquals("Security level should be 2", 2, keyPair.getSecurityLevel());
        assertEquals("Variant should be ML-DSA-44", "ML-DSA-44", keyPair.getVariant());
        assertNotNull("Public key should not be null", keyPair.getPublicKey());
        assertNotNull("Private key should not be null", keyPair.getPrivateKey());
    }
    
    @Test
    public void testGenerateMLDSAKeyPair_Level3() {
        MLDSAKeyPair keyPair = AuditPQCCrypto.generateMLDSAKeyPair(3);
        
        assertNotNull("Key pair should not be null", keyPair);
        assertEquals("Security level should be 3", 3, keyPair.getSecurityLevel());
        assertEquals("Variant should be ML-DSA-65", "ML-DSA-65", keyPair.getVariant());
    }
    
    @Test
    public void testGenerateMLDSAKeyPair_Level5() {
        MLDSAKeyPair keyPair = AuditPQCCrypto.generateMLDSAKeyPair(5);
        
        assertNotNull("Key pair should not be null", keyPair);
        assertEquals("Security level should be 5", 5, keyPair.getSecurityLevel());
        assertEquals("Variant should be ML-DSA-87", "ML-DSA-87", keyPair.getVariant());
    }
    
    @Test
    public void testSignVerifyMLDSA() {
        byte[] signature = AuditPQCCrypto.signMLDSA(testData, pqcKeyPair.getPrivateKey());
        
        assertNotNull("Signature should not be null", signature);
        assertEquals("Signature length should match expected size", 
                    pqcKeyPair.getPublicKey().getExpectedSignatureSize(), signature.length);
        
        boolean valid = AuditPQCCrypto.verifyMLDSA(testData, signature, pqcKeyPair.getPublicKey());
        
        assertTrue("Signature should be valid", valid);
    }
    
    @Test
    public void testSignMLDSA_NullData() {
        byte[] signature = AuditPQCCrypto.signMLDSA(null, pqcKeyPair.getPrivateKey());
        
        assertEquals("Signing null data should return null", null, signature);
    }
    
    @Test
    public void testSignMLDSA_NullKey() {
        byte[] signature = AuditPQCCrypto.signMLDSA(testData, null);
        
        assertEquals("Signing with null key should return null", null, signature);
    }
    
    @Test
    public void testVerifyMLDSA_TamperedData() {
        byte[] signature = AuditPQCCrypto.signMLDSA(testData, pqcKeyPair.getPrivateKey());
        
        byte[] tamperedData = testData.clone();
        tamperedData[0] ^= 0x01;
        
        boolean valid = AuditPQCCrypto.verifyMLDSA(tamperedData, signature, pqcKeyPair.getPublicKey());
        
        assertFalse("Tampered data should not verify", valid);
    }
    
    @Test
    public void testVerifyMLDSA_TamperedSignature() {
        byte[] signature = AuditPQCCrypto.signMLDSA(testData, pqcKeyPair.getPrivateKey());
        
        signature[0] ^= 0x01;
        
        boolean valid = AuditPQCCrypto.verifyMLDSA(testData, signature, pqcKeyPair.getPublicKey());
        
        assertFalse("Tampered signature should not verify", valid);
    }
    
    @Test
    public void testSignVerifyHybrid() {
        byte[] hybridSig = AuditPQCCrypto.signHybrid(testData, rsaKeyPair.getPrivate(), 
                                                     pqcKeyPair.getPrivateKey());
        
        assertNotNull("Hybrid signature should not be null", hybridSig);
        assertTrue("Hybrid signature should be larger than RSA alone", hybridSig.length > 256);
        
        boolean valid = AuditPQCCrypto.verifyHybrid(testData, hybridSig, rsaKeyPair.getPublic(),
                                                    pqcKeyPair.getPublicKey());
        
        assertTrue("Hybrid signature should be valid", valid);
    }
    
    @Test
    public void testSignHybrid_NullRSAKey() {
        byte[] hybridSig = AuditPQCCrypto.signHybrid(testData, null, pqcKeyPair.getPrivateKey());
        
        assertEquals("Signing with null RSA key should return null", null, hybridSig);
    }
    
    @Test
    public void testSignHybrid_NullPQCKey() {
        byte[] hybridSig = AuditPQCCrypto.signHybrid(testData, rsaKeyPair.getPrivate(), null);
        
        assertEquals("Signing with null PQC key should return null", null, hybridSig);
    }
    
    @Test
    public void testVerifyHybrid_TamperedData() {
        byte[] hybridSig = AuditPQCCrypto.signHybrid(testData, rsaKeyPair.getPrivate(),
                                                     pqcKeyPair.getPrivateKey());
        
        byte[] tamperedData = testData.clone();
        tamperedData[0] ^= 0x01;
        
        boolean valid = AuditPQCCrypto.verifyHybrid(tamperedData, hybridSig, rsaKeyPair.getPublic(),
                                                    pqcKeyPair.getPublicKey());
        
        assertFalse("Tampered data should not verify in hybrid mode", valid);
    }
    
    @Test
    public void testMultipleEncryptionRounds() {
        // Test that multiple encryption/decryption rounds work correctly
        byte[] data = testData;
        
        for (int i = 0; i < 5; i++) {
            byte[] encrypted = AuditPQCCrypto.encryptAES256GCM(data, aes256Key);
            assertNotNull("Encryption round " + i + " should succeed", encrypted);
            
            byte[] decrypted = AuditPQCCrypto.decryptAES256GCM(encrypted, aes256Key);
            assertNotNull("Decryption round " + i + " should succeed", decrypted);
            assertArrayEquals("Data should match after round " + i, data, decrypted);
            
            data = decrypted;
        }
    }
    
    @Test
    public void testLargeDataEncryption() {
        // Test with large data (1MB)
        byte[] largeData = new byte[1024 * 1024];
        Arrays.fill(largeData, (byte) 0x42);
        
        byte[] encrypted = AuditPQCCrypto.encryptAES256GCM(largeData, aes256Key);
        assertNotNull("Large data encryption should succeed", encrypted);
        
        byte[] decrypted = AuditPQCCrypto.decryptAES256GCM(encrypted, aes256Key);
        assertNotNull("Large data decryption should succeed", decrypted);
        assertArrayEquals("Large data should match after encryption/decryption", largeData, decrypted);
    }
    
    @Test
    public void testDifferentSecurityLevels() {
        // Test all security levels
        int[] levels = {2, 3, 5};
        
        for (int level : levels) {
            MLDSAKeyPair keyPair = AuditPQCCrypto.generateMLDSAKeyPair(level);
            assertNotNull("Key pair for level " + level + " should not be null", keyPair);
            
            byte[] signature = AuditPQCCrypto.signMLDSA(testData, keyPair.getPrivateKey());
            assertNotNull("Signature for level " + level + " should not be null", signature);
            
            boolean valid = AuditPQCCrypto.verifyMLDSA(testData, signature, keyPair.getPublicKey());
            assertTrue("Signature for level " + level + " should be valid", valid);
        }
    }
}

// Made with Bob
