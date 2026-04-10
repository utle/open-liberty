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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.ws.ffdc.annotation.FFDCIgnore;

/**
 * Post-Quantum Cryptography operations for LTPA tokens.
 * Provides ML-DSA (Dilithium) signature operations and hybrid signature support.
 * 
 * This class uses BouncyCastle PQC provider for ML-DSA operations.
 */
public final class LTPAPQCCrypto {
    
    private static final TraceComponent tc = Tr.register(LTPAPQCCrypto.class);
    
    // Algorithm names
    private static final String MLDSA_ALGORITHM = "ML-DSA";
    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    private static final String AES_ALGORITHM = "AES";
    private static final String SHA256_ALGORITHM = "SHA-256";
    private static final String SHA384_ALGORITHM = "SHA-384";
    
    // GCM parameters
    private static final int GCM_TAG_LENGTH = 128; // 128 bits
    private static final int GCM_IV_LENGTH = 12; // 12 bytes (96 bits)
    
    // Provider name
    private static final String BC_PROVIDER = "BCPQC"; // BouncyCastle PQC provider
    
    private static volatile boolean pqcProviderInitialized = false;
    private static final Object providerLock = new Object();
    
    /**
     * Initialize the PQC provider (BouncyCastle PQC)
     */
    @FFDCIgnore(Exception.class)
    public static void initializePQCProvider() {
        if (pqcProviderInitialized) {
            return;
        }
        
        synchronized (providerLock) {
            if (pqcProviderInitialized) {
                return;
            }
            
            try {
                // Try to load BouncyCastle PQC provider
                Class<?> providerClass = Class.forName("org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider");
                Provider provider = (Provider) providerClass.getDeclaredConstructor().newInstance();
                Security.addProvider(provider);
                
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "BouncyCastle PQC provider initialized successfully");
                }
                
                pqcProviderInitialized = true;
            } catch (Exception e) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isWarningEnabled()) {
                    Tr.warning(tc, "Failed to initialize PQC provider. PQC features will not be available: " + e.getMessage());
                }
            }
        }
    }
    
    /**
     * Check if PQC provider is available
     */
    public static boolean isPQCProviderAvailable() {
        if (!pqcProviderInitialized) {
            initializePQCProvider();
        }
        return pqcProviderInitialized;
    }
    
    /**
     * Generate an ML-DSA key pair
     * 
     * @param securityLevel NIST security level (2, 3, or 5)
     * @return ML-DSA key pair
     * @throws Exception if key generation fails
     */
    public static MLDSAKeyPair generateMLDSAKeyPair(int securityLevel) throws Exception {
        if (!isPQCProviderAvailable()) {
            throw new IllegalStateException("PQC provider not available");
        }
        
        String algorithm = getMLDSAAlgorithmName(securityLevel);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Generating ML-DSA key pair: " + algorithm);
        }
        
        // Use BouncyCastle PQC provider to generate keys
        java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance(algorithm, BC_PROVIDER);
        java.security.KeyPair keyPair = keyGen.generateKeyPair();
        
        // Extract raw key bytes
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        
        MLDSAPublicKey publicKey = new MLDSAPublicKey(publicKeyBytes, securityLevel);
        MLDSAPrivateKey privateKey = new MLDSAPrivateKey(privateKeyBytes, securityLevel);
        
        return new MLDSAKeyPair(publicKey, privateKey);
    }
    
    /**
     * Get the ML-DSA algorithm name for a security level
     */
    private static String getMLDSAAlgorithmName(int securityLevel) {
        switch (securityLevel) {
            case 2:
                return "ML-DSA-44";
            case 3:
                return "ML-DSA-65";
            case 5:
                return "ML-DSA-87";
            default:
                throw new IllegalArgumentException("Invalid security level: " + securityLevel);
        }
    }
    
    /**
     * Sign data using ML-DSA
     * 
     * @param data Data to sign
     * @param privateKey ML-DSA private key
     * @return Signature bytes
     * @throws Exception if signing fails
     */
    public static byte[] signMLDSA(@Sensitive byte[] data, MLDSAPrivateKey privateKey) throws Exception {
        if (!isPQCProviderAvailable()) {
            throw new IllegalStateException("PQC provider not available");
        }
        
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        
        // Hash the data first
        MessageDigest digest = getDigestForSecurityLevel(privateKey.getSecurityLevel());
        byte[] hash = digest.digest(data);
        
        // Sign the hash
        String algorithm = privateKey.getVariant();
        Signature signature = Signature.getInstance(algorithm, BC_PROVIDER);
        
        // Reconstruct the private key for signing
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(algorithm, BC_PROVIDER);
        java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(privateKey.getRawKey());
        java.security.PrivateKey signingKey = keyFactory.generatePrivate(keySpec);
        
        signature.initSign(signingKey);
        signature.update(hash);
        
        byte[] signatureBytes = signature.sign();
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "ML-DSA signature created: " + signatureBytes.length + " bytes");
        }
        
        return signatureBytes;
    }
    
    /**
     * Verify ML-DSA signature
     * 
     * @param data Original data
     * @param signature Signature to verify
     * @param publicKey ML-DSA public key
     * @return true if signature is valid
     * @throws Exception if verification fails
     */
    public static boolean verifyMLDSA(byte[] data, byte[] signature, MLDSAPublicKey publicKey) throws Exception {
        if (!isPQCProviderAvailable()) {
            throw new IllegalStateException("PQC provider not available");
        }
        
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }
        
        // Hash the data first
        MessageDigest digest = getDigestForSecurityLevel(publicKey.getSecurityLevel());
        byte[] hash = digest.digest(data);
        
        // Verify the signature
        String algorithm = publicKey.getVariant();
        Signature sig = Signature.getInstance(algorithm, BC_PROVIDER);
        
        // Reconstruct the public key for verification
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance(algorithm, BC_PROVIDER);
        java.security.spec.X509EncodedKeySpec keySpec = new java.security.spec.X509EncodedKeySpec(publicKey.getRawKey());
        java.security.PublicKey verifyKey = keyFactory.generatePublic(keySpec);
        
        sig.initVerify(verifyKey);
        sig.update(hash);
        
        boolean valid = sig.verify(signature);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "ML-DSA signature verification: " + (valid ? "VALID" : "INVALID"));
        }
        
        return valid;
    }
    
    /**
     * Create a hybrid signature (RSA + ML-DSA)
     * 
     * @param data Data to sign
     * @param rsaPrivateKey RSA private key
     * @param pqcPrivateKey ML-DSA private key
     * @return Hybrid signature (RSA signature || ML-DSA signature)
     * @throws Exception if signing fails
     */
    public static byte[] signHybrid(@Sensitive byte[] data, LTPAPrivateKey rsaPrivateKey, MLDSAPrivateKey pqcPrivateKey) throws Exception {
        // Sign with RSA
        byte[] rsaSignature = LTPACrypto.signISO9796(rsaPrivateKey.getRawKey(), data, 0, data.length);
        
        // Sign with ML-DSA
        byte[] pqcSignature = signMLDSA(data, pqcPrivateKey);
        
        // Concatenate signatures: [RSA length (4 bytes)] [RSA signature] [PQC signature]
        byte[] hybridSignature = new byte[4 + rsaSignature.length + pqcSignature.length];
        
        // Write RSA signature length
        hybridSignature[0] = (byte) (rsaSignature.length >> 24);
        hybridSignature[1] = (byte) (rsaSignature.length >> 16);
        hybridSignature[2] = (byte) (rsaSignature.length >> 8);
        hybridSignature[3] = (byte) rsaSignature.length;
        
        // Copy RSA signature
        System.arraycopy(rsaSignature, 0, hybridSignature, 4, rsaSignature.length);
        
        // Copy PQC signature
        System.arraycopy(pqcSignature, 0, hybridSignature, 4 + rsaSignature.length, pqcSignature.length);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Hybrid signature created: RSA=" + rsaSignature.length + " bytes, PQC=" + pqcSignature.length + " bytes");
        }
        
        return hybridSignature;
    }
    
    /**
     * Verify hybrid signature (RSA + ML-DSA)
     * 
     * @param data Original data
     * @param hybridSignature Hybrid signature
     * @param rsaPublicKey RSA public key
     * @param pqcPublicKey ML-DSA public key
     * @return true if both signatures are valid
     * @throws Exception if verification fails
     */
    public static boolean verifyHybrid(byte[] data, byte[] hybridSignature, LTPAPublicKey rsaPublicKey, MLDSAPublicKey pqcPublicKey) throws Exception {
        if (hybridSignature == null || hybridSignature.length < 4) {
            throw new IllegalArgumentException("Invalid hybrid signature");
        }
        
        // Read RSA signature length
        int rsaLength = ((hybridSignature[0] & 0xFF) << 24) |
                       ((hybridSignature[1] & 0xFF) << 16) |
                       ((hybridSignature[2] & 0xFF) << 8) |
                       (hybridSignature[3] & 0xFF);
        
        if (rsaLength < 0 || rsaLength > hybridSignature.length - 4) {
            throw new IllegalArgumentException("Invalid RSA signature length in hybrid signature");
        }
        
        // Extract RSA signature
        byte[] rsaSignature = new byte[rsaLength];
        System.arraycopy(hybridSignature, 4, rsaSignature, 0, rsaLength);
        
        // Extract PQC signature
        int pqcLength = hybridSignature.length - 4 - rsaLength;
        byte[] pqcSignature = new byte[pqcLength];
        System.arraycopy(hybridSignature, 4 + rsaLength, pqcSignature, 0, pqcLength);
        
        // Verify RSA signature
        boolean rsaValid = LTPACrypto.verifyISO9796(rsaPublicKey.getRawKey(), data, 0, data.length, 
                                                     rsaSignature, 0, rsaSignature.length);
        
        // Verify PQC signature
        boolean pqcValid = verifyMLDSA(data, pqcSignature, pqcPublicKey);
        
        boolean bothValid = rsaValid && pqcValid;
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Hybrid signature verification: RSA=" + rsaValid + ", PQC=" + pqcValid + ", Overall=" + bothValid);
        }
        
        return bothValid;
    }
    
    /**
     * Encrypt data using AES-256-GCM
     * 
     * @param data Data to encrypt
     * @param key AES-256 key (32 bytes)
     * @return Encrypted data with IV prepended
     * @throws Exception if encryption fails
     */
    public static byte[] encryptAES256GCM(@Sensitive byte[] data, @Sensitive byte[] key) throws Exception {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes for AES-256");
        }
        
        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        
        // Create cipher
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] encrypted = cipher.doFinal(data);
        
        // Prepend IV to encrypted data
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        
        return result;
    }
    
    /**
     * Decrypt data using AES-256-GCM
     * 
     * @param encryptedData Encrypted data with IV prepended
     * @param key AES-256 key (32 bytes)
     * @return Decrypted data
     * @throws Exception if decryption fails
     */
    public static byte[] decryptAES256GCM(byte[] encryptedData, @Sensitive byte[] key) throws Exception {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes for AES-256");
        }
        if (encryptedData == null || encryptedData.length <= GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted data");
        }
        
        // Extract IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(encryptedData, 0, iv, 0, GCM_IV_LENGTH);
        
        // Extract encrypted data
        byte[] encrypted = new byte[encryptedData.length - GCM_IV_LENGTH];
        System.arraycopy(encryptedData, GCM_IV_LENGTH, encrypted, 0, encrypted.length);
        
        // Create cipher
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        return cipher.doFinal(encrypted);
    }
    
    /**
     * Generate a random AES-256 key
     * 
     * @return 32-byte AES key
     * @throws NoSuchAlgorithmException if AES is not available
     */
    public static byte[] generateAES256Key() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        return key.getEncoded();
    }
    
    /**
     * Get the appropriate message digest for a security level
     */
    private static MessageDigest getDigestForSecurityLevel(int securityLevel) throws NoSuchAlgorithmException {
        // Use SHA-256 for level 2, SHA-384 for levels 3 and 5
        String algorithm = (securityLevel == 2) ? SHA256_ALGORITHM : SHA384_ALGORITHM;
        return MessageDigest.getInstance(algorithm);
    }
}

// Made with Bob
