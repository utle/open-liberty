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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.ws.common.encoder.Base64Coder;

/**
 * Utility class for PQC key management in LTPA.
 * Handles key generation, serialization, and key file operations.
 */
public final class LTPAPQCKeyUtil {
    
    private static final TraceComponent tc = Tr.register(LTPAPQCKeyUtil.class);
    
    // Property keys for PQC keys in ltpa.keys file
    public static final String PQC_VERSION = "com.ibm.websphere.ltpa.pqc.version";
    public static final String PQC_ALGORITHM = "com.ibm.websphere.ltpa.pqc.algorithm";
    public static final String PQC_SECURITY_LEVEL = "com.ibm.websphere.ltpa.pqc.securityLevel";
    public static final String PQC_PRIVATE_KEY = "com.ibm.websphere.ltpa.pqc.PrivateKey";
    public static final String PQC_PUBLIC_KEY = "com.ibm.websphere.ltpa.pqc.PublicKey";
    public static final String PQC_AES256_KEY = "com.ibm.websphere.ltpa.pqc.AES256Key";
    public static final String PQC_CREATED = "com.ibm.websphere.ltpa.pqc.created";
    public static final String PQC_KEY_ROTATION = "com.ibm.websphere.ltpa.pqc.keyRotation";
    
    // Traditional LTPA key properties
    public static final String LTPA_VERSION = "com.ibm.websphere.ltpa.version";
    public static final String LTPA_3DES_KEY = "com.ibm.websphere.ltpa.3DESKey";
    public static final String LTPA_PRIVATE_KEY = "com.ibm.websphere.ltpa.PrivateKey";
    public static final String LTPA_PUBLIC_KEY = "com.ibm.websphere.ltpa.PublicKey";
    
    private static final String PQC_VERSION_VALUE = "3.0";
    
    /**
     * Generate a complete set of PQC keys
     * 
     * @param securityLevel NIST security level (2, 3, or 5)
     * @return Properties containing all PQC keys
     * @throws Exception if key generation fails
     */
    public static Properties generatePQCKeys(int securityLevel) throws Exception {
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Generating PQC keys with security level: " + securityLevel);
        }
        
        Properties props = new Properties();
        
        // Generate ML-DSA key pair
        MLDSAKeyPair keyPair = LTPAPQCCrypto.generateMLDSAKeyPair(securityLevel);
        
        // Generate AES-256 key
        byte[] aes256Key = LTPAPQCCrypto.generateAES256Key();
        
        // Encode keys to Base64
        String privateKeyB64 = Base64Coder.toString(Base64Coder.base64Encode(keyPair.getPrivateKey().getRawKey()));
        String publicKeyB64 = Base64Coder.toString(Base64Coder.base64Encode(keyPair.getPublicKey().getRawKey()));
        String aes256KeyB64 = Base64Coder.toString(Base64Coder.base64Encode(aes256Key));
        
        // Set properties
        props.setProperty(PQC_VERSION, PQC_VERSION_VALUE);
        props.setProperty(PQC_ALGORITHM, keyPair.getVariant());
        props.setProperty(PQC_SECURITY_LEVEL, String.valueOf(securityLevel));
        props.setProperty(PQC_PRIVATE_KEY, privateKeyB64);
        props.setProperty(PQC_PUBLIC_KEY, publicKeyB64);
        props.setProperty(PQC_AES256_KEY, aes256KeyB64);
        props.setProperty(PQC_CREATED, String.valueOf(System.currentTimeMillis()));
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "PQC keys generated successfully: " + keyPair.getVariant());
        }
        
        return props;
    }
    
    /**
     * Generate both traditional and PQC keys
     * 
     * @param securityLevel NIST security level for PQC keys
     * @return Properties containing both traditional and PQC keys
     * @throws Exception if key generation fails
     */
    public static Properties generateHybridKeys(int securityLevel) throws Exception {
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Generating hybrid keys (RSA + PQC)");
        }
        
        Properties props = new Properties();
        
        // Generate traditional RSA keys
        LTPAKeyPair rsaKeyPair = LTPAKeyUtil.generateLTPAKeyPair();
        byte[] sharedKey = LTPAKeyUtil.generateSharedKey();
        
        // Encode traditional keys
        String privateKeyB64 = Base64Coder.toString(Base64Coder.base64Encode(rsaKeyPair.getPrivateKey().getEncoded()));
        String publicKeyB64 = Base64Coder.toString(Base64Coder.base64Encode(rsaKeyPair.getPublicKey().getEncoded()));
        String sharedKeyB64 = Base64Coder.toString(Base64Coder.base64Encode(sharedKey));
        
        // Set traditional properties
        props.setProperty(LTPA_VERSION, "1.0");
        props.setProperty(LTPA_3DES_KEY, sharedKeyB64);
        props.setProperty(LTPA_PRIVATE_KEY, privateKeyB64);
        props.setProperty(LTPA_PUBLIC_KEY, publicKeyB64);
        
        // Generate and add PQC keys
        Properties pqcProps = generatePQCKeys(securityLevel);
        props.putAll(pqcProps);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Hybrid keys generated successfully");
        }
        
        return props;
    }
    
    /**
     * Load PQC keys from properties
     * 
     * @param props Properties containing PQC keys
     * @return PQCKeySet containing the loaded keys
     * @throws Exception if keys cannot be loaded
     */
    public static PQCKeySet loadPQCKeys(Properties props) throws Exception {
        if (props == null) {
            throw new IllegalArgumentException("Properties cannot be null");
        }
        
        // Check if PQC keys are present
        if (!props.containsKey(PQC_PRIVATE_KEY) || !props.containsKey(PQC_PUBLIC_KEY)) {
            return null; // No PQC keys available
        }
        
        // Load security level
        String secLevelStr = props.getProperty(PQC_SECURITY_LEVEL, "3");
        int securityLevel = Integer.parseInt(secLevelStr);
        
        // Decode keys from Base64
        byte[] privateKeyBytes = Base64Coder.base64Decode(Base64Coder.getBytes(props.getProperty(PQC_PRIVATE_KEY)));
        byte[] publicKeyBytes = Base64Coder.base64Decode(Base64Coder.getBytes(props.getProperty(PQC_PUBLIC_KEY)));
        byte[] aes256Key = null;
        
        if (props.containsKey(PQC_AES256_KEY)) {
            aes256Key = Base64Coder.base64Decode(Base64Coder.getBytes(props.getProperty(PQC_AES256_KEY)));
        }
        
        // Create key objects
        MLDSAPrivateKey privateKey = new MLDSAPrivateKey(privateKeyBytes, securityLevel);
        MLDSAPublicKey publicKey = new MLDSAPublicKey(publicKeyBytes, securityLevel);
        
        String algorithm = props.getProperty(PQC_ALGORITHM);
        String created = props.getProperty(PQC_CREATED);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "PQC keys loaded: " + algorithm);
        }
        
        return new PQCKeySet(privateKey, publicKey, aes256Key, algorithm, created);
    }
    
    /**
     * Save PQC keys to properties
     * 
     * @param keySet PQC key set to save
     * @return Properties containing the keys
     */
    public static Properties savePQCKeys(PQCKeySet keySet) {
        Properties props = new Properties();
        
        // Encode keys to Base64
        String privateKeyB64 = Base64Coder.toString(Base64Coder.base64Encode(keySet.getPrivateKey().getRawKey()));
        String publicKeyB64 = Base64Coder.toString(Base64Coder.base64Encode(keySet.getPublicKey().getRawKey()));
        
        props.setProperty(PQC_VERSION, PQC_VERSION_VALUE);
        props.setProperty(PQC_ALGORITHM, keySet.getAlgorithm());
        props.setProperty(PQC_SECURITY_LEVEL, String.valueOf(keySet.getPrivateKey().getSecurityLevel()));
        props.setProperty(PQC_PRIVATE_KEY, privateKeyB64);
        props.setProperty(PQC_PUBLIC_KEY, publicKeyB64);
        
        if (keySet.getAes256Key() != null) {
            String aes256KeyB64 = Base64Coder.toString(Base64Coder.base64Encode(keySet.getAes256Key()));
            props.setProperty(PQC_AES256_KEY, aes256KeyB64);
        }
        
        if (keySet.getCreated() != null) {
            props.setProperty(PQC_CREATED, keySet.getCreated());
        }
        
        return props;
    }
    
    /**
     * Check if properties contain PQC keys
     * 
     * @param props Properties to check
     * @return true if PQC keys are present
     */
    public static boolean hasPQCKeys(Properties props) {
        return props != null && 
               props.containsKey(PQC_PRIVATE_KEY) && 
               props.containsKey(PQC_PUBLIC_KEY);
    }
    
    /**
     * Check if properties contain traditional LTPA keys
     * 
     * @param props Properties to check
     * @return true if traditional keys are present
     */
    public static boolean hasTraditionalKeys(Properties props) {
        return props != null && 
               props.containsKey(LTPA_PRIVATE_KEY) && 
               props.containsKey(LTPA_PUBLIC_KEY);
    }
    
    /**
     * Merge traditional and PQC keys into a single properties object
     * 
     * @param traditionalProps Traditional LTPA keys
     * @param pqcProps PQC keys
     * @return Merged properties
     */
    public static Properties mergeKeys(Properties traditionalProps, Properties pqcProps) {
        Properties merged = new Properties();
        
        if (traditionalProps != null) {
            merged.putAll(traditionalProps);
        }
        
        if (pqcProps != null) {
            merged.putAll(pqcProps);
        }
        
        return merged;
    }
    
    /**
     * Container for PQC key set
     */
    public static class PQCKeySet {
        private final MLDSAPrivateKey privateKey;
        private final MLDSAPublicKey publicKey;
        @Sensitive
        private final byte[] aes256Key;
        private final String algorithm;
        private final String created;
        
        public PQCKeySet(MLDSAPrivateKey privateKey, MLDSAPublicKey publicKey, 
                        @Sensitive byte[] aes256Key, String algorithm, String created) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.aes256Key = (aes256Key != null) ? aes256Key.clone() : null;
            this.algorithm = algorithm;
            this.created = created;
        }
        
        public MLDSAPrivateKey getPrivateKey() {
            return privateKey;
        }
        
        public MLDSAPublicKey getPublicKey() {
            return publicKey;
        }
        
        @Sensitive
        public byte[] getAes256Key() {
            return (aes256Key != null) ? aes256Key.clone() : null;
        }
        
        public String getAlgorithm() {
            return algorithm;
        }
        
        public String getCreated() {
            return created;
        }
        
        public int getSecurityLevel() {
            return privateKey.getSecurityLevel();
        }
        
        @Override
        public String toString() {
            return "PQCKeySet[algorithm=" + algorithm + 
                   ", securityLevel=" + getSecurityLevel() + 
                   ", created=" + created + "]";
        }
    }
}

// Made with Bob
