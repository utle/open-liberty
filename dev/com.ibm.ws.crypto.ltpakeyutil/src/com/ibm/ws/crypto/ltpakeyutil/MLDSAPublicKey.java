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

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Represents an ML-DSA (Module-Lattice-Based Digital Signature Algorithm) public key
 * for Post-Quantum Cryptography support in LTPA tokens.
 * 
 * ML-DSA is the NIST-standardized version of Dilithium (FIPS 204).
 */
public class MLDSAPublicKey implements Serializable, PublicKey {
    
    private static final long serialVersionUID = 1L;
    private static final String ALGORITHM = "ML-DSA";
    
    private final byte[] keyBytes;
    private final int securityLevel; // 2, 3, or 5 (NIST security levels)
    private final String variant; // ML-DSA-44, ML-DSA-65, or ML-DSA-87
    
    /**
     * Constructor for ML-DSA public key
     * 
     * @param keyBytes The raw key bytes
     * @param securityLevel The NIST security level (2, 3, or 5)
     */
    public MLDSAPublicKey(byte[] keyBytes, int securityLevel) {
        if (keyBytes == null || keyBytes.length == 0) {
            throw new IllegalArgumentException("Key bytes cannot be null or empty");
        }
        if (securityLevel != 2 && securityLevel != 3 && securityLevel != 5) {
            throw new IllegalArgumentException("Security level must be 2, 3, or 5");
        }
        
        this.keyBytes = keyBytes.clone();
        this.securityLevel = securityLevel;
        this.variant = getVariantForSecurityLevel(securityLevel);
    }
    
    /**
     * Get the variant name based on security level
     */
    private static String getVariantForSecurityLevel(int level) {
        switch (level) {
            case 2:
                return "ML-DSA-44";
            case 3:
                return "ML-DSA-65";
            case 5:
                return "ML-DSA-87";
            default:
                throw new IllegalArgumentException("Invalid security level: " + level);
        }
    }
    
    /**
     * Get the expected key size for a security level
     */
    public static int getPublicKeySize(int securityLevel) {
        switch (securityLevel) {
            case 2:
                return 1312; // ML-DSA-44
            case 3:
                return 1952; // ML-DSA-65
            case 5:
                return 2592; // ML-DSA-87
            default:
                throw new IllegalArgumentException("Invalid security level: " + securityLevel);
        }
    }
    
    /**
     * Get the expected signature size for a security level
     */
    public static int getSignatureSize(int securityLevel) {
        switch (securityLevel) {
            case 2:
                return 2420; // ML-DSA-44
            case 3:
                return 3309; // ML-DSA-65
            case 5:
                return 4627; // ML-DSA-87
            default:
                throw new IllegalArgumentException("Invalid security level: " + securityLevel);
        }
    }
    
    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }
    
    @Override
    public String getFormat() {
        return "RAW";
    }
    
    @Override
    public byte[] getEncoded() {
        return keyBytes.clone();
    }
    
    /**
     * Get the raw key bytes (internal use)
     */
    public byte[] getRawKey() {
        return keyBytes.clone();
    }
    
    /**
     * Get the security level
     */
    public int getSecurityLevel() {
        return securityLevel;
    }
    
    /**
     * Get the ML-DSA variant name
     */
    public String getVariant() {
        return variant;
    }
    
    /**
     * Get the key size in bytes
     */
    public int getKeySize() {
        return keyBytes.length;
    }
    
    /**
     * Get the expected signature size for this key
     */
    public int getExpectedSignatureSize() {
        return getSignatureSize(securityLevel);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MLDSAPublicKey)) {
            return false;
        }
        MLDSAPublicKey other = (MLDSAPublicKey) obj;
        return securityLevel == other.securityLevel && 
               Arrays.equals(keyBytes, other.keyBytes);
    }
    
    @Override
    public int hashCode() {
        return Arrays.hashCode(keyBytes) ^ securityLevel;
    }
    
    @Override
    public String toString() {
        return "MLDSAPublicKey[variant=" + variant + 
               ", securityLevel=" + securityLevel + 
               ", keySize=" + keyBytes.length + " bytes" +
               ", signatureSize=" + getExpectedSignatureSize() + " bytes]";
    }
}

// Made with Bob
