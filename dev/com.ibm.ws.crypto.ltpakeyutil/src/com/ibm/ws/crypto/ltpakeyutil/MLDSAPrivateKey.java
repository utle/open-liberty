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
import java.security.PrivateKey;
import java.util.Arrays;

import com.ibm.websphere.ras.annotation.Sensitive;

/**
 * Represents an ML-DSA (Module-Lattice-Based Digital Signature Algorithm) private key
 * for Post-Quantum Cryptography support in LTPA tokens.
 * 
 * ML-DSA is the NIST-standardized version of Dilithium (FIPS 204).
 */
public class MLDSAPrivateKey implements Serializable, PrivateKey {
    
    private static final long serialVersionUID = 1L;
    private static final String ALGORITHM = "ML-DSA";
    
    @Sensitive
    private final byte[] keyBytes;
    private final int securityLevel; // 2, 3, or 5 (NIST security levels)
    private final String variant; // ML-DSA-44, ML-DSA-65, or ML-DSA-87
    
    /**
     * Constructor for ML-DSA private key
     * 
     * @param keyBytes The raw key bytes
     * @param securityLevel The NIST security level (2, 3, or 5)
     */
    public MLDSAPrivateKey(@Sensitive byte[] keyBytes, int securityLevel) {
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
    public static int getPrivateKeySize(int securityLevel) {
        switch (securityLevel) {
            case 2:
                return 2560; // ML-DSA-44
            case 3:
                return 4032; // ML-DSA-65
            case 5:
                return 4896; // ML-DSA-87
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
    @Sensitive
    public byte[] getEncoded() {
        return keyBytes.clone();
    }
    
    /**
     * Get the raw key bytes (internal use)
     */
    @Sensitive
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
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MLDSAPrivateKey)) {
            return false;
        }
        MLDSAPrivateKey other = (MLDSAPrivateKey) obj;
        return securityLevel == other.securityLevel && 
               Arrays.equals(keyBytes, other.keyBytes);
    }
    
    @Override
    public int hashCode() {
        return Arrays.hashCode(keyBytes) ^ securityLevel;
    }
    
    @Override
    public String toString() {
        return "MLDSAPrivateKey[variant=" + variant + 
               ", securityLevel=" + securityLevel + 
               ", keySize=" + keyBytes.length + " bytes]";
    }
    
    /**
     * Clear sensitive key material from memory
     */
    public void destroy() {
        Arrays.fill(keyBytes, (byte) 0);
    }
}

// Made with Bob
