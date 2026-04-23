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
import java.util.Arrays;

/**
 * Represents an ML-DSA (Dilithium) public key for LTPA.
 * ML-DSA is a NIST-standardized post-quantum digital signature algorithm.
 * 
 * Supports three security levels:
 * - Level 2 (ML-DSA-44): ~1952 bytes public key
 * - Level 3 (ML-DSA-65): ~2592 bytes public key (recommended)
 * - Level 5 (ML-DSA-87): ~2592 bytes public key
 */
public final class LTPAMLDSAPublicKey implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private final byte[] encodedKey;
    private final int securityLevel; // 2, 3, or 5
    
    /**
     * Create an ML-DSA public key.
     * 
     * @param encodedKey The encoded public key bytes
     * @param securityLevel The security level (2, 3, or 5)
     */
    public LTPAMLDSAPublicKey(byte[] encodedKey, int securityLevel) {
        if (encodedKey == null || encodedKey.length == 0) {
            throw new IllegalArgumentException("Encoded key cannot be null or empty");
        }
        if (securityLevel != 2 && securityLevel != 3 && securityLevel != 5) {
            throw new IllegalArgumentException("Security level must be 2, 3, or 5");
        }
        this.encodedKey = encodedKey.clone();
        this.securityLevel = securityLevel;
    }
    
    /**
     * Get the encoded public key bytes.
     * 
     * @return A copy of the encoded key
     */
    public byte[] getEncoded() {
        return encodedKey.clone();
    }
    
    /**
     * Get the security level.
     * 
     * @return The security level (2, 3, or 5)
     */
    public int getSecurityLevel() {
        return securityLevel;
    }
    
    /**
     * Get the algorithm name with security level.
     * 
     * @return Algorithm name (e.g., "ML-DSA-65")
     */
    public String getAlgorithm() {
        switch (securityLevel) {
            case 2:
                return "ML-DSA-44";
            case 3:
                return "ML-DSA-65";
            case 5:
                return "ML-DSA-87";
            default:
                return "ML-DSA-" + securityLevel;
        }
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LTPAMLDSAPublicKey)) {
            return false;
        }
        LTPAMLDSAPublicKey other = (LTPAMLDSAPublicKey) obj;
        return securityLevel == other.securityLevel && 
               Arrays.equals(encodedKey, other.encodedKey);
    }
    
    @Override
    public int hashCode() {
        return Arrays.hashCode(encodedKey) ^ securityLevel;
    }
    
    @Override
    public String toString() {
        return "LTPAMLDSAPublicKey[algorithm=" + getAlgorithm() + 
               ", keyLength=" + encodedKey.length + " bytes]";
    }
}

// Made with Bob
