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

/**
 * Represents a hybrid key pair combining RSA and ML-DSA keys for LTPA.
 * Used for LTPA version 3.0 (hybrid signatures).
 * 
 * Hybrid signatures provide quantum resistance while maintaining backward
 * compatibility with existing RSA-based systems. Both signatures must be
 * valid for the token to be accepted.
 * 
 * Recommended configuration:
 * - RSA: 2048-bit or 3072-bit
 * - ML-DSA: Security level 3 (ML-DSA-65)
 */
public final class LTPAHybridKeyPair implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private final LTPAKeyPair rsaKeyPair;
    private final LTPAMLDSAKeyPair mldsaKeyPair;
    
    /**
     * Create a hybrid key pair.
     * 
     * @param rsaKeyPair The RSA key pair
     * @param mldsaKeyPair The ML-DSA key pair
     * @throws IllegalArgumentException if either key pair is null
     */
    public LTPAHybridKeyPair(LTPAKeyPair rsaKeyPair, LTPAMLDSAKeyPair mldsaKeyPair) {
        if (rsaKeyPair == null) {
            throw new IllegalArgumentException("RSA key pair cannot be null");
        }
        if (mldsaKeyPair == null) {
            throw new IllegalArgumentException("ML-DSA key pair cannot be null");
        }
        this.rsaKeyPair = rsaKeyPair;
        this.mldsaKeyPair = mldsaKeyPair;
    }
    
    /**
     * Get the RSA key pair.
     * 
     * @return The RSA key pair
     */
    public LTPAKeyPair getRSAKeyPair() {
        return rsaKeyPair;
    }
    
    /**
     * Get the ML-DSA key pair.
     * 
     * @return The ML-DSA key pair
     */
    public LTPAMLDSAKeyPair getMLDSAKeyPair() {
        return mldsaKeyPair;
    }
    
    /**
     * Get the RSA key size in bits.
     * 
     * @return RSA key size (e.g., 2048, 3072)
     */
    public int getRSAKeySize() {
        // Calculate from modulus length
        byte[] publicKey = rsaKeyPair.getPublicKey();
        if (publicKey != null && publicKey.length > 0) {
            // Approximate: actual size depends on encoding
            return publicKey.length * 8;
        }
        return 0;
    }
    
    /**
     * Get the ML-DSA security level.
     * 
     * @return Security level (2, 3, or 5)
     */
    public int getMLDSASecurityLevel() {
        return mldsaKeyPair.getSecurityLevel();
    }
    
    /**
     * Get a description of the hybrid algorithm.
     * 
     * @return Algorithm description (e.g., "RSA-2048 + ML-DSA-65")
     */
    public String getAlgorithmDescription() {
        return "RSA-" + getRSAKeySize() + " + " + mldsaKeyPair.getAlgorithm();
    }
    
    /**
     * Clear the private key material from memory.
     * Should be called when the key pair is no longer needed.
     */
    public void destroy() {
        if (mldsaKeyPair != null) {
            mldsaKeyPair.destroy();
        }
        // Note: LTPAKeyPair doesn't have a destroy method, but we should
        // consider adding one for consistency
    }
    
    @Override
    public String toString() {
        return "LTPAHybridKeyPair[" + getAlgorithmDescription() + "]";
    }
}

// Made with Bob
