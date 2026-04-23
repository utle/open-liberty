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
 * Represents an ML-DSA (Dilithium) key pair for LTPA.
 * Contains both public and private keys for post-quantum digital signatures.
 * 
 * This class is used for pure ML-DSA signatures (LTPA version 4.0).
 * For hybrid RSA+ML-DSA signatures (version 3.0), use {@link LTPAHybridKeyPair}.
 */
public final class LTPAMLDSAKeyPair implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private final LTPAMLDSAPublicKey publicKey;
    private final LTPAMLDSAPrivateKey privateKey;
    
    /**
     * Create an ML-DSA key pair.
     * 
     * @param publicKey The public key
     * @param privateKey The private key
     * @throws IllegalArgumentException if keys are null or have mismatched security levels
     */
    public LTPAMLDSAKeyPair(LTPAMLDSAPublicKey publicKey, LTPAMLDSAPrivateKey privateKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        if (publicKey.getSecurityLevel() != privateKey.getSecurityLevel()) {
            throw new IllegalArgumentException("Public and private keys must have the same security level");
        }
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }
    
    /**
     * Get the public key.
     * 
     * @return The ML-DSA public key
     */
    public LTPAMLDSAPublicKey getPublicKey() {
        return publicKey;
    }
    
    /**
     * Get the private key.
     * 
     * @return The ML-DSA private key
     */
    public LTPAMLDSAPrivateKey getPrivateKey() {
        return privateKey;
    }
    
    /**
     * Get the security level of this key pair.
     * 
     * @return The security level (2, 3, or 5)
     */
    public int getSecurityLevel() {
        return publicKey.getSecurityLevel();
    }
    
    /**
     * Get the algorithm name.
     * 
     * @return Algorithm name (e.g., "ML-DSA-65")
     */
    public String getAlgorithm() {
        return publicKey.getAlgorithm();
    }
    
    /**
     * Clear the private key material from memory.
     * Should be called when the key pair is no longer needed.
     */
    public void destroy() {
        if (privateKey != null) {
            privateKey.destroy();
        }
    }
    
    @Override
    public String toString() {
        return "LTPAMLDSAKeyPair[algorithm=" + getAlgorithm() + 
               ", securityLevel=" + getSecurityLevel() + "]";
    }
}

// Made with Bob
