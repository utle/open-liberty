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
import java.security.KeyPair;

/**
 * Container for an ML-DSA key pair (public and private keys).
 * Used for Post-Quantum Cryptography support in LTPA tokens.
 */
public class MLDSAKeyPair implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private final MLDSAPublicKey publicKey;
    private final MLDSAPrivateKey privateKey;
    private final int securityLevel;
    private final long creationTime;
    
    /**
     * Constructor for ML-DSA key pair
     * 
     * @param publicKey The ML-DSA public key
     * @param privateKey The ML-DSA private key
     */
    public MLDSAKeyPair(MLDSAPublicKey publicKey, MLDSAPrivateKey privateKey) {
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
        this.securityLevel = publicKey.getSecurityLevel();
        this.creationTime = System.currentTimeMillis();
    }
    
    /**
     * Get the public key
     */
    public MLDSAPublicKey getPublicKey() {
        return publicKey;
    }
    
    /**
     * Get the private key
     */
    public MLDSAPrivateKey getPrivateKey() {
        return privateKey;
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
        return publicKey.getVariant();
    }
    
    /**
     * Get the creation timestamp
     */
    public long getCreationTime() {
        return creationTime;
    }
    
    /**
     * Convert to standard Java KeyPair (for compatibility)
     */
    public KeyPair toKeyPair() {
        return new KeyPair(publicKey, privateKey);
    }
    
    /**
     * Destroy sensitive key material
     */
    public void destroy() {
        privateKey.destroy();
    }
    
    @Override
    public String toString() {
        return "MLDSAKeyPair[variant=" + getVariant() + 
               ", securityLevel=" + securityLevel + 
               ", created=" + new java.util.Date(creationTime) + "]";
    }
}

// Made with Bob
