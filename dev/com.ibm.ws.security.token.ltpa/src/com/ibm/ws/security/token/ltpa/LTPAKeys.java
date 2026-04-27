/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.security.token.ltpa;

/**
 * Simple data holder for LTPA key bytes.
 * Contains the three types of keys used in LTPA:
 * - Secret key (AES) for token encryption
 * - Private key (RSA) for token signing
 * - Public key (RSA) for token verification
 */
public class LTPAKeys {
    private final byte[] secretKeyBytes;
    private final byte[] privateKeyBytes;
    private final byte[] publicKeyBytes;

    /**
     * Create a new LTPAKeys instance with the specified key bytes.
     *
     * @param secretKey  The secret key bytes (AES)
     * @param privateKey The private key bytes (RSA)
     * @param publicKey  The public key bytes (RSA)
     */
    public LTPAKeys(byte[] secretKey, byte[] privateKey, byte[] publicKey) {
        if (secretKey == null || privateKey == null || publicKey == null) {
            throw new IllegalArgumentException("All key bytes must be non-null");
        }
        this.secretKeyBytes = secretKey.clone();
        this.privateKeyBytes = privateKey.clone();
        this.publicKeyBytes = publicKey.clone();
    }

    /**
     * Get the secret key bytes.
     *
     * @return A copy of the secret key bytes
     */
    public byte[] getSecretKeyBytes() {
        return secretKeyBytes.clone();
    }

    /**
     * Get the private key bytes.
     *
     * @return A copy of the private key bytes
     */
    public byte[] getPrivateKeyBytes() {
        return privateKeyBytes.clone();
    }

    /**
     * Get the public key bytes.
     *
     * @return A copy of the public key bytes
     */
    public byte[] getPublicKeyBytes() {
        return publicKeyBytes.clone();
    }
}

// Made with Bob
