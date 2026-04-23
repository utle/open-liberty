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

import com.ibm.websphere.ras.annotation.Sensitive;

/**
 * Interface for LTPA signature algorithms supporting both classical (RSA) and
 * post-quantum cryptography (ML-DSA/Dilithium) as well as hybrid approaches.
 * 
 * This abstraction enables crypto-agility and supports migration from RSA to
 * quantum-resistant algorithms.
 */
public interface LTPASignatureAlgorithm {
    
    /**
     * Sign data using the provided private key.
     * 
     * @param data The data to sign
     * @param privateKey The private key (type depends on algorithm)
     * @return The signature bytes
     * @throws Exception if signing fails
     */
    byte[] sign(byte[] data, @Sensitive Object privateKey) throws Exception;
    
    /**
     * Verify a signature using the provided public key.
     * 
     * @param data The original data
     * @param signature The signature to verify
     * @param publicKey The public key (type depends on algorithm)
     * @return true if signature is valid, false otherwise
     * @throws Exception if verification fails
     */
    boolean verify(byte[] data, byte[] signature, Object publicKey) throws Exception;
    
    /**
     * Get the algorithm name (e.g., "RSA", "ML-DSA-65", "HYBRID_RSA_MLDSA65").
     * 
     * @return The algorithm name
     */
    String getAlgorithmName();
    
    /**
     * Get the expected signature size in bytes.
     * For hybrid algorithms, this is the combined size.
     * 
     * @return The signature size in bytes
     */
    int getSignatureSize();
    
    /**
     * Get the LTPA version number for this algorithm.
     * - 2.0: LTPA2 (RSA)
     * - 3.0: LTPA2 Hybrid (RSA + ML-DSA)
     * - 4.0: LTPA2 Pure PQC (ML-DSA only)
     *
     * @return The version number
     */
    String getVersion();
    
    /**
     * Check if this algorithm is quantum-resistant.
     * 
     * @return true if quantum-resistant, false otherwise
     */
    boolean isQuantumResistant();
    
    /**
     * Check if this is a hybrid algorithm (combines classical and PQC).
     * 
     * @return true if hybrid, false otherwise
     */
    boolean isHybrid();
}

// Made with Bob
