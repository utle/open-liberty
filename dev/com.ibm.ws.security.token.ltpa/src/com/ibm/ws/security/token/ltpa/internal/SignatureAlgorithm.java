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
package com.ibm.ws.security.token.ltpa.internal;

/**
 * Enumeration of signature algorithms supported for LTPA tokens.
 * Used to specify which cryptographic algorithm should be used for token signing.
 */
public enum SignatureAlgorithm {
    
    /**
     * RSA signature algorithm (legacy, classical cryptography)
     * - Uses RSA-2048 or RSA-1024 keys
     * - ISO9796 padding
     * - Compatible with LTPAToken2
     * - Not quantum-resistant
     */
    RSA("RSA", "Classical RSA signature", false, 1),
    
    /**
     * ML-DSA signature algorithm (Post-Quantum Cryptography)
     * - Uses ML-DSA (Dilithium) keys
     * - NIST FIPS 204 standard
     * - Quantum-resistant
     * - Requires LTPAToken3
     */
    ML_DSA("ML-DSA", "Post-Quantum ML-DSA signature", true, 3),
    
    /**
     * Hybrid signature algorithm (RSA + ML-DSA)
     * - Uses both RSA and ML-DSA keys
     * - Provides defense-in-depth
     * - Quantum-resistant
     * - Requires LTPAToken3
     * - Both signatures must verify for token to be valid
     */
    HYBRID("HYBRID", "Hybrid RSA + ML-DSA signature", true, 3);
    
    private final String algorithmName;
    private final String description;
    private final boolean quantumResistant;
    private final int minimumTokenVersion;
    
    /**
     * Constructor
     * 
     * @param algorithmName The algorithm name
     * @param description Human-readable description
     * @param quantumResistant Whether the algorithm is quantum-resistant
     * @param minimumTokenVersion Minimum LTPA token version required
     */
    SignatureAlgorithm(String algorithmName, String description, boolean quantumResistant, int minimumTokenVersion) {
        this.algorithmName = algorithmName;
        this.description = description;
        this.quantumResistant = quantumResistant;
        this.minimumTokenVersion = minimumTokenVersion;
    }
    
    /**
     * Get the algorithm name
     */
    public String getAlgorithmName() {
        return algorithmName;
    }
    
    /**
     * Get the description
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Check if this algorithm is quantum-resistant
     */
    public boolean isQuantumResistant() {
        return quantumResistant;
    }
    
    /**
     * Get the minimum token version required for this algorithm
     */
    public int getMinimumTokenVersion() {
        return minimumTokenVersion;
    }
    
    /**
     * Check if this algorithm requires PQC keys
     */
    public boolean requiresPQCKeys() {
        return this == ML_DSA || this == HYBRID;
    }
    
    /**
     * Check if this algorithm requires RSA keys
     */
    public boolean requiresRSAKeys() {
        return this == RSA || this == HYBRID;
    }
    
    /**
     * Parse algorithm from string (case-insensitive)
     * 
     * @param value The string value
     * @return The SignatureAlgorithm, or null if not found
     */
    public static SignatureAlgorithm fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        
        String normalized = value.trim().toUpperCase().replace("-", "_");
        
        try {
            return SignatureAlgorithm.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
    
    /**
     * Get the default algorithm (RSA for backward compatibility)
     */
    public static SignatureAlgorithm getDefault() {
        return RSA;
    }
    
    /**
     * Get the recommended algorithm for new deployments
     */
    public static SignatureAlgorithm getRecommended() {
        return HYBRID;
    }
    
    @Override
    public String toString() {
        return algorithmName + " (" + description + ", quantum-resistant=" + quantumResistant + ")";
    }
}

// Made with Bob
