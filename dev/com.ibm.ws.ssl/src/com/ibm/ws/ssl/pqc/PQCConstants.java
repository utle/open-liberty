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
package com.ibm.ws.ssl.pqc;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Constants for Post-Quantum Cryptography (PQC) support in Liberty SSL.
 * 
 * This class defines the supported PQC algorithms, cipher suites, and
 * recommended configurations based on NIST standards (FIPS 203, 204, 205).
 */
public class PQCConstants {
    
    /**
     * Supported PQC Key Encapsulation Mechanism (KEM) algorithms.
     * Based on NIST FIPS 203 (ML-KEM / Kyber).
     */
    public static final List<String> SUPPORTED_KEM_ALGORITHMS = Collections.unmodifiableList(
        Arrays.asList(
            "ML-KEM-512",   // NIST Security Level 1
            "ML-KEM-768",   // NIST Security Level 3 (Recommended)
            "ML-KEM-1024"   // NIST Security Level 5
        )
    );
    
    /**
     * Supported PQC Digital Signature algorithms.
     * Based on NIST FIPS 204 (ML-DSA / Dilithium).
     */
    public static final List<String> SUPPORTED_SIGNATURE_ALGORITHMS = Collections.unmodifiableList(
        Arrays.asList(
            "ML-DSA-44",    // NIST Security Level 2
            "ML-DSA-65",    // NIST Security Level 3 (Recommended)
            "ML-DSA-87"     // NIST Security Level 5
        )
    );
    
    /**
     * Recommended PQC KEM algorithm for most use cases.
     * ML-KEM-768 provides NIST Level 3 security with balanced performance.
     */
    public static final String RECOMMENDED_KEM = "ML-KEM-768";
    
    /**
     * Recommended PQC signature algorithm for most use cases.
     * ML-DSA-65 provides NIST Level 3 security with balanced performance.
     */
    public static final String RECOMMENDED_SIGNATURE = "ML-DSA-65";
    
    /**
     * Hybrid cipher suites combining classical and PQC algorithms.
     * These follow IETF draft specifications for hybrid key exchange in TLS 1.3.
     */
    public static final String[] HYBRID_CIPHER_SUITES = {
        "TLS_AES_128_GCM_SHA256_X25519_MLKEM768",
        "TLS_AES_256_GCM_SHA384_P256_MLKEM768",
        "TLS_CHACHA20_POLY1305_SHA256_X25519_MLKEM768"
    };
    
    /**
     * Default hybrid cipher suites as an unmodifiable list.
     */
    public static final List<String> DEFAULT_HYBRID_CIPHERS = Collections.unmodifiableList(
        Arrays.asList(HYBRID_CIPHER_SUITES)
    );
    
    /**
     * Algorithm key sizes in bytes.
     * PQC algorithms have significantly larger keys than classical algorithms.
     */
    public static final int MLKEM512_PUBLIC_KEY_SIZE = 800;
    public static final int MLKEM768_PUBLIC_KEY_SIZE = 1184;
    public static final int MLKEM1024_PUBLIC_KEY_SIZE = 1568;
    
    public static final int MLDSA44_PUBLIC_KEY_SIZE = 1312;
    public static final int MLDSA65_PUBLIC_KEY_SIZE = 1952;
    public static final int MLDSA87_PUBLIC_KEY_SIZE = 2592;
    
    /**
     * Signature sizes in bytes.
     */
    public static final int MLDSA44_SIGNATURE_SIZE = 2420;
    public static final int MLDSA65_SIGNATURE_SIZE = 3293;
    public static final int MLDSA87_SIGNATURE_SIZE = 4595;
    
    /**
     * NIST security levels for PQC algorithms.
     */
    public static final int NIST_LEVEL_1 = 1;  // Equivalent to AES-128
    public static final int NIST_LEVEL_2 = 2;  // Equivalent to SHA-256
    public static final int NIST_LEVEL_3 = 3;  // Equivalent to AES-192
    public static final int NIST_LEVEL_5 = 5;  // Equivalent to AES-256
    
    /**
     * Get the NIST security level for a given KEM algorithm.
     * 
     * @param algorithm the KEM algorithm name
     * @return the NIST security level, or -1 if unknown
     */
    public static int getKemSecurityLevel(String algorithm) {
        if (algorithm == null) {
            return -1;
        }
        
        switch (algorithm) {
            case "ML-KEM-512":
                return NIST_LEVEL_1;
            case "ML-KEM-768":
                return NIST_LEVEL_3;
            case "ML-KEM-1024":
                return NIST_LEVEL_5;
            default:
                return -1;
        }
    }
    
    /**
     * Get the NIST security level for a given signature algorithm.
     * 
     * @param algorithm the signature algorithm name
     * @return the NIST security level, or -1 if unknown
     */
    public static int getSignatureSecurityLevel(String algorithm) {
        if (algorithm == null) {
            return -1;
        }
        
        switch (algorithm) {
            case "ML-DSA-44":
                return NIST_LEVEL_2;
            case "ML-DSA-65":
                return NIST_LEVEL_3;
            case "ML-DSA-87":
                return NIST_LEVEL_5;
            default:
                return -1;
        }
    }
    
    /**
     * Check if the given algorithm is a supported KEM algorithm.
     * 
     * @param algorithm the algorithm name to check
     * @return true if supported, false otherwise
     */
    public static boolean isSupportedKemAlgorithm(String algorithm) {
        return SUPPORTED_KEM_ALGORITHMS.contains(algorithm);
    }
    
    /**
     * Check if the given algorithm is a supported signature algorithm.
     * 
     * @param algorithm the algorithm name to check
     * @return true if supported, false otherwise
     */
    public static boolean isSupportedSignatureAlgorithm(String algorithm) {
        return SUPPORTED_SIGNATURE_ALGORITHMS.contains(algorithm);
    }
    
    /**
     * Get the public key size for a given KEM algorithm.
     * 
     * @param algorithm the KEM algorithm name
     * @return the public key size in bytes, or -1 if unknown
     */
    public static int getKemPublicKeySize(String algorithm) {
        if (algorithm == null) {
            return -1;
        }
        
        switch (algorithm) {
            case "ML-KEM-512":
                return MLKEM512_PUBLIC_KEY_SIZE;
            case "ML-KEM-768":
                return MLKEM768_PUBLIC_KEY_SIZE;
            case "ML-KEM-1024":
                return MLKEM1024_PUBLIC_KEY_SIZE;
            default:
                return -1;
        }
    }
    
    /**
     * Get the public key size for a given signature algorithm.
     * 
     * @param algorithm the signature algorithm name
     * @return the public key size in bytes, or -1 if unknown
     */
    public static int getSignaturePublicKeySize(String algorithm) {
        if (algorithm == null) {
            return -1;
        }
        
        switch (algorithm) {
            case "ML-DSA-44":
                return MLDSA44_PUBLIC_KEY_SIZE;
            case "ML-DSA-65":
                return MLDSA65_PUBLIC_KEY_SIZE;
            case "ML-DSA-87":
                return MLDSA87_PUBLIC_KEY_SIZE;
            default:
                return -1;
        }
    }
    
    /**
     * Get the signature size for a given signature algorithm.
     * 
     * @param algorithm the signature algorithm name
     * @return the signature size in bytes, or -1 if unknown
     */
    public static int getSignatureSize(String algorithm) {
        if (algorithm == null) {
            return -1;
        }
        
        switch (algorithm) {
            case "ML-DSA-44":
                return MLDSA44_SIGNATURE_SIZE;
            case "ML-DSA-65":
                return MLDSA65_SIGNATURE_SIZE;
            case "ML-DSA-87":
                return MLDSA87_SIGNATURE_SIZE;
            default:
                return -1;
        }
    }
    
    /**
     * Private constructor to prevent instantiation.
     */
    private PQCConstants() {
        // Utility class - no instances
    }
}

// Made with Bob
