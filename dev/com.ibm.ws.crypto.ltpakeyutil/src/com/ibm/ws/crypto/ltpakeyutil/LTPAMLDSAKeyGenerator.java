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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;

/**
 * Utility class for generating ML-DSA (Dilithium) key pairs for LTPA.
 * 
 * Supports three security levels:
 * - Level 2 (ML-DSA-44): NIST Security Category 2
 * - Level 3 (ML-DSA-65): NIST Security Category 3 (recommended)
 * - Level 5 (ML-DSA-87): NIST Security Category 5
 * 
 * Security levels correspond to:
 * - Level 2: Equivalent to AES-128
 * - Level 3: Equivalent to AES-192
 * - Level 5: Equivalent to AES-256
 */
public class LTPAMLDSAKeyGenerator {
    
    private static final TraceComponent tc = Tr.register(LTPAMLDSAKeyGenerator.class);
    
    private static final String ALGORITHM = "Dilithium";
    private static final String PROVIDER = "BCPQC";
    
    // Default security level (3 = ML-DSA-65, equivalent to AES-192)
    public static final int DEFAULT_SECURITY_LEVEL = 3;
    
    static {
        // Register BouncyCastle PQC provider if not already registered
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Registered BouncyCastle PQC provider for ML-DSA key generation");
            }
        }
    }
    
    /**
     * Generate an ML-DSA key pair with the default security level (3).
     * 
     * @return LTPAMLDSAKeyPair with security level 3 (ML-DSA-65)
     * @throws Exception if key generation fails
     */
    public static LTPAMLDSAKeyPair generateKeyPair() throws Exception {
        return generateKeyPair(DEFAULT_SECURITY_LEVEL);
    }
    
    /**
     * Generate an ML-DSA key pair with the specified security level.
     * 
     * @param securityLevel The security level (2, 3, or 5)
     * @return LTPAMLDSAKeyPair with the specified security level
     * @throws Exception if key generation fails
     */
    public static LTPAMLDSAKeyPair generateKeyPair(int securityLevel) throws Exception {
        if (securityLevel != 2 && securityLevel != 3 && securityLevel != 5) {
            throw new IllegalArgumentException("Security level must be 2, 3, or 5");
        }
        
        try {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Generating ML-DSA key pair with security level: " + securityLevel);
            }
            
            // Get the appropriate parameter spec for the security level
            DilithiumParameterSpec paramSpec = getDilithiumParameterSpec(securityLevel);
            
            // Create key pair generator
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
            keyPairGen.initialize(paramSpec, new SecureRandom());
            
            // Generate key pair
            KeyPair keyPair = keyPairGen.generateKeyPair();
            
            // Extract encoded keys
            byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
            byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
            
            // Create LTPA ML-DSA key objects
            LTPAMLDSAPublicKey publicKey = new LTPAMLDSAPublicKey(publicKeyBytes, securityLevel);
            LTPAMLDSAPrivateKey privateKey = new LTPAMLDSAPrivateKey(privateKeyBytes, securityLevel);
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA key pair generated successfully - " +
                        "Public key: " + publicKeyBytes.length + " bytes, " +
                        "Private key: " + privateKeyBytes.length + " bytes");
            }
            
            return new LTPAMLDSAKeyPair(publicKey, privateKey);
            
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA key generation failed: " + e.getMessage());
            }
            throw new Exception("Failed to generate ML-DSA key pair", e);
        }
    }
    
    /**
     * Generate a hybrid key pair combining RSA and ML-DSA.
     * 
     * @param rsaKeySize RSA key size in bits (2048 or 3072 recommended)
     * @param mldsaSecurityLevel ML-DSA security level (2, 3, or 5)
     * @return LTPAHybridKeyPair containing both RSA and ML-DSA keys
     * @throws Exception if key generation fails
     */
    public static LTPAHybridKeyPair generateHybridKeyPair(int rsaKeySize, int mldsaSecurityLevel) throws Exception {
        if (rsaKeySize < 2048) {
            throw new IllegalArgumentException("RSA key size must be at least 2048 bits");
        }
        if (mldsaSecurityLevel != 2 && mldsaSecurityLevel != 3 && mldsaSecurityLevel != 5) {
            throw new IllegalArgumentException("ML-DSA security level must be 2, 3, or 5");
        }
        
        try {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Generating hybrid key pair - RSA: " + rsaKeySize + 
                        " bits, ML-DSA: level " + mldsaSecurityLevel);
            }
            
            // Generate RSA key pair
            LTPAKeyPair rsaKeyPair = LTPAKeyUtil.generateLTPAKeyPair(null, rsaKeySize);
            
            // Generate ML-DSA key pair
            LTPAMLDSAKeyPair mldsaKeyPair = generateKeyPair(mldsaSecurityLevel);
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Hybrid key pair generated successfully");
            }
            
            return new LTPAHybridKeyPair(rsaKeyPair, mldsaKeyPair);
            
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Hybrid key generation failed: " + e.getMessage());
            }
            throw new Exception("Failed to generate hybrid key pair", e);
        }
    }
    
    /**
     * Generate a hybrid key pair with default settings.
     * Uses RSA-2048 and ML-DSA security level 3.
     * 
     * @return LTPAHybridKeyPair with default settings
     * @throws Exception if key generation fails
     */
    public static LTPAHybridKeyPair generateHybridKeyPair() throws Exception {
        return generateHybridKeyPair(2048, DEFAULT_SECURITY_LEVEL);
    }
    
    /**
     * Get the Dilithium parameter spec for the specified security level.
     * 
     * @param securityLevel The security level (2, 3, or 5)
     * @return DilithiumParameterSpec for the security level
     */
    private static DilithiumParameterSpec getDilithiumParameterSpec(int securityLevel) {
        switch (securityLevel) {
            case 2:
                return DilithiumParameterSpec.dilithium2;
            case 3:
                return DilithiumParameterSpec.dilithium3;
            case 5:
                return DilithiumParameterSpec.dilithium5;
            default:
                throw new IllegalArgumentException("Invalid security level: " + securityLevel);
        }
    }
    
    /**
     * Get the recommended security level based on RSA key size.
     * This helps maintain equivalent security strength.
     * 
     * @param rsaKeySize RSA key size in bits
     * @return Recommended ML-DSA security level
     */
    public static int getRecommendedMLDSALevel(int rsaKeySize) {
        if (rsaKeySize >= 4096) {
            return 5; // ML-DSA-87 for RSA-4096+
        } else if (rsaKeySize >= 3072) {
            return 3; // ML-DSA-65 for RSA-3072
        } else {
            return 2; // ML-DSA-44 for RSA-2048
        }
    }
    
    /**
     * Validate that a security level is supported.
     * 
     * @param securityLevel The security level to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidSecurityLevel(int securityLevel) {
        return securityLevel == 2 || securityLevel == 3 || securityLevel == 5;
    }
    
    /**
     * Get a human-readable description of a security level.
     * 
     * @param securityLevel The security level (2, 3, or 5)
     * @return Description string
     */
    public static String getSecurityLevelDescription(int securityLevel) {
        switch (securityLevel) {
            case 2:
                return "ML-DSA-44 (NIST Category 2, equivalent to AES-128)";
            case 3:
                return "ML-DSA-65 (NIST Category 3, equivalent to AES-192, recommended)";
            case 5:
                return "ML-DSA-87 (NIST Category 5, equivalent to AES-256)";
            default:
                return "Unknown security level";
        }
    }
}

// Made with Bob
