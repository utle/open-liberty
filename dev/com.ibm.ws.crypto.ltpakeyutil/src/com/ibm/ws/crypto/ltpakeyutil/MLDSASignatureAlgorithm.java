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

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * ML-DSA (Dilithium) signature algorithm implementation for LTPA version 4.0.
 * Uses NIST-standardized post-quantum digital signature algorithm.
 * 
 * Supports three security levels:
 * - Level 2 (ML-DSA-44): ~2420 byte signatures
 * - Level 3 (ML-DSA-65): ~3293 byte signatures (recommended)
 * - Level 5 (ML-DSA-87): ~4595 byte signatures
 * 
 * Requires BouncyCastle PQC provider 1.78 or later.
 */
public class MLDSASignatureAlgorithm implements LTPASignatureAlgorithm {
    
    private static final TraceComponent tc = Tr.register(MLDSASignatureAlgorithm.class);
    
    private static final String ALGORITHM_NAME = "ML-DSA";
    private static final String VERSION = "4.0";
    private static final String PROVIDER = "BCPQC";
    
    // Signature sizes for each security level
    private static final int SIG_SIZE_LEVEL_2 = 2420;
    private static final int SIG_SIZE_LEVEL_3 = 3293;
    private static final int SIG_SIZE_LEVEL_5 = 4595;
    
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final int securityLevel;
    
    static {
        // Register BouncyCastle PQC provider if not already registered
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Registered BouncyCastle PQC provider");
            }
        }
    }
    
    /**
     * Create an ML-DSA signature algorithm instance.
     * 
     * @param privateKey The ML-DSA private key (may be null for verify-only)
     * @param publicKey The ML-DSA public key (may be null for sign-only)
     * @param securityLevel The security level (2, 3, or 5)
     */
    public MLDSASignatureAlgorithm(PrivateKey privateKey, PublicKey publicKey, int securityLevel) {
        if (privateKey == null && publicKey == null) {
            throw new IllegalArgumentException("At least one key must be provided");
        }
        if (securityLevel != 2 && securityLevel != 3 && securityLevel != 5) {
            throw new IllegalArgumentException("Security level must be 2, 3, or 5");
        }
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.securityLevel = securityLevel;
    }
    
    /**
     * Create an ML-DSA signature algorithm from an LTPAMLDSAKeyPair.
     * 
     * @param keyPair The ML-DSA key pair
     * @return ML-DSA signature algorithm instance
     * @throws Exception if key conversion fails
     */
    public static MLDSASignatureAlgorithm fromKeyPair(LTPAMLDSAKeyPair keyPair) throws Exception {
        if (keyPair == null) {
            throw new IllegalArgumentException("Key pair cannot be null");
        }
        
        int securityLevel = keyPair.getSecurityLevel();
        
        // Convert byte arrays to Java key objects
        KeyFactory keyFactory = KeyFactory.getInstance("Dilithium", PROVIDER);
        
        PrivateKey privateKey = null;
        if (keyPair.getPrivateKey() != null) {
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                keyPair.getPrivateKey().getEncoded()
            );
            privateKey = keyFactory.generatePrivate(privateKeySpec);
        }
        
        PublicKey publicKey = null;
        if (keyPair.getPublicKey() != null) {
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                keyPair.getPublicKey().getEncoded()
            );
            publicKey = keyFactory.generatePublic(publicKeySpec);
        }
        
        return new MLDSASignatureAlgorithm(privateKey, publicKey, securityLevel);
    }
    
    @Override
    public byte[] sign(@Sensitive byte[] data) throws Exception {
        if (privateKey == null) {
            throw new IllegalStateException("Private key not available for signing");
        }
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to sign cannot be null or empty");
        }
        
        try {
            String algorithm = getDilithiumAlgorithm();
            Signature signature = Signature.getInstance(algorithm, PROVIDER);
            signature.initSign(privateKey);
            signature.update(data);
            byte[] signatureBytes = signature.sign();
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA signature created, algorithm: " + algorithm + 
                        ", length: " + signatureBytes.length);
            }
            
            return signatureBytes;
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA signature creation failed: " + e.getMessage());
            }
            throw new Exception("Failed to create ML-DSA signature", e);
        }
    }
    
    @Override
    public boolean verify(@Sensitive byte[] data, byte[] signature) throws Exception {
        if (publicKey == null) {
            throw new IllegalStateException("Public key not available for verification");
        }
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to verify cannot be null or empty");
        }
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        
        try {
            String algorithm = getDilithiumAlgorithm();
            Signature verifier = Signature.getInstance(algorithm, PROVIDER);
            verifier.initVerify(publicKey);
            verifier.update(data);
            boolean valid = verifier.verify(signature);
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA signature verification result: " + valid + 
                        ", algorithm: " + algorithm);
            }
            
            return valid;
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA signature verification failed: " + e.getMessage());
            }
            throw new Exception("Failed to verify ML-DSA signature", e);
        }
    }
    
    @Override
    public String getAlgorithmName() {
        return ALGORITHM_NAME + "-" + getSecurityLevelName();
    }
    
    @Override
    public int getSignatureSize() {
        switch (securityLevel) {
            case 2:
                return SIG_SIZE_LEVEL_2;
            case 3:
                return SIG_SIZE_LEVEL_3;
            case 5:
                return SIG_SIZE_LEVEL_5;
            default:
                return SIG_SIZE_LEVEL_3; // Default to level 3
        }
    }
    
    @Override
    public String getVersion() {
        return VERSION;
    }
    
    @Override
    public boolean isQuantumResistant() {
        return true;
    }
    
    @Override
    public boolean isHybrid() {
        return false;
    }
    
    /**
     * Get the security level.
     * 
     * @return Security level (2, 3, or 5)
     */
    public int getSecurityLevel() {
        return securityLevel;
    }
    
    /**
     * Get the security level name.
     * 
     * @return Security level name (e.g., "44", "65", "87")
     */
    private String getSecurityLevelName() {
        switch (securityLevel) {
            case 2:
                return "44";
            case 3:
                return "65";
            case 5:
                return "87";
            default:
                return String.valueOf(securityLevel);
        }
    }
    
    /**
     * Get the Dilithium algorithm name for BouncyCastle.
     * 
     * @return Algorithm name (e.g., "Dilithium2", "Dilithium3", "Dilithium5")
     */
    private String getDilithiumAlgorithm() {
        return "Dilithium" + securityLevel;
    }
    
    @Override
    public String toString() {
        return "MLDSASignatureAlgorithm[version=" + VERSION + 
               ", algorithm=" + getAlgorithmName() + 
               ", securityLevel=" + securityLevel + "]";
    }
}

// Made with Bob
