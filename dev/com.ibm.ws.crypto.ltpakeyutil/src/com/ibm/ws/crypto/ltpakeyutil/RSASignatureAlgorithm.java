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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;

/**
 * RSA signature algorithm implementation for LTPA version 2.0.
 * Uses RSA with ISO9796-2 padding scheme.
 * 
 * This implementation maintains backward compatibility with existing
 * LTPA2 tokens while providing a clean abstraction for crypto-agility.
 */
public class RSASignatureAlgorithm implements LTPASignatureAlgorithm {
    
    private static final TraceComponent tc = Tr.register(RSASignatureAlgorithm.class);
    
    private static final String SIGNATURE_ALGORITHM = "SHA1withRSA/ISO9796-2";
    private static final String VERSION = "2.0";
    
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    
    /**
     * Create an RSA signature algorithm instance.
     * 
     * @param privateKey The RSA private key (may be null for verify-only)
     * @param publicKey The RSA public key (may be null for sign-only)
     */
    public RSASignatureAlgorithm(PrivateKey privateKey, PublicKey publicKey) {
        if (privateKey == null && publicKey == null) {
            throw new IllegalArgumentException("At least one key must be provided");
        }
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
    
    /**
     * Create an RSA signature algorithm from an LTPAKeyPair.
     * 
     * @param keyPair The LTPA key pair containing RSA keys
     * @return RSA signature algorithm instance
     * @throws Exception if key conversion fails
     */
    public static RSASignatureAlgorithm fromKeyPair(LTPAKeyPair keyPair) throws Exception {
        if (keyPair == null) {
            throw new IllegalArgumentException("Key pair cannot be null");
        }
        
        // Convert byte arrays to Java key objects
        PrivateKey privateKey = LTPAKeyUtil.getPrivateKey(keyPair.getPrivateKey());
        PublicKey publicKey = LTPAKeyUtil.getPublicKey(keyPair.getPublicKey());
        
        return new RSASignatureAlgorithm(privateKey, publicKey);
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
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(data);
            byte[] signatureBytes = signature.sign();
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "RSA signature created, length: " + signatureBytes.length);
            }
            
            return signatureBytes;
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "RSA signature creation failed: " + e.getMessage());
            }
            throw new Exception("Failed to create RSA signature", e);
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
            Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(data);
            boolean valid = verifier.verify(signature);
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "RSA signature verification result: " + valid);
            }
            
            return valid;
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "RSA signature verification failed: " + e.getMessage());
            }
            throw new Exception("Failed to verify RSA signature", e);
        }
    }
    
    @Override
    public String getAlgorithmName() {
        return "RSA";
    }
    
    @Override
    public int getSignatureSize() {
        // RSA signature size equals key size
        // Typical sizes: 256 bytes (2048-bit), 384 bytes (3072-bit)
        if (publicKey != null) {
            // Estimate from public key encoding
            return publicKey.getEncoded().length;
        }
        if (privateKey != null) {
            // Estimate from private key encoding
            return privateKey.getEncoded().length / 2; // Approximate
        }
        return 256; // Default to 2048-bit
    }
    
    @Override
    public String getVersion() {
        return VERSION;
    }
    
    @Override
    public boolean isQuantumResistant() {
        return false;
    }
    
    @Override
    public boolean isHybrid() {
        return false;
    }
    
    @Override
    public String toString() {
        return "RSASignatureAlgorithm[version=" + VERSION + 
               ", algorithm=" + SIGNATURE_ALGORITHM + "]";
    }
}

// Made with Bob
