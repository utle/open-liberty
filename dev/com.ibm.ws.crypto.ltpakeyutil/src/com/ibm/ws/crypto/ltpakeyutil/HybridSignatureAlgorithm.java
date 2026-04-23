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

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Hybrid signature algorithm combining RSA and ML-DSA for LTPA version 3.0.
 * 
 * This implementation creates dual signatures:
 * 1. RSA signature (classical cryptography)
 * 2. ML-DSA signature (post-quantum cryptography)
 * 
 * Both signatures must be valid for the token to be accepted, providing:
 * - Quantum resistance from ML-DSA
 * - Backward compatibility with RSA
 * - Defense in depth (both algorithms must be broken)
 * 
 * Signature format: [RSA_SIZE(4 bytes)][RSA_SIGNATURE][ML-DSA_SIGNATURE]
 */
public class HybridSignatureAlgorithm implements LTPASignatureAlgorithm {
    
    private static final TraceComponent tc = Tr.register(HybridSignatureAlgorithm.class);
    
    private static final String VERSION = "3.0";
    private static final int SIZE_FIELD_LENGTH = 4; // 4 bytes for RSA signature size
    
    private final RSASignatureAlgorithm rsaAlgorithm;
    private final MLDSASignatureAlgorithm mldsaAlgorithm;
    
    /**
     * Create a hybrid signature algorithm instance.
     * 
     * @param rsaAlgorithm The RSA signature algorithm
     * @param mldsaAlgorithm The ML-DSA signature algorithm
     */
    public HybridSignatureAlgorithm(RSASignatureAlgorithm rsaAlgorithm, 
                                    MLDSASignatureAlgorithm mldsaAlgorithm) {
        if (rsaAlgorithm == null) {
            throw new IllegalArgumentException("RSA algorithm cannot be null");
        }
        if (mldsaAlgorithm == null) {
            throw new IllegalArgumentException("ML-DSA algorithm cannot be null");
        }
        this.rsaAlgorithm = rsaAlgorithm;
        this.mldsaAlgorithm = mldsaAlgorithm;
    }
    
    /**
     * Create a hybrid signature algorithm from an LTPAHybridKeyPair.
     * 
     * @param keyPair The hybrid key pair
     * @return Hybrid signature algorithm instance
     * @throws Exception if key conversion fails
     */
    public static HybridSignatureAlgorithm fromKeyPair(LTPAHybridKeyPair keyPair) throws Exception {
        if (keyPair == null) {
            throw new IllegalArgumentException("Key pair cannot be null");
        }
        
        RSASignatureAlgorithm rsaAlg = RSASignatureAlgorithm.fromKeyPair(keyPair.getRSAKeyPair());
        MLDSASignatureAlgorithm mldsaAlg = MLDSASignatureAlgorithm.fromKeyPair(keyPair.getMLDSAKeyPair());
        
        return new HybridSignatureAlgorithm(rsaAlg, mldsaAlg);
    }
    
    @Override
    public byte[] sign(@Sensitive byte[] data) throws Exception {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to sign cannot be null or empty");
        }
        
        try {
            // Create both signatures
            byte[] rsaSignature = rsaAlgorithm.sign(data);
            byte[] mldsaSignature = mldsaAlgorithm.sign(data);
            
            // Combine signatures: [RSA_SIZE][RSA_SIG][ML-DSA_SIG]
            ByteBuffer buffer = ByteBuffer.allocate(
                SIZE_FIELD_LENGTH + rsaSignature.length + mldsaSignature.length
            );
            
            buffer.putInt(rsaSignature.length);
            buffer.put(rsaSignature);
            buffer.put(mldsaSignature);
            
            byte[] hybridSignature = buffer.array();
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Hybrid signature created - RSA: " + rsaSignature.length + 
                        " bytes, ML-DSA: " + mldsaSignature.length + 
                        " bytes, Total: " + hybridSignature.length + " bytes");
            }
            
            return hybridSignature;
            
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Hybrid signature creation failed: " + e.getMessage());
            }
            throw new Exception("Failed to create hybrid signature", e);
        }
    }
    
    @Override
    public boolean verify(@Sensitive byte[] data, byte[] signature) throws Exception {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data to verify cannot be null or empty");
        }
        if (signature == null || signature.length < SIZE_FIELD_LENGTH) {
            throw new IllegalArgumentException("Invalid hybrid signature format");
        }
        
        try {
            // Parse hybrid signature
            ByteBuffer buffer = ByteBuffer.wrap(signature);
            
            // Read RSA signature size
            int rsaSize = buffer.getInt();
            if (rsaSize <= 0 || rsaSize > signature.length - SIZE_FIELD_LENGTH) {
                throw new IllegalArgumentException("Invalid RSA signature size in hybrid signature");
            }
            
            // Extract RSA signature
            byte[] rsaSignature = new byte[rsaSize];
            buffer.get(rsaSignature);
            
            // Extract ML-DSA signature (remaining bytes)
            int mldsaSize = signature.length - SIZE_FIELD_LENGTH - rsaSize;
            if (mldsaSize <= 0) {
                throw new IllegalArgumentException("Invalid ML-DSA signature size in hybrid signature");
            }
            byte[] mldsaSignature = new byte[mldsaSize];
            buffer.get(mldsaSignature);
            
            // Verify both signatures - BOTH must be valid
            boolean rsaValid = rsaAlgorithm.verify(data, rsaSignature);
            boolean mldsaValid = mldsaAlgorithm.verify(data, mldsaSignature);
            
            boolean valid = rsaValid && mldsaValid;
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Hybrid signature verification - RSA: " + rsaValid + 
                        ", ML-DSA: " + mldsaValid + ", Overall: " + valid);
            }
            
            return valid;
            
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Hybrid signature verification failed: " + e.getMessage());
            }
            throw new Exception("Failed to verify hybrid signature", e);
        }
    }
    
    @Override
    public String getAlgorithmName() {
        return "Hybrid-" + rsaAlgorithm.getAlgorithmName() + "+" + mldsaAlgorithm.getAlgorithmName();
    }
    
    @Override
    public int getSignatureSize() {
        // Total size: size field + RSA signature + ML-DSA signature
        return SIZE_FIELD_LENGTH + rsaAlgorithm.getSignatureSize() + mldsaAlgorithm.getSignatureSize();
    }
    
    @Override
    public String getVersion() {
        return VERSION;
    }
    
    @Override
    public boolean isQuantumResistant() {
        // Hybrid is quantum resistant because ML-DSA component is quantum resistant
        return true;
    }
    
    @Override
    public boolean isHybrid() {
        return true;
    }
    
    /**
     * Get the RSA signature algorithm component.
     * 
     * @return RSA signature algorithm
     */
    public RSASignatureAlgorithm getRSAAlgorithm() {
        return rsaAlgorithm;
    }
    
    /**
     * Get the ML-DSA signature algorithm component.
     * 
     * @return ML-DSA signature algorithm
     */
    public MLDSASignatureAlgorithm getMLDSAAlgorithm() {
        return mldsaAlgorithm;
    }
    
    @Override
    public String toString() {
        return "HybridSignatureAlgorithm[version=" + VERSION + 
               ", algorithm=" + getAlgorithmName() + 
               ", totalSize=" + getSignatureSize() + " bytes]";
    }
}

// Made with Bob
