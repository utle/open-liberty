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

import java.nio.charset.StandardCharsets;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.websphere.security.auth.InvalidTokenException;
import com.ibm.websphere.security.auth.TokenExpiredException;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPublicKey;
import com.ibm.ws.crypto.ltpakeyutil.MLDSAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.MLDSAPublicKey;
import com.ibm.wsspi.security.ltpa.Token;

/**
 * Factory for creating and validating LTPA tokens with version detection.
 * Handles routing between LTPAToken2 (RSA-only) and LTPAToken3 (PQC-enabled).
 */
public class LTPAToken3Factory {
    
    private static final TraceComponent tc = Tr.register(LTPAToken3Factory.java);
    
    private static final String VERSION_PREFIX_V3 = "v3:";
    private static final String VERSION_PREFIX_V2 = "v2:";
    
    /**
     * Create a new LTPA token with the specified algorithm
     * 
     * @param accessID User identifier
     * @param expirationInMinutes Token expiration in minutes
     * @param sharedKey Shared encryption key
     * @param rsaPrivateKey RSA private key (required for RSA and HYBRID)
     * @param rsaPublicKey RSA public key (required for RSA and HYBRID)
     * @param pqcPrivateKey ML-DSA private key (required for ML_DSA and HYBRID)
     * @param pqcPublicKey ML-DSA public key (required for ML_DSA and HYBRID)
     * @param algorithm Signature algorithm to use
     * @return New LTPA token
     */
    public static Token createToken(String accessID, long expirationInMinutes,
                                    @Sensitive byte[] sharedKey,
                                    LTPAPrivateKey rsaPrivateKey, LTPAPublicKey rsaPublicKey,
                                    MLDSAPrivateKey pqcPrivateKey, MLDSAPublicKey pqcPublicKey,
                                    SignatureAlgorithm algorithm) {
        
        if (algorithm == null) {
            algorithm = SignatureAlgorithm.getDefault();
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Creating token with algorithm: " + algorithm);
        }
        
        // Use LTPAToken3 for PQC algorithms, LTPAToken2 for RSA-only
        if (algorithm == SignatureAlgorithm.RSA && pqcPrivateKey == null && pqcPublicKey == null) {
            // Create LTPAToken2 for backward compatibility
            return new LTPAToken2(accessID, expirationInMinutes, sharedKey, rsaPrivateKey, rsaPublicKey);
        } else {
            // Create LTPAToken3 for PQC support
            return new LTPAToken3(accessID, expirationInMinutes, sharedKey,
                                 rsaPrivateKey, rsaPublicKey,
                                 pqcPrivateKey, pqcPublicKey,
                                 algorithm);
        }
    }
    
    /**
     * Validate an existing LTPA token with automatic version detection
     * 
     * @param tokenBytes Token bytes (may include version prefix)
     * @param sharedKey Shared encryption key
     * @param rsaPrivateKey RSA private key
     * @param rsaPublicKey RSA public key
     * @param pqcPrivateKey ML-DSA private key (can be null for v2 tokens)
     * @param pqcPublicKey ML-DSA public key (can be null for v2 tokens)
     * @param expDiffAllowed Expiration difference allowed
     * @return Validated token
     * @throws InvalidTokenException if token is invalid
     * @throws TokenExpiredException if token has expired
     */
    public static Token validateToken(byte[] tokenBytes, @Sensitive byte[] sharedKey,
                                     LTPAPrivateKey rsaPrivateKey, LTPAPublicKey rsaPublicKey,
                                     MLDSAPrivateKey pqcPrivateKey, MLDSAPublicKey pqcPublicKey,
                                     long expDiffAllowed) 
            throws InvalidTokenException, TokenExpiredException {
        
        if (tokenBytes == null || tokenBytes.length == 0) {
            throw new InvalidTokenException("Token bytes cannot be null or empty");
        }
        
        // Detect version from prefix
        TokenVersion version = detectVersion(tokenBytes);
        byte[] actualTokenBytes = stripVersionPrefix(tokenBytes, version);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Validating token version: " + version);
        }
        
        Token token;
        switch (version) {
            case V3:
                token = new LTPAToken3(actualTokenBytes, sharedKey,
                                      rsaPrivateKey, rsaPublicKey,
                                      pqcPrivateKey, pqcPublicKey,
                                      expDiffAllowed);
                break;
                
            case V2:
            case LEGACY:
            default:
                token = new LTPAToken2(actualTokenBytes, sharedKey,
                                      rsaPrivateKey, rsaPublicKey,
                                      expDiffAllowed);
                break;
        }
        
        // Validate the token
        token.isValid();
        
        return token;
    }
    
    /**
     * Detect token version from bytes
     * 
     * @param tokenBytes Token bytes
     * @return Detected version
     */
    public static TokenVersion detectVersion(byte[] tokenBytes) {
        if (tokenBytes == null || tokenBytes.length < 3) {
            return TokenVersion.LEGACY;
        }
        
        // Check for v3: prefix
        if (tokenBytes.length >= VERSION_PREFIX_V3.length()) {
            String prefix = new String(tokenBytes, 0, VERSION_PREFIX_V3.length(), StandardCharsets.UTF_8);
            if (VERSION_PREFIX_V3.equals(prefix)) {
                return TokenVersion.V3;
            }
        }
        
        // Check for v2: prefix
        if (tokenBytes.length >= VERSION_PREFIX_V2.length()) {
            String prefix = new String(tokenBytes, 0, VERSION_PREFIX_V2.length(), StandardCharsets.UTF_8);
            if (VERSION_PREFIX_V2.equals(prefix)) {
                return TokenVersion.V2;
            }
        }
        
        // No prefix = legacy v2 token
        return TokenVersion.LEGACY;
    }
    
    /**
     * Strip version prefix from token bytes
     * 
     * @param tokenBytes Token bytes with possible prefix
     * @param version Detected version
     * @return Token bytes without prefix
     */
    private static byte[] stripVersionPrefix(byte[] tokenBytes, TokenVersion version) {
        int prefixLength = 0;
        
        switch (version) {
            case V3:
                prefixLength = VERSION_PREFIX_V3.length();
                break;
            case V2:
                prefixLength = VERSION_PREFIX_V2.length();
                break;
            case LEGACY:
            default:
                prefixLength = 0;
                break;
        }
        
        if (prefixLength == 0) {
            return tokenBytes;
        }
        
        byte[] result = new byte[tokenBytes.length - prefixLength];
        System.arraycopy(tokenBytes, prefixLength, result, 0, result.length);
        return result;
    }
    
    /**
     * Check if PQC is required for the given token bytes
     * 
     * @param tokenBytes Token bytes
     * @return true if PQC keys are required
     */
    public static boolean requiresPQC(byte[] tokenBytes) {
        TokenVersion version = detectVersion(tokenBytes);
        return version == TokenVersion.V3;
    }
    
    /**
     * Get the recommended algorithm based on available keys
     * 
     * @param hasRSAKeys Whether RSA keys are available
     * @param hasPQCKeys Whether PQC keys are available
     * @return Recommended algorithm
     */
    public static SignatureAlgorithm getRecommendedAlgorithm(boolean hasRSAKeys, boolean hasPQCKeys) {
        if (hasRSAKeys && hasPQCKeys) {
            return SignatureAlgorithm.HYBRID; // Best security
        } else if (hasPQCKeys) {
            return SignatureAlgorithm.ML_DSA; // PQC only
        } else if (hasRSAKeys) {
            return SignatureAlgorithm.RSA; // Legacy
        } else {
            throw new IllegalStateException("No keys available");
        }
    }
    
    /**
     * Convert a token to a different version/algorithm
     * 
     * @param sourceToken Source token
     * @param targetAlgorithm Target algorithm
     * @param sharedKey Shared encryption key
     * @param rsaPrivateKey RSA private key
     * @param rsaPublicKey RSA public key
     * @param pqcPrivateKey ML-DSA private key
     * @param pqcPublicKey ML-DSA public key
     * @return Converted token
     * @throws Exception if conversion fails
     */
    public static Token convertToken(Token sourceToken, SignatureAlgorithm targetAlgorithm,
                                    @Sensitive byte[] sharedKey,
                                    LTPAPrivateKey rsaPrivateKey, LTPAPublicKey rsaPublicKey,
                                    MLDSAPrivateKey pqcPrivateKey, MLDSAPublicKey pqcPublicKey)
            throws Exception {
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Converting token to algorithm: " + targetAlgorithm);
        }
        
        // Extract user data and expiration from source token
        String accessID = null;
        java.util.Enumeration<String> attrNames = sourceToken.getAttributeNames();
        if (attrNames.hasMoreElements()) {
            String firstAttr = attrNames.nextElement();
            String[] values = sourceToken.getAttributes(firstAttr);
            if (values != null && values.length > 0) {
                accessID = values[0];
            }
        }
        
        if (accessID == null) {
            throw new IllegalArgumentException("Cannot extract access ID from source token");
        }
        
        // Calculate remaining expiration time
        long currentTime = System.currentTimeMillis();
        long expiration = sourceToken.getExpiration();
        long remainingMinutes = (expiration - currentTime) / (60 * 1000);
        
        if (remainingMinutes <= 0) {
            throw new TokenExpiredException(expiration, "Source token has expired");
        }
        
        // Create new token with target algorithm
        Token newToken = createToken(accessID, remainingMinutes, sharedKey,
                                    rsaPrivateKey, rsaPublicKey,
                                    pqcPrivateKey, pqcPublicKey,
                                    targetAlgorithm);
        
        // Copy all attributes
        attrNames = sourceToken.getAttributeNames();
        while (attrNames.hasMoreElements()) {
            String attrName = attrNames.nextElement();
            String[] values = sourceToken.getAttributes(attrName);
            if (values != null) {
                for (String value : values) {
                    newToken.addAttribute(attrName, value);
                }
            }
        }
        
        return newToken;
    }
    
    /**
     * Token version enumeration
     */
    public enum TokenVersion {
        /** Legacy LTPAToken2 without version prefix */
        LEGACY,
        /** LTPAToken2 with v2: prefix */
        V2,
        /** LTPAToken3 with v3: prefix (PQC-enabled) */
        V3
    }
}

// Made with Bob
