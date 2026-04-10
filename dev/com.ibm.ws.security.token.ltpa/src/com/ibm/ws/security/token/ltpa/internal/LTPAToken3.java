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

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.websphere.security.auth.InvalidTokenException;
import com.ibm.websphere.security.auth.TokenExpiredException;
import com.ibm.ws.common.encoder.Base64Coder;
import com.ibm.ws.crypto.ltpakeyutil.LTPAKeyUtil;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPQCCrypto;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPublicKey;
import com.ibm.ws.crypto.ltpakeyutil.MLDSAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.MLDSAPublicKey;
import com.ibm.ws.ffdc.annotation.FFDCIgnore;
import com.ibm.wsspi.security.ltpa.Token;
import com.ibm.wsspi.security.token.AttributeNameConstants;

/**
 * Represents an LTPA Token version 3 with Post-Quantum Cryptography support.
 * 
 * This token supports three signature algorithms:
 * - RSA: Classical RSA signatures (backward compatible)
 * - ML-DSA: Post-quantum ML-DSA (Dilithium) signatures
 * - HYBRID: Both RSA and ML-DSA signatures for defense-in-depth
 * 
 * The token uses AES-256-GCM for encryption (quantum-resistant symmetric encryption).
 */
public class LTPAToken3 implements Token, Serializable {
    
    private static final TraceComponent tc = Tr.register(LTPAToken3.class);
    
    private static final long serialVersionUID = 3L;
    private static final String DELIM = "%";
    private static final String VERSION_PREFIX = "v3:";
    
    private final short version = 3;
    private byte[] signature;
    private byte[] encryptedBytes = null;
    private UserData userData;
    private long expirationInMilliseconds;
    
    // Keys
    @Sensitive
    private final byte[] sharedKey; // AES-256 key
    private final LTPAPrivateKey rsaPrivateKey;
    private final LTPAPublicKey rsaPublicKey;
    private final MLDSAPrivateKey pqcPrivateKey;
    private final MLDSAPublicKey pqcPublicKey;
    
    // Algorithm configuration
    private final SignatureAlgorithm signatureAlgorithm;
    private long expirationDifferenceAllowed;
    
    /**
     * Constructor for validating an existing LTPAToken3
     * 
     * @param tokenBytes The byte representation of the LTPA3 token
     * @param sharedKey The LTPA shared key (AES-256)
     * @param rsaPrivateKey The RSA private key (can be null if not using RSA)
     * @param rsaPublicKey The RSA public key (can be null if not using RSA)
     * @param pqcPrivateKey The ML-DSA private key (can be null if not using PQC)
     * @param pqcPublicKey The ML-DSA public key (can be null if not using PQC)
     * @param expDiffAllowed Expiration difference allowed in milliseconds
     * @throws InvalidTokenException if token is invalid
     */
    public LTPAToken3(byte[] tokenBytes, @Sensitive byte[] sharedKey,
                      LTPAPrivateKey rsaPrivateKey, LTPAPublicKey rsaPublicKey,
                      MLDSAPrivateKey pqcPrivateKey, MLDSAPublicKey pqcPublicKey,
                      long expDiffAllowed) throws InvalidTokenException {
        checkTokenBytes(tokenBytes);
        
        this.signature = null;
        this.encryptedBytes = tokenBytes.clone();
        this.sharedKey = (sharedKey != null) ? sharedKey.clone() : null;
        this.rsaPrivateKey = rsaPrivateKey;
        this.rsaPublicKey = rsaPublicKey;
        this.pqcPrivateKey = pqcPrivateKey;
        this.pqcPublicKey = pqcPublicKey;
        this.expirationInMilliseconds = 0;
        this.expirationDifferenceAllowed = expDiffAllowed;
        
        // Decrypt and determine algorithm
        decrypt();
        
        // Determine signature algorithm from the token
        this.signatureAlgorithm = determineSignatureAlgorithm();
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "LTPAToken3 created for validation, algorithm: " + signatureAlgorithm);
        }
    }
    
    /**
     * Constructor for creating a new LTPAToken3
     * 
     * @param accessID The unique user identifier
     * @param expirationInMinutes Expiration limit of the LTPA3 token in minutes
     * @param sharedKey The LTPA shared key (AES-256)
     * @param rsaPrivateKey The RSA private key (can be null if not using RSA)
     * @param rsaPublicKey The RSA public key (can be null if not using RSA)
     * @param pqcPrivateKey The ML-DSA private key (can be null if not using PQC)
     * @param pqcPublicKey The ML-DSA public key (can be null if not using PQC)
     * @param algorithm The signature algorithm to use
     */
    protected LTPAToken3(String accessID, long expirationInMinutes, @Sensitive byte[] sharedKey,
                         LTPAPrivateKey rsaPrivateKey, LTPAPublicKey rsaPublicKey,
                         MLDSAPrivateKey pqcPrivateKey, MLDSAPublicKey pqcPublicKey,
                         SignatureAlgorithm algorithm) {
        this.signature = null;
        this.encryptedBytes = null;
        this.sharedKey = (sharedKey != null) ? sharedKey.clone() : null;
        this.rsaPrivateKey = rsaPrivateKey;
        this.rsaPublicKey = rsaPublicKey;
        this.pqcPrivateKey = pqcPrivateKey;
        this.pqcPublicKey = pqcPublicKey;
        this.userData = new UserData(accessID);
        this.signatureAlgorithm = (algorithm != null) ? algorithm : SignatureAlgorithm.getDefault();
        setExpiration(expirationInMinutes);
        
        // Validate key availability for chosen algorithm
        validateKeysForAlgorithm();
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "LTPAToken3 created for user: " + accessID + ", algorithm: " + this.signatureAlgorithm);
        }
    }
    
    /**
     * Validate that required keys are available for the chosen algorithm
     */
    private void validateKeysForAlgorithm() {
        if (signatureAlgorithm.requiresRSAKeys() && (rsaPrivateKey == null || rsaPublicKey == null)) {
            throw new IllegalArgumentException("RSA keys required for algorithm: " + signatureAlgorithm);
        }
        if (signatureAlgorithm.requiresPQCKeys() && (pqcPrivateKey == null || pqcPublicKey == null)) {
            throw new IllegalArgumentException("PQC keys required for algorithm: " + signatureAlgorithm);
        }
    }
    
    /**
     * Check if token bytes are valid
     */
    private void checkTokenBytes(byte[] tokenBytes) throws InvalidTokenException {
        if (tokenBytes == null || tokenBytes.length == 0) {
            throw new InvalidTokenException("Token bytes cannot be null or empty");
        }
    }
    
    /**
     * Encrypt the token
     */
    @FFDCIgnore(Exception.class)
    private final void encrypt() throws Exception {
        String signStr = Base64Coder.toString(Base64Coder.base64Encode(signature));
        String ud = userData.toString();
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
            Tr.event(this, tc, "encrypt: userData" + ud);
        }
        
        byte[] accessID = Base64Coder.getBytes(ud);
        
        // Format: userData % expiration % signature % algorithm
        StringBuilder sb = new StringBuilder(DELIM);
        sb.append(getExpiration()).append(DELIM)
          .append(signStr).append(DELIM)
          .append(signatureAlgorithm.name());
        
        byte[] timeSignAlg = sb.toString().getBytes(StandardCharsets.UTF_8);
        byte[] toBeEnc = new byte[accessID.length + timeSignAlg.length];
        
        System.arraycopy(accessID, 0, toBeEnc, 0, accessID.length);
        System.arraycopy(timeSignAlg, 0, toBeEnc, accessID.length, timeSignAlg.length);
        
        try {
            // Use AES-256-GCM for encryption
            encryptedBytes = LTPAPQCCrypto.encryptAES256GCM(toBeEnc, sharedKey);
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Error encrypting; " + e);
            }
            throw e;
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
            Tr.event(this, tc, "Encrypted bytes are: " + (encryptedBytes == null ? "" : Base64Coder.toString(Base64Coder.base64Encode(encryptedBytes))));
        }
    }
    
    /**
     * Decrypt the encrypted token bytes
     */
    @FFDCIgnore(Exception.class)
    private final void decrypt() throws InvalidTokenException {
        byte[] tokenData;
        try {
            // Use AES-256-GCM for decryption
            tokenData = LTPAPQCCrypto.decryptAES256GCM(encryptedBytes.clone(), sharedKey);
            
            checkTokenBytes(tokenData);
            String tokenString = new String(tokenData, StandardCharsets.UTF_8);
            String[] fields = LTPATokenizer.parseToken(tokenString);
            
            // Parse user data
            Map<String, ArrayList<String>> attribs = LTPATokenizer.parseUserData(fields[0]);
            userData = new UserData(attribs);
            
            // Parse expiration
            String[] expirationArray = userData.getAttributes(AttributeNameConstants.WSTOKEN_EXPIRATION);
            if (expirationArray != null && expirationArray[expirationArray.length - 1] != null) {
                expirationInMilliseconds = Long.parseLong(expirationArray[expirationArray.length - 1]);
                
                // Validate expiration consistency if present in both locations
                if (fields.length >= 4 && expirationDifferenceAllowed >= 0) {
                    long fieldExpiration = Long.parseLong(fields[1]);
                    if (Math.abs(expirationInMilliseconds - fieldExpiration) > expirationDifferenceAllowed) {
                        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                            Tr.debug(this, tc, "Token validation failed due to expiration mismatch");
                        }
                        throw new InvalidTokenException("Token Validation Failed - expiration mismatch");
                    }
                }
            } else if (fields.length >= 2) {
                expirationInMilliseconds = Long.parseLong(fields[1]);
            }
            
            // Parse signature (always second-to-last or last field)
            int signatureIndex = (fields.length >= 4) ? 2 : fields.length - 1;
            byte[] sig = Base64Coder.base64Decode(Base64Coder.getBytes(fields[signatureIndex]));
            setSignature(sig);
            
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEventEnabled()) {
                Tr.event(this, tc, "Error decrypting; " + e);
            }
            throw new InvalidTokenException(e.getMessage(), e);
        }
    }
    
    /**
     * Determine the signature algorithm from the decrypted token
     */
    private SignatureAlgorithm determineSignatureAlgorithm() {
        // Try to extract algorithm from token data
        // If not present, infer from signature size and available keys
        
        if (signature == null) {
            return SignatureAlgorithm.RSA; // Default
        }
        
        int sigLength = signature.length;
        
        // Check if it's a hybrid signature (has length prefix)
        if (sigLength > 4) {
            int rsaLength = ((signature[0] & 0xFF) << 24) |
                           ((signature[1] & 0xFF) << 16) |
                           ((signature[2] & 0xFF) << 8) |
                           (signature[3] & 0xFF);
            
            if (rsaLength > 0 && rsaLength < sigLength - 4) {
                return SignatureAlgorithm.HYBRID;
            }
        }
        
        // Check if it's an ML-DSA signature (typical sizes: 2420, 3309, 4627)
        if (sigLength > 2000 && pqcPublicKey != null) {
            return SignatureAlgorithm.ML_DSA;
        }
        
        // Default to RSA
        return SignatureAlgorithm.RSA;
    }
    
    /**
     * Sign the token based on the configured algorithm
     */
    @FFDCIgnore(Exception.class)
    private final void sign() throws Exception {
        String dataStr = this.getUserData().toString();
        byte[] data = Base64Coder.getBytes(dataStr);
        
        byte[] sig;
        switch (signatureAlgorithm) {
            case RSA:
                sig = signRSA(data);
                break;
            case ML_DSA:
                sig = signMLDSA(data);
                break;
            case HYBRID:
                sig = signHybrid(data);
                break;
            default:
                throw new IllegalStateException("Unknown signature algorithm: " + signatureAlgorithm);
        }
        
        this.setSignature(sig);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Token signed with " + signatureAlgorithm + ", signature size: " + sig.length);
        }
    }
    
    /**
     * Sign with RSA
     */
    private byte[] signRSA(byte[] data) throws Exception {
        byte[][] rsaPrivKey = LTPAKeyUtil.getRawKey(rsaPrivateKey);
        LTPAKeyUtil.setRSAKey(rsaPrivKey);
        return LTPAKeyUtil.signISO9796(rsaPrivKey, data, 0, data.length);
    }
    
    /**
     * Sign with ML-DSA
     */
    private byte[] signMLDSA(byte[] data) throws Exception {
        return LTPAPQCCrypto.signMLDSA(data, pqcPrivateKey);
    }
    
    /**
     * Sign with hybrid (RSA + ML-DSA)
     */
    private byte[] signHybrid(byte[] data) throws Exception {
        return LTPAPQCCrypto.signHybrid(data, rsaPrivateKey, pqcPrivateKey);
    }
    
    /**
     * Verify the token signature
     */
    @FFDCIgnore(Exception.class)
    private final boolean verify() throws Exception {
        String dataStr = this.getUserData().toString();
        byte[] data = Base64Coder.getBytes(dataStr);
        
        boolean valid;
        switch (signatureAlgorithm) {
            case RSA:
                valid = verifyRSA(data, signature);
                break;
            case ML_DSA:
                valid = verifyMLDSA(data, signature);
                break;
            case HYBRID:
                valid = verifyHybrid(data, signature);
                break;
            default:
                throw new IllegalStateException("Unknown signature algorithm: " + signatureAlgorithm);
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Token verification with " + signatureAlgorithm + ": " + (valid ? "VALID" : "INVALID"));
        }
        
        return valid;
    }
    
    /**
     * Verify RSA signature
     */
    private boolean verifyRSA(byte[] data, byte[] sig) throws Exception {
        byte[][] rsaPubKey = LTPAKeyUtil.getRawKey(rsaPublicKey);
        return LTPAKeyUtil.verifyISO9796(rsaPubKey, data, 0, data.length, sig, 0, sig.length);
    }
    
    /**
     * Verify ML-DSA signature
     */
    private boolean verifyMLDSA(byte[] data, byte[] sig) throws Exception {
        return LTPAPQCCrypto.verifyMLDSA(data, sig, pqcPublicKey);
    }
    
    /**
     * Verify hybrid signature
     */
    private boolean verifyHybrid(byte[] data, byte[] sig) throws Exception {
        return LTPAPQCCrypto.verifyHybrid(data, sig, rsaPublicKey, pqcPublicKey);
    }
    
    /** {@inheritDoc} */
    @Override
    @FFDCIgnore(Exception.class)
    public final boolean isValid() throws InvalidTokenException, TokenExpiredException {
        boolean verified = false;
        
        validateExpiration();
        
        try {
            verified = verify();
        } catch (Exception e) {
            verified = false;
            throw new InvalidTokenException(e.getMessage(), e);
        }
        
        if (!verified) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(this, tc, "Invalid signature of the token " + this);
            }
            throw new InvalidTokenException("Token Validation Failed");
        }
        
        return verified;
    }
    
    /**
     * Validate token expiration
     */
    public final void validateExpiration() throws TokenExpiredException {
        Date d = new Date();
        Date expD = new Date(getExpiration());
        boolean expired = d.after(expD);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(this, tc, "Current time = " + d + ", expiration time = " + expD);
        }
        
        if (expired) {
            String msg = "The token has expired: current time = \"" + d + "\", expire time = \"" + expD + "\"";
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(this, tc, msg);
            }
            throw new TokenExpiredException(expirationInMilliseconds, msg);
        }
    }
    
    /** {@inheritDoc} */
    @Override
    @FFDCIgnore(Exception.class)
    public final byte[] getBytes() throws InvalidTokenException, TokenExpiredException {
        if (encryptedBytes == null) {
            try {
                sign();
                encrypt();
            } catch (Exception e) {
                throw new InvalidTokenException(e.getMessage(), e);
            }
        }
        return encryptedBytes.clone();
    }
    
    /**
     * Get the token bytes with version prefix
     */
    public final byte[] getBytesWithPrefix() throws InvalidTokenException, TokenExpiredException {
        byte[] tokenBytes = getBytes();
        byte[] prefix = VERSION_PREFIX.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[prefix.length + tokenBytes.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(tokenBytes, 0, result, prefix.length, tokenBytes.length);
        return result;
    }
    
    /** {@inheritDoc} */
    @Override
    public final long getExpiration() {
        return expirationInMilliseconds;
    }
    
    /** {@inheritDoc} */
    @Override
    public final short getVersion() {
        return version;
    }
    
    /**
     * Get the signature algorithm
     */
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
    
    /** {@inheritDoc} */
    @Override
    public final String[] addAttribute(String name, String value) {
        signature = null;
        encryptedBytes = null;
        return userData.addAttribute(name, value);
    }
    
    /** {@inheritDoc} */
    @Override
    public final String[] getAttributes(String name) {
        return userData.getAttributes(name);
    }
    
    /** {@inheritDoc} */
    @Override
    public final Enumeration<String> getAttributeNames() {
        return userData.getAttributeNames();
    }
    
    /**
     * Get user data
     */
    protected UserData getUserData() {
        return userData;
    }
    
    /**
     * Set signature
     */
    protected void setSignature(byte[] sig) {
        this.signature = (sig != null) ? sig.clone() : null;
    }
    
    /**
     * Set expiration
     */
    protected void setExpiration(long expirationInMinutes) {
        long currentTime = System.currentTimeMillis();
        this.expirationInMilliseconds = currentTime + (expirationInMinutes * 60 * 1000);
    }
    
    @Override
    public String toString() {
        return "LTPAToken3[version=" + version + 
               ", algorithm=" + signatureAlgorithm +
               ", expiration=" + new Date(expirationInMilliseconds) +
               ", quantumResistant=" + signatureAlgorithm.isQuantumResistant() + "]";
    }
}

// Made with Bob
