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

import java.util.Map;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;

/**
 * Configuration class for Post-Quantum Cryptography settings in LTPA.
 * Manages PQC-specific configuration options including algorithm selection,
 * security levels, and migration settings.
 */
public class LTPAPQCConfiguration {
    
    private static final TraceComponent tc = Tr.register(LTPAPQCConfiguration.class, TraceConstants.TRACE_GROUP, TraceConstants.MESSAGE_BUNDLE);
    
    // Configuration property keys
    public static final String KEY_ENABLE_PQC = "enablePQC";
    public static final String KEY_SIGNATURE_ALGORITHM = "signatureAlgorithm";
    public static final String KEY_PQC_SECURITY_LEVEL = "pqcSecurityLevel";
    public static final String KEY_ALLOW_LEGACY_TOKENS = "allowLegacyTokens";
    public static final String KEY_HYBRID_MODE = "hybridMode";
    public static final String KEY_KEY_ROTATION_INTERVAL = "keyRotationInterval";
    public static final String KEY_FORCE_PQC_VALIDATION = "forcePQCValidation";
    
    // Default values
    private static final boolean DEFAULT_ENABLE_PQC = false;
    private static final SignatureAlgorithm DEFAULT_SIGNATURE_ALGORITHM = SignatureAlgorithm.RSA;
    private static final int DEFAULT_PQC_SECURITY_LEVEL = 3; // NIST Level 3 (ML-DSA-65)
    private static final boolean DEFAULT_ALLOW_LEGACY_TOKENS = true;
    private static final boolean DEFAULT_HYBRID_MODE = true;
    private static final long DEFAULT_KEY_ROTATION_INTERVAL = 90 * 24 * 60 * 60 * 1000L; // 90 days
    private static final boolean DEFAULT_FORCE_PQC_VALIDATION = false;
    
    // Configuration values
    private final boolean enablePQC;
    private final SignatureAlgorithm signatureAlgorithm;
    private final int pqcSecurityLevel;
    private final boolean allowLegacyTokens;
    private final boolean hybridMode;
    private final long keyRotationInterval;
    private final boolean forcePQCValidation;
    
    /**
     * Constructor with configuration map
     * 
     * @param config Configuration map from server.xml
     */
    public LTPAPQCConfiguration(Map<String, Object> config) {
        if (config == null) {
            // Use all defaults
            this.enablePQC = DEFAULT_ENABLE_PQC;
            this.signatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;
            this.pqcSecurityLevel = DEFAULT_PQC_SECURITY_LEVEL;
            this.allowLegacyTokens = DEFAULT_ALLOW_LEGACY_TOKENS;
            this.hybridMode = DEFAULT_HYBRID_MODE;
            this.keyRotationInterval = DEFAULT_KEY_ROTATION_INTERVAL;
            this.forcePQCValidation = DEFAULT_FORCE_PQC_VALIDATION;
        } else {
            // Parse configuration
            this.enablePQC = parseBoolean(config, KEY_ENABLE_PQC, DEFAULT_ENABLE_PQC);
            this.signatureAlgorithm = parseSignatureAlgorithm(config, KEY_SIGNATURE_ALGORITHM, DEFAULT_SIGNATURE_ALGORITHM);
            this.pqcSecurityLevel = parseInt(config, KEY_PQC_SECURITY_LEVEL, DEFAULT_PQC_SECURITY_LEVEL);
            this.allowLegacyTokens = parseBoolean(config, KEY_ALLOW_LEGACY_TOKENS, DEFAULT_ALLOW_LEGACY_TOKENS);
            this.hybridMode = parseBoolean(config, KEY_HYBRID_MODE, DEFAULT_HYBRID_MODE);
            this.keyRotationInterval = parseDuration(config, KEY_KEY_ROTATION_INTERVAL, DEFAULT_KEY_ROTATION_INTERVAL);
            this.forcePQCValidation = parseBoolean(config, KEY_FORCE_PQC_VALIDATION, DEFAULT_FORCE_PQC_VALIDATION);
        }
        
        // Validate configuration
        validateConfiguration();
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "LTPAPQCConfiguration created: " + this);
        }
    }
    
    /**
     * Default constructor (all defaults)
     */
    public LTPAPQCConfiguration() {
        this(null);
    }
    
    /**
     * Validate the configuration
     */
    private void validateConfiguration() {
        // Validate security level
        if (pqcSecurityLevel != 2 && pqcSecurityLevel != 3 && pqcSecurityLevel != 5) {
            throw new IllegalArgumentException("Invalid PQC security level: " + pqcSecurityLevel + 
                                             ". Must be 2, 3, or 5.");
        }
        
        // If PQC is enabled, signature algorithm should not be RSA-only
        if (enablePQC && signatureAlgorithm == SignatureAlgorithm.RSA) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isWarningEnabled()) {
                Tr.warning(tc, "PQC is enabled but signature algorithm is RSA. " +
                              "Consider using ML_DSA or HYBRID for quantum resistance.");
            }
        }
        
        // If hybrid mode is enabled, signature algorithm should be HYBRID
        if (hybridMode && signatureAlgorithm != SignatureAlgorithm.HYBRID) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Hybrid mode is enabled but signature algorithm is " + signatureAlgorithm);
            }
        }
        
        // Validate key rotation interval
        if (keyRotationInterval < 0) {
            throw new IllegalArgumentException("Key rotation interval cannot be negative");
        }
    }
    
    /**
     * Parse boolean from config
     */
    private boolean parseBoolean(Map<String, Object> config, String key, boolean defaultValue) {
        Object value = config.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value instanceof String) {
            return Boolean.parseBoolean((String) value);
        }
        return defaultValue;
    }
    
    /**
     * Parse integer from config
     */
    private int parseInt(Map<String, Object> config, String key, int defaultValue) {
        Object value = config.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Integer) {
            return (Integer) value;
        }
        if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isWarningEnabled()) {
                    Tr.warning(tc, "Invalid integer value for " + key + ": " + value);
                }
                return defaultValue;
            }
        }
        return defaultValue;
    }
    
    /**
     * Parse signature algorithm from config
     */
    private SignatureAlgorithm parseSignatureAlgorithm(Map<String, Object> config, String key, SignatureAlgorithm defaultValue) {
        Object value = config.get(key);
        if (value == null) {
            return defaultValue;
        }
        
        String algStr = value.toString();
        SignatureAlgorithm alg = SignatureAlgorithm.fromString(algStr);
        
        if (alg == null) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isWarningEnabled()) {
                Tr.warning(tc, "Invalid signature algorithm: " + algStr + ". Using default: " + defaultValue);
            }
            return defaultValue;
        }
        
        return alg;
    }
    
    /**
     * Parse duration from config (supports days, hours, minutes, seconds)
     */
    private long parseDuration(Map<String, Object> config, String key, long defaultValue) {
        Object value = config.get(key);
        if (value == null) {
            return defaultValue;
        }
        
        if (value instanceof Long) {
            return (Long) value;
        }
        
        if (value instanceof String) {
            String durationStr = ((String) value).trim().toLowerCase();
            try {
                // Parse duration string like "90d", "24h", "60m", "3600s"
                if (durationStr.endsWith("d")) {
                    long days = Long.parseLong(durationStr.substring(0, durationStr.length() - 1));
                    return days * 24 * 60 * 60 * 1000L;
                } else if (durationStr.endsWith("h")) {
                    long hours = Long.parseLong(durationStr.substring(0, durationStr.length() - 1));
                    return hours * 60 * 60 * 1000L;
                } else if (durationStr.endsWith("m")) {
                    long minutes = Long.parseLong(durationStr.substring(0, durationStr.length() - 1));
                    return minutes * 60 * 1000L;
                } else if (durationStr.endsWith("s")) {
                    long seconds = Long.parseLong(durationStr.substring(0, durationStr.length() - 1));
                    return seconds * 1000L;
                } else {
                    // Assume milliseconds
                    return Long.parseLong(durationStr);
                }
            } catch (NumberFormatException e) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isWarningEnabled()) {
                    Tr.warning(tc, "Invalid duration value for " + key + ": " + value);
                }
                return defaultValue;
            }
        }
        
        return defaultValue;
    }
    
    // Getters
    
    public boolean isEnablePQC() {
        return enablePQC;
    }
    
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
    
    public int getPqcSecurityLevel() {
        return pqcSecurityLevel;
    }
    
    public boolean isAllowLegacyTokens() {
        return allowLegacyTokens;
    }
    
    public boolean isHybridMode() {
        return hybridMode;
    }
    
    public long getKeyRotationInterval() {
        return keyRotationInterval;
    }
    
    public boolean isForcePQCValidation() {
        return forcePQCValidation;
    }
    
    /**
     * Check if PQC keys are required based on configuration
     */
    public boolean requiresPQCKeys() {
        return enablePQC && signatureAlgorithm.requiresPQCKeys();
    }
    
    /**
     * Check if RSA keys are required based on configuration
     */
    public boolean requiresRSAKeys() {
        return signatureAlgorithm.requiresRSAKeys() || allowLegacyTokens;
    }
    
    /**
     * Get the effective signature algorithm based on configuration
     */
    public SignatureAlgorithm getEffectiveSignatureAlgorithm() {
        if (!enablePQC) {
            return SignatureAlgorithm.RSA;
        }
        
        if (hybridMode && signatureAlgorithm.requiresPQCKeys()) {
            return SignatureAlgorithm.HYBRID;
        }
        
        return signatureAlgorithm;
    }
    
    /**
     * Check if a token with the given algorithm should be accepted
     */
    public boolean acceptsTokenAlgorithm(SignatureAlgorithm tokenAlgorithm) {
        if (tokenAlgorithm == null) {
            return false;
        }
        
        // Always accept tokens with our configured algorithm
        if (tokenAlgorithm == signatureAlgorithm) {
            return true;
        }
        
        // Check if legacy tokens are allowed
        if (tokenAlgorithm == SignatureAlgorithm.RSA && allowLegacyTokens) {
            return true;
        }
        
        // If force PQC validation is enabled, only accept PQC tokens
        if (forcePQCValidation && !tokenAlgorithm.isQuantumResistant()) {
            return false;
        }
        
        return true;
    }
    
    @Override
    public String toString() {
        return "LTPAPQCConfiguration[" +
               "enablePQC=" + enablePQC +
               ", signatureAlgorithm=" + signatureAlgorithm +
               ", pqcSecurityLevel=" + pqcSecurityLevel +
               ", allowLegacyTokens=" + allowLegacyTokens +
               ", hybridMode=" + hybridMode +
               ", keyRotationInterval=" + (keyRotationInterval / (24 * 60 * 60 * 1000)) + " days" +
               ", forcePQCValidation=" + forcePQCValidation +
               "]";
    }
}

// Made with Bob
