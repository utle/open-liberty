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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ssl.Constants;

/**
 * Configuration manager for Post-Quantum Cryptography (PQC) settings.
 * 
 * This class manages PQC configuration from SSL properties, including:
 * <ul>
 *   <li>PQC enabled/disabled state</li>
 *   <li>PQC mode (hybrid, pure, disabled)</li>
 *   <li>KEM algorithm selection</li>
 *   <li>Signature algorithm selection</li>
 *   <li>Hybrid cipher suite configuration</li>
 * </ul>
 */
public class PQCConfigManager {
    
    private static final TraceComponent tc = Tr.register(
        PQCConfigManager.class, "SSL", "com.ibm.ws.ssl.resources.ssl");
    
    private final boolean pqcEnabled;
    private final String pqcMode;
    private final String kemAlgorithm;
    private final String signatureAlgorithm;
    private final String[] hybridCipherSuites;
    
    /**
     * Create a new PQC configuration manager from SSL properties.
     * 
     * @param sslProps the SSL properties containing PQC configuration
     */
    public PQCConfigManager(Properties sslProps) {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "PQCConfigManager", sslProps);
        }
        
        if (sslProps == null) {
            sslProps = new Properties();
        }
        
        // Load PQC enabled flag
        String enabled = sslProps.getProperty(Constants.SSLPROP_PQC_ENABLED, "false");
        this.pqcEnabled = Boolean.parseBoolean(enabled);
        
        // Load PQC mode
        this.pqcMode = sslProps.getProperty(
            Constants.SSLPROP_PQC_MODE, 
            Constants.PQC_MODE_HYBRID);
        
        // Load KEM algorithm
        this.kemAlgorithm = sslProps.getProperty(
            Constants.SSLPROP_PQC_KEM_ALGORITHM,
            PQCConstants.RECOMMENDED_KEM);
        
        // Load signature algorithm
        this.signatureAlgorithm = sslProps.getProperty(
            Constants.SSLPROP_PQC_SIGNATURE_ALGORITHM,
            PQCConstants.RECOMMENDED_SIGNATURE);
        
        // Load hybrid cipher suites
        String ciphers = sslProps.getProperty(Constants.SSLPROP_PQC_HYBRID_CIPHERS, "");
        if (ciphers.isEmpty()) {
            this.hybridCipherSuites = PQCConstants.HYBRID_CIPHER_SUITES;
        } else {
            this.hybridCipherSuites = ciphers.split(",\\s*");
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "PQC Configuration loaded: enabled=" + pqcEnabled + 
                    ", mode=" + pqcMode + 
                    ", KEM=" + kemAlgorithm + 
                    ", signature=" + signatureAlgorithm +
                    ", ciphers=" + Arrays.toString(hybridCipherSuites));
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "PQCConfigManager");
        }
    }
    
    /**
     * Check if PQC is enabled and available.
     * PQC is considered enabled if the configuration flag is true AND
     * the PQC provider is available in the environment.
     * 
     * @return true if PQC is enabled and available, false otherwise
     */
    public boolean isPQCEnabled() {
        boolean available = pqcEnabled && PQCProviderManager.isPQCAvailable();
        
        if (pqcEnabled && !PQCProviderManager.isPQCAvailable()) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "PQC is enabled in configuration but provider is not available");
            }
        }
        
        return available;
    }
    
    /**
     * Get the PQC mode.
     * 
     * @return the PQC mode (hybrid, pure, or disabled)
     */
    public String getPQCMode() {
        return pqcMode;
    }
    
    /**
     * Get the configured KEM algorithm.
     * 
     * @return the KEM algorithm name
     */
    public String getKemAlgorithm() {
        return kemAlgorithm;
    }
    
    /**
     * Get the configured signature algorithm.
     * 
     * @return the signature algorithm name
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
    
    /**
     * Get the configured hybrid cipher suites.
     * 
     * @return array of hybrid cipher suite names
     */
    public String[] getHybridCipherSuites() {
        return hybridCipherSuites.clone();
    }
    
    /**
     * Check if hybrid mode is enabled.
     * 
     * @return true if mode is hybrid, false otherwise
     */
    public boolean isHybridMode() {
        return Constants.PQC_MODE_HYBRID.equals(pqcMode);
    }
    
    /**
     * Check if pure PQC mode is enabled.
     * 
     * @return true if mode is pure, false otherwise
     */
    public boolean isPureMode() {
        return Constants.PQC_MODE_PURE.equals(pqcMode);
    }
    
    /**
     * Check if PQC is explicitly disabled.
     * 
     * @return true if mode is disabled, false otherwise
     */
    public boolean isDisabled() {
        return Constants.PQC_MODE_DISABLED.equals(pqcMode) || !pqcEnabled;
    }
    
    /**
     * Validate the PQC configuration.
     * 
     * @return list of validation error messages, empty if valid
     */
    public List<String> validate() {
        List<String> errors = new ArrayList<>();
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "validate");
        }
        
        // Validate PQC mode
        if (!Constants.PQC_MODE_HYBRID.equals(pqcMode) &&
            !Constants.PQC_MODE_PURE.equals(pqcMode) &&
            !Constants.PQC_MODE_DISABLED.equals(pqcMode)) {
            errors.add("Invalid PQC mode: " + pqcMode + 
                      ". Must be 'hybrid', 'pure', or 'disabled'");
        }
        
        // Validate KEM algorithm
        if (!PQCConstants.isSupportedKemAlgorithm(kemAlgorithm)) {
            errors.add("Unsupported PQC KEM algorithm: " + kemAlgorithm + 
                      ". Supported: " + PQCConstants.SUPPORTED_KEM_ALGORITHMS);
        }
        
        // Validate signature algorithm
        if (!PQCConstants.isSupportedSignatureAlgorithm(signatureAlgorithm)) {
            errors.add("Unsupported PQC signature algorithm: " + signatureAlgorithm + 
                      ". Supported: " + PQCConstants.SUPPORTED_SIGNATURE_ALGORITHMS);
        }
        
        // Validate hybrid cipher suites
        if (isHybridMode() && (hybridCipherSuites == null || hybridCipherSuites.length == 0)) {
            errors.add("Hybrid mode requires at least one hybrid cipher suite");
        }
        
        // Check provider availability if PQC is enabled
        if (pqcEnabled && !PQCProviderManager.isPQCAvailable()) {
            errors.add("PQC is enabled but provider is not available. " +
                      "Ensure BouncyCastle PQC provider is in the classpath");
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            if (errors.isEmpty()) {
                Tr.debug(tc, "PQC configuration is valid");
            } else {
                Tr.debug(tc, "PQC configuration validation errors: " + errors);
            }
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "validate", errors);
        }
        
        return errors;
    }
    
    /**
     * Get a summary of the PQC configuration for logging.
     * 
     * @return configuration summary string
     */
    public String getConfigurationSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("PQC Configuration: ");
        sb.append("enabled=").append(isPQCEnabled());
        sb.append(", mode=").append(pqcMode);
        sb.append(", KEM=").append(kemAlgorithm);
        sb.append(" (Level ").append(PQCConstants.getKemSecurityLevel(kemAlgorithm)).append(")");
        sb.append(", signature=").append(signatureAlgorithm);
        sb.append(" (Level ").append(PQCConstants.getSignatureSecurityLevel(signatureAlgorithm)).append(")");
        
        if (isHybridMode()) {
            sb.append(", hybrid ciphers=").append(hybridCipherSuites.length);
        }
        
        return sb.toString();
    }
    
    @Override
    public String toString() {
        return getConfigurationSummary();
    }
}

// Made with Bob
