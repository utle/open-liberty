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

import java.security.Provider;
import java.security.Security;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ssl.Constants;

/**
 * Manager for Post-Quantum Cryptography (PQC) security providers.
 * 
 * This class handles the initialization and management of PQC providers,
 * primarily BouncyCastle PQC provider. It ensures the provider is loaded
 * only once and provides methods to check PQC availability.
 */
public class PQCProviderManager {
    
    private static final TraceComponent tc = Tr.register(
        PQCProviderManager.class, "SSL", "com.ibm.ws.ssl.resources.ssl");
    
    private static boolean pqcProviderInitialized = false;
    private static Provider pqcProvider = null;
    private static final Object initLock = new Object();
    
    /**
     * Initialize the PQC provider (BouncyCastle PQC).
     * This method is thread-safe and will only initialize the provider once.
     * 
     * @return true if the provider was successfully initialized or was already initialized,
     *         false if initialization failed
     */
    public static boolean initializePQCProvider() {
        if (pqcProviderInitialized) {
            return pqcProvider != null;
        }
        
        synchronized (initLock) {
            // Double-check after acquiring lock
            if (pqcProviderInitialized) {
                return pqcProvider != null;
            }
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.entry(tc, "initializePQCProvider");
            }
            
            try {
                // Try to load BouncyCastle PQC provider
                Class<?> providerClass = Class.forName(Constants.BOUNCYCASTLE_PQC_PROVIDER_CLASS);
                pqcProvider = (Provider) providerClass.getDeclaredConstructor().newInstance();
                
                // Add provider to Security
                Security.addProvider(pqcProvider);
                
                if (TraceComponent.isAnyTracingEnabled() && tc.isInfoEnabled()) {
                    Tr.info(tc, "ssl.pqc.provider.initialized.CWPKI0845I", 
                           new Object[] { pqcProvider.getName(), pqcProvider.getVersionStr() });
                }
                
                pqcProviderInitialized = true;
                
                if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                    Tr.exit(tc, "initializePQCProvider", Boolean.TRUE);
                }
                
                return true;
                
            } catch (ClassNotFoundException e) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "BouncyCastle PQC provider class not found: " + 
                            Constants.BOUNCYCASTLE_PQC_PROVIDER_CLASS);
                }
                Tr.warning(tc, "ssl.pqc.provider.unavailable.CWPKI0840E", 
                          "BouncyCastle PQC provider not found in classpath");
                pqcProviderInitialized = true;
                
                if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                    Tr.exit(tc, "initializePQCProvider", Boolean.FALSE);
                }
                
                return false;
                
            } catch (Exception e) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "Failed to initialize PQC provider", e);
                }
                Tr.warning(tc, "ssl.pqc.provider.unavailable.CWPKI0840E", 
                          "Failed to initialize: " + e.getMessage());
                pqcProviderInitialized = true;
                
                if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                    Tr.exit(tc, "initializePQCProvider", Boolean.FALSE);
                }
                
                return false;
            }
        }
    }
    
    /**
     * Check if PQC is available in the current environment.
     * This method will attempt to initialize the provider if not already done.
     * 
     * @return true if PQC provider is available, false otherwise
     */
    public static boolean isPQCAvailable() {
        if (!pqcProviderInitialized) {
            initializePQCProvider();
        }
        return pqcProvider != null;
    }
    
    /**
     * Get the PQC provider instance.
     * 
     * @return the PQC provider, or null if not initialized or unavailable
     */
    public static Provider getPQCProvider() {
        return pqcProvider;
    }
    
    /**
     * Get the name of the PQC provider.
     * 
     * @return the provider name, or null if not initialized
     */
    public static String getPQCProviderName() {
        return pqcProvider != null ? pqcProvider.getName() : null;
    }
    
    /**
     * Get the version of the PQC provider.
     * 
     * @return the provider version string, or null if not initialized
     */
    public static String getPQCProviderVersion() {
        return pqcProvider != null ? pqcProvider.getVersionStr() : null;
    }
    
    /**
     * Check if a specific algorithm is supported by the PQC provider.
     * 
     * @param algorithmType the type of algorithm (e.g., "KeyPairGenerator", "Signature")
     * @param algorithmName the name of the algorithm (e.g., "ML-KEM-768")
     * @return true if the algorithm is supported, false otherwise
     */
    public static boolean isAlgorithmSupported(String algorithmType, String algorithmName) {
        if (!isPQCAvailable()) {
            return false;
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Checking algorithm support: " + algorithmType + "." + algorithmName);
        }
        
        try {
            // Check if the provider supports this algorithm
            String key = algorithmType + "." + algorithmName;
            return pqcProvider.getService(algorithmType, algorithmName) != null;
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Error checking algorithm support", e);
            }
            return false;
        }
    }
    
    /**
     * Reset the provider initialization state.
     * This is primarily for testing purposes.
     * 
     * WARNING: This method should not be called in production code.
     */
    static void resetForTesting() {
        synchronized (initLock) {
            if (pqcProvider != null) {
                Security.removeProvider(pqcProvider.getName());
                pqcProvider = null;
            }
            pqcProviderInitialized = false;
        }
    }
    
    /**
     * Private constructor to prevent instantiation.
     */
    private PQCProviderManager() {
        // Utility class - no instances
    }
}

// Made with Bob
