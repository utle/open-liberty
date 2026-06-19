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
package com.ibm.ws.ssl.internal;

import java.security.KeyStore;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ssl.Constants;
import com.ibm.websphere.ssl.JSSEHelper;
import com.ibm.websphere.ssl.SSLConfig;
import com.ibm.websphere.ssl.SSLException;
import com.ibm.ws.ssl.JSSEProviderFactory;
import com.ibm.ws.ssl.config.KeyStoreManager;
import com.ibm.ws.ssl.config.SSLConfigManager;
import com.ibm.ws.ssl.config.WSKeyStore;
import com.ibm.ws.ssl.core.WSX509TrustManager;
import com.ibm.ws.ssl.provider.AbstractJSSEProvider;
import com.ibm.wsspi.ssl.InternalSSLSupport;

/**
 * Internal implementation of SSL support for Liberty components.
 * 
 * <p>This service provides access to WSX509TrustManager instances
 * for internal Liberty components that need to configure TLS connections
 * programmatically.</p>
 */
@Component(service = InternalSSLSupport.class,
           configurationPolicy = ConfigurationPolicy.IGNORE,
           property = "service.vendor=IBM")
public class InternalSSLSupportImpl implements InternalSSLSupport {
    
    private static final TraceComponent tc = Tr.register(InternalSSLSupportImpl.class, 
                                                         TraceConstants.TRACE_GROUP, 
                                                         TraceConstants.MESSAGE_BUNDLE);
    
    @Override
    public X509TrustManager getTrustManager(String sslAliasName, Map<String, Object> connectionInfo) throws SSLException {
        return getTrustManager(sslAliasName, connectionInfo, true);
    }
    
    @Override
    public X509TrustManager getTrustManager(String sslAliasName, Map<String, Object> connectionInfo, boolean tryDefault) throws SSLException {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled())
            Tr.entry(tc, "getTrustManager", new Object[] { sslAliasName, connectionInfo, tryDefault });
        
        try {
            // Get SSL configuration properties using same logic as JSSEHelper
            JSSEHelper helper = JSSEHelper.getInstance();
            Properties sslProps = helper.getProperties(sslAliasName, connectionInfo, null, tryDefault);
            
            if (sslProps == null) {
                SSLException ex = new SSLException("SSL configuration not found for alias: " + sslAliasName);
                if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled())
                    Tr.exit(tc, "getTrustManager", ex);
                throw ex;
            }
            
            // Get trust store information
            String trustStoreName = sslProps.getProperty(Constants.SSLPROP_TRUST_STORE);
            String trustStoreLocation = sslProps.getProperty(Constants.SSLPROP_TRUST_STORE_NAME);
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled())
                Tr.debug(tc, "Trust store name: " + trustStoreName + ", location: " + trustStoreLocation);
            
            // Get trust store
            KeyStore trustStore = null;
            if (trustStoreName != null) {
                WSKeyStore wsTrustStore = KeyStoreManager.getInstance().getKeyStoreFromMap(trustStoreName);
                if (wsTrustStore != null) {
                    trustStore = wsTrustStore.getKeyStore();
                }
            }
            
            // Get trust manager algorithm
            String trustMgr = sslProps.getProperty(Constants.SSLPROP_TRUST_MANAGER);
            if (trustMgr == null) {
                trustMgr = JSSEProviderFactory.getTrustManagerFactoryAlgorithm();
            }
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled())
                Tr.debug(tc, "Trust manager algorithm: " + trustMgr);
            
            // Get context provider
            String ctxtProvider = sslProps.getProperty(Constants.SSLPROP_CONTEXT_PROVIDER);
            
            // Create trust manager factory
            TrustManagerFactory tmf = AbstractJSSEProvider.getTrustManagerFactoryInstance(trustMgr, ctxtProvider);
            tmf.init(trustStore);
            
            // Get trust managers
            TrustManager[] trustManagers = tmf.getTrustManagers();
            
            if (trustManagers == null || trustManagers.length == 0) {
                SSLException ex = new SSLException("No trust managers available for SSL configuration: " + sslAliasName);
                if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled())
                    Tr.exit(tc, "getTrustManager", ex);
                throw ex;
            }
            
            // Get SSLConfig for WSX509TrustManager
            SSLConfig sslConfig = SSLConfigManager.getInstance().getSSLConfig(sslAliasName);
            if (sslConfig == null) {
                // Create a basic SSLConfig from properties if not found
                sslConfig = new SSLConfig();
                sslConfig.putAll(sslProps);
            }
            
            // Create WSX509TrustManager wrapper
            WSX509TrustManager wsTrustManager = new WSX509TrustManager(
                trustManagers, 
                connectionInfo, 
                sslConfig, 
                trustStoreName, 
                trustStoreLocation
            );
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled())
                Tr.exit(tc, "getTrustManager", wsTrustManager);
            
            return wsTrustManager;
            
        } catch (SSLException e) {
            // Re-throw SSLException as-is
            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled())
                Tr.exit(tc, "getTrustManager", e);
            throw e;
        } catch (Exception e) {
            // Wrap other exceptions in SSLException
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled())
                Tr.debug(tc, "Exception creating trust manager", e);
            SSLException ex = new SSLException("Failed to create trust manager for alias: " + sslAliasName, e);
            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled())
                Tr.exit(tc, "getTrustManager", ex);
            throw ex;
        }
    }
}

// Made with Bob
