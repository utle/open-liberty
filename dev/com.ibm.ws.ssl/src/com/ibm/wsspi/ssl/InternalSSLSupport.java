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
package com.ibm.wsspi.ssl;

import java.util.Map;

import javax.net.ssl.X509TrustManager;

import com.ibm.websphere.ssl.SSLException;

/**
 * Internal SPI for Liberty components to access SSL functionality
 * not exposed through public APIs.
 * 
 * <p>This is NOT a public API and may change without notice.</p>
 * 
 * <p>This interface provides access to WSX509TrustManager instances
 * for internal Liberty components that need to configure TLS connections
 * programmatically, such as OpenTelemetry exporters.</p>
 */
public interface InternalSSLSupport {
    
    /**
     * Get a WSX509TrustManager for the specified SSL configuration.
     * The returned trust manager is a wrapper that provides enhanced
     * error handling and tracing.
     * 
     * <p>If the specified SSL configuration is not found, this method
     * will attempt to use the default SSL configuration.</p>
     * 
     * @param sslAliasName The SSL configuration alias, or null for default
     * @param connectionInfo Connection information map (optional)
     * @return WSX509TrustManager instance
     * @throws SSLException if trust manager cannot be created
     */
    X509TrustManager getTrustManager(String sslAliasName, Map<String, Object> connectionInfo) throws SSLException;
    
    /**
     * Get a WSX509TrustManager for the specified SSL configuration,
     * with option to try default configuration on failure.
     * 
     * <p>The returned trust manager is a wrapper that provides enhanced
     * error handling and tracing.</p>
     * 
     * @param sslAliasName The SSL configuration alias, or null for default
     * @param connectionInfo Connection information map (optional)
     * @param tryDefault Whether to fall back to default SSL config if specified config not found
     * @return WSX509TrustManager instance
     * @throws SSLException if trust manager cannot be created
     */
    X509TrustManager getTrustManager(String sslAliasName, Map<String, Object> connectionInfo, boolean tryDefault) throws SSLException;
}

// Made with Bob
