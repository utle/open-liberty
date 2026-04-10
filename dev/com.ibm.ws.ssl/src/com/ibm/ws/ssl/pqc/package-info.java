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
/**
 * Post-Quantum Cryptography (PQC) support for Liberty SSL.
 * 
 * <p>This package provides support for quantum-resistant cryptographic algorithms
 * in Liberty's SSL/TLS infrastructure, based on NIST-standardized PQC algorithms:</p>
 * 
 * <ul>
 *   <li><b>ML-KEM (Kyber)</b> - Key Encapsulation Mechanism (FIPS 203)</li>
 *   <li><b>ML-DSA (Dilithium)</b> - Digital Signature Algorithm (FIPS 204)</li>
 * </ul>
 * 
 * <p>The implementation supports both hybrid mode (classical + PQC) and pure PQC mode,
 * with hybrid mode recommended for production deployments during the transition period.</p>
 * 
 * <h2>Key Classes:</h2>
 * <ul>
 *   <li>{@link com.ibm.ws.ssl.pqc.PQCConstants} - PQC algorithm constants and utilities</li>
 *   <li>{@link com.ibm.ws.ssl.pqc.PQCProviderManager} - PQC provider initialization and management</li>
 *   <li>{@link com.ibm.ws.ssl.pqc.PQCConfigManager} - PQC configuration management</li>
 * </ul>
 * 
 * @since Liberty 24.0.0.x
 */
package com.ibm.ws.ssl.pqc;

// Made with Bob
