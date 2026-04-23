/*******************************************************************************
 * Copyright (c) 2016, 2026 IBM Corporation and others.
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

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Utility class for LTPA key operations including RSA and post-quantum cryptography (PQC).
 *
 * Supports:
 * - RSA key generation and operations (LTPA v2.0)
 * - ML-DSA key generation (LTPA v4.0)
 * - Hybrid RSA+ML-DSA keys (LTPA v3.0)
 */
public final class LTPAKeyUtil {

	// ========== Legacy RSA Methods (LTPA v2.0) ==========

	public static byte[] encrypt(byte[] data, byte[] key, String cipher) throws Exception {
		return LTPACrypto.encrypt(data, key, cipher);
	}

	public static byte[] decrypt(byte[] msg, byte[] key, String cipher) throws Exception {
		return LTPACrypto.decrypt(msg, key, cipher);
	}

	public static boolean verifyISO9796(byte[][] key, byte[] data, int off, int len, byte[] sig, int sigOff, int sigLen)
			throws Exception {
		return LTPACrypto.verifyISO9796(key, data, off, len, sig, sigOff, sigLen);
	}

	public static byte[] signISO9796(byte[][] key, byte[] data, int off, int len) throws Exception {
		return LTPACrypto.signISO9796(key, data, off, len);
	}

	public static void setRSAKey(byte[][] key) {
		LTPACrypto.setRSAKey(key);
	}

	public static byte[][] getRawKey(LTPAPrivateKey privKey) {
		return privKey.getRawKey();
	}

	public static byte[][] getRawKey(LTPAPublicKey pubKey) {
		return pubKey.getRawKey();
	}

	public static LTPAKeyPair generateLTPAKeyPair() {
		return LTPADigSignature.generateLTPAKeyPair();
	}

	/**
	 * Generate an RSA LTPA key pair with specified key size.
	 *
	 * @param password Optional password (can be null)
	 * @param keySize RSA key size in bits (2048 or 3072 recommended)
	 * @return LTPAKeyPair containing RSA keys
	 */
	public static LTPAKeyPair generateLTPAKeyPair(String password, int keySize) {
		// Use existing generation logic with specified key size
		int oldKeySize = LTPADigSignature.keySize;
		try {
			LTPADigSignature.keySize = keySize / 8; // Convert bits to bytes
			return LTPADigSignature.generateLTPAKeyPair();
		} finally {
			LTPADigSignature.keySize = oldKeySize; // Restore original
		}
	}

	public static byte[] generateSharedKey() {
		return LTPACrypto.generateSharedKey();
	}

	// ========== Post-Quantum Cryptography Methods ==========

	/**
	 * Generate an ML-DSA key pair with default security level (3).
	 *
	 * @return LTPAMLDSAKeyPair for LTPA v4.0
	 * @throws Exception if key generation fails
	 */
	public static LTPAMLDSAKeyPair generateMLDSAKeyPair() throws Exception {
		return LTPAMLDSAKeyGenerator.generateKeyPair();
	}

	/**
	 * Generate an ML-DSA key pair with specified security level.
	 *
	 * @param securityLevel Security level (2, 3, or 5)
	 * @return LTPAMLDSAKeyPair for LTPA v4.0
	 * @throws Exception if key generation fails
	 */
	public static LTPAMLDSAKeyPair generateMLDSAKeyPair(int securityLevel) throws Exception {
		return LTPAMLDSAKeyGenerator.generateKeyPair(securityLevel);
	}

	/**
	 * Generate a hybrid key pair with default settings (RSA-2048 + ML-DSA-65).
	 *
	 * @return LTPAHybridKeyPair for LTPA v3.0
	 * @throws Exception if key generation fails
	 */
	public static LTPAHybridKeyPair generateHybridKeyPair() throws Exception {
		return LTPAMLDSAKeyGenerator.generateHybridKeyPair();
	}

	/**
	 * Generate a hybrid key pair with specified parameters.
	 *
	 * @param rsaKeySize RSA key size in bits (2048 or 3072 recommended)
	 * @param mldsaSecurityLevel ML-DSA security level (2, 3, or 5)
	 * @return LTPAHybridKeyPair for LTPA v3.0
	 * @throws Exception if key generation fails
	 */
	public static LTPAHybridKeyPair generateHybridKeyPair(int rsaKeySize, int mldsaSecurityLevel) throws Exception {
		return LTPAMLDSAKeyGenerator.generateHybridKeyPair(rsaKeySize, mldsaSecurityLevel);
	}

	// ========== Key Conversion Utilities ==========

	/**
	 * Convert RSA private key bytes to Java PrivateKey object.
	 *
	 * @param privateKeyBytes Encoded private key
	 * @return PrivateKey object
	 * @throws Exception if conversion fails
	 */
	public static PrivateKey getPrivateKey(byte[] privateKeyBytes) throws Exception {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		return keyFactory.generatePrivate(keySpec);
	}

	/**
	 * Convert RSA public key bytes to Java PublicKey object.
	 *
	 * @param publicKeyBytes Encoded public key
	 * @return PublicKey object
	 * @throws Exception if conversion fails
	 */
	public static PublicKey getPublicKey(byte[] publicKeyBytes) throws Exception {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
		return keyFactory.generatePublic(keySpec);
	}

	/**
	 * Create a signature algorithm instance from an RSA key pair.
	 *
	 * @param keyPair RSA key pair
	 * @return RSASignatureAlgorithm for LTPA v2.0
	 * @throws Exception if creation fails
	 */
	public static RSASignatureAlgorithm createRSASignatureAlgorithm(LTPAKeyPair keyPair) throws Exception {
		return RSASignatureAlgorithm.fromKeyPair(keyPair);
	}

	/**
	 * Create a signature algorithm instance from an ML-DSA key pair.
	 *
	 * @param keyPair ML-DSA key pair
	 * @return MLDSASignatureAlgorithm for LTPA v4.0
	 * @throws Exception if creation fails
	 */
	public static MLDSASignatureAlgorithm createMLDSASignatureAlgorithm(LTPAMLDSAKeyPair keyPair) throws Exception {
		return MLDSASignatureAlgorithm.fromKeyPair(keyPair);
	}

	/**
	 * Create a signature algorithm instance from a hybrid key pair.
	 *
	 * @param keyPair Hybrid key pair
	 * @return HybridSignatureAlgorithm for LTPA v3.0
	 * @throws Exception if creation fails
	 */
	public static HybridSignatureAlgorithm createHybridSignatureAlgorithm(LTPAHybridKeyPair keyPair) throws Exception {
		return HybridSignatureAlgorithm.fromKeyPair(keyPair);
	}

	/**
	 * Get recommended ML-DSA security level for a given RSA key size.
	 *
	 * @param rsaKeySize RSA key size in bits
	 * @return Recommended ML-DSA security level
	 */
	public static int getRecommendedMLDSALevel(int rsaKeySize) {
		return LTPAMLDSAKeyGenerator.getRecommendedMLDSALevel(rsaKeySize);
	}
}
