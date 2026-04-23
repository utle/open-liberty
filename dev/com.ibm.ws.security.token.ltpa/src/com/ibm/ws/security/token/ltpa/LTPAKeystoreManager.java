/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.security.token.ltpa;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;

/**
 * Manages LTPA keystore operations for PKCS12 keystores.
 * Stores LTPA keys using SecretKeyEntry for secret keys and setKeyEntry for private keys.
 */
public class LTPAKeystoreManager {
    private static final TraceComponent tc = Tr.register(LTPAKeystoreManager.class);

    // Keystore entry aliases
    private static final String SECRET_KEY_ALIAS = "ltpaSecretKey";
    private static final String PRIVATE_KEY_ALIAS = "ltpaPrivateKey";
    private static final String PUBLIC_KEY_ALIAS = "ltpaPublicKey";

    // Key algorithms
    private static final String SECRET_KEY_ALGORITHM = "AES"; // Use AES for 24-byte (192-bit) secret key
    private static final String ASYMMETRIC_KEY_ALGORITHM = "RSA";
    private static final String KEYSTORE_TYPE = "PKCS12";

    /**
     * Create a new PKCS12 keystore with LTPA keys.
     * Stores secret key using AES algorithm and private key with NULL certificate chain.
     *
     * @param keystoreFile The keystore file to create
     * @param password The keystore password
     * @param ltpaKeys The LTPA keys to store
     * @throws Exception if keystore creation fails
     */
    public void createKeystore(File keystoreFile, char[] password, LTPAKeys ltpaKeys) throws Exception {
        if (tc.isEntryEnabled()) {
            Tr.entry(tc, "createKeystore", keystoreFile.getAbsolutePath());
        }

        try {
            // Create new PKCS12 keystore
            KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(null, password);

            // Store secret key (24 bytes) as AES-192
            SecretKey secretKey = new SecretKeySpec(ltpaKeys.getSecretKeyBytes(), SECRET_KEY_ALGORITHM);
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(password);
            keystore.setEntry(SECRET_KEY_ALIAS, secretKeyEntry, passwordProtection);

            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Stored secret key with alias: " + SECRET_KEY_ALIAS);
            }

            // Store private key (RSA) with NULL certificate chain
            KeyFactory keyFactory = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM);
            PrivateKey privateKey = keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(ltpaKeys.getPrivateKeyBytes())
            );
            keystore.setKeyEntry(PRIVATE_KEY_ALIAS, privateKey, password, null);

            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Stored private key with alias: " + PRIVATE_KEY_ALIAS);
            }

            // Store public key bytes as AES SecretKey
            SecretKey publicKeyAsSecret = new SecretKeySpec(ltpaKeys.getPublicKeyBytes(), SECRET_KEY_ALGORITHM);
            KeyStore.SecretKeyEntry publicKeyEntry = new KeyStore.SecretKeyEntry(publicKeyAsSecret);
            keystore.setEntry(PUBLIC_KEY_ALIAS, publicKeyEntry, passwordProtection);

            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Stored public key with alias: " + PUBLIC_KEY_ALIAS);
            }

            // Ensure parent directories exist
            File parentDir = keystoreFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                if (!parentDir.mkdirs()) {
                    throw new IOException("Failed to create keystore directory: " + parentDir.getAbsolutePath());
                }
            }

            // Save keystore to file
            try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
                keystore.store(fos, password);
            }

            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Keystore created successfully: " + keystoreFile.getAbsolutePath());
            }

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException |
                 CertificateException | InvalidKeySpecException e) {
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Failed to create keystore", e);
            }
            throw new Exception("Failed to create LTPA keystore: " + e.getMessage(), e);
        } finally {
            if (tc.isEntryEnabled()) {
                Tr.exit(tc, "createKeystore");
            }
        }
    }

    /**
     * Load LTPA keys from an existing keystore.
     *
     * @param keystoreFile The keystore file to load from
     * @param password The keystore password
     * @return The LTPA keys loaded from the keystore
     * @throws Exception if key loading fails
     */
    public LTPAKeys loadKeysFromKeystore(File keystoreFile, char[] password) throws Exception {
        if (tc.isEntryEnabled()) {
            Tr.entry(tc, "loadKeysFromKeystore", keystoreFile.getAbsolutePath());
        }

        try {
            // Load PKCS12 keystore
            KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                keystore.load(fis, password);
            }

            // Retrieve secret key
            SecretKey secretKey = (SecretKey) keystore.getKey(SECRET_KEY_ALIAS, password);
            if (secretKey == null) {
                throw new Exception("Secret key not found in keystore with alias: " + SECRET_KEY_ALIAS);
            }
            byte[] secretKeyBytes = secretKey.getEncoded();

            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Loaded secret key from keystore");
            }

            // Retrieve private key
            PrivateKey privateKey = (PrivateKey) keystore.getKey(PRIVATE_KEY_ALIAS, password);
            if (privateKey == null) {
                throw new Exception("Private key not found in keystore with alias: " + PRIVATE_KEY_ALIAS);
            }
            byte[] privateKeyBytes = privateKey.getEncoded();

            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Loaded private key from keystore");
            }

            // Retrieve public key (stored as a SecretKey entry)
            SecretKey publicKeyAsSecret = (SecretKey) keystore.getKey(PUBLIC_KEY_ALIAS, password);
            if (publicKeyAsSecret == null) {
                throw new Exception("Public key not found in keystore with alias: " + PUBLIC_KEY_ALIAS);
            }
            byte[] publicKeyBytes = publicKeyAsSecret.getEncoded();

            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Loaded public key from keystore");
            }

            LTPAKeys ltpaKeys = new LTPAKeys(secretKeyBytes, privateKeyBytes, publicKeyBytes);

            if (tc.isEntryEnabled()) {
                Tr.exit(tc, "loadKeysFromKeystore");
            }

            return ltpaKeys;

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException |
                 CertificateException | UnrecoverableKeyException e) {
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Failed to load keys from keystore", e);
            }
            throw new Exception("Failed to load LTPA keys from keystore: " + e.getMessage(), e);
        }
    }

    /**
     * Check if a keystore file exists and is valid.
     * 
     * @param keystoreFile The keystore file to check
     * @param password The keystore password
     * @return true if the keystore exists and can be loaded
     */
    public boolean isValidKeystore(File keystoreFile, char[] password) {
        if (keystoreFile == null || !keystoreFile.exists() || !keystoreFile.isFile()) {
            return false;
        }

        try {
            KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                keystore.load(fis, password);
            }
            // Check if required aliases exist
            return keystore.containsAlias(SECRET_KEY_ALIAS) && 
                   keystore.containsAlias(PRIVATE_KEY_ALIAS) &&
                   keystore.containsAlias(PUBLIC_KEY_ALIAS);
        } catch (Exception e) {
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Keystore validation failed", e);
            }
            return false;
        }
    }
}

// Made with Bob
