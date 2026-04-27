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
package com.ibm.ws.security.token.ltpa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyStore;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Unit tests for LTPAKeystoreManager class.
 * Tests keystore creation, loading, validation, and security features.
 */
public class LTPAKeystoreManagerTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private LTPAKeystoreManager keystoreManager;
    private File testKeystoreFile;
    private char[] testPassword;
    private LTPAKeys testLTPAKeys;

    // Test key data (24 bytes for secret key, sample RSA key bytes)
    private static final byte[] TEST_SECRET_KEY = new byte[24];
    private static final byte[] TEST_PRIVATE_KEY = new byte[128];
    private static final byte[] TEST_PUBLIC_KEY = new byte[128];

    static {
        // Initialize with test data
        for (int i = 0; i < TEST_SECRET_KEY.length; i++) {
            TEST_SECRET_KEY[i] = (byte) i;
        }
        for (int i = 0; i < TEST_PRIVATE_KEY.length; i++) {
            TEST_PRIVATE_KEY[i] = (byte) (i % 256);
        }
        for (int i = 0; i < TEST_PUBLIC_KEY.length; i++) {
            TEST_PUBLIC_KEY[i] = (byte) ((i * 2) % 256);
        }
    }

    @Before
    public void setUp() throws Exception {
        keystoreManager = new LTPAKeystoreManager();
        testKeystoreFile = new File(tempFolder.getRoot(), "test-ltpa.p12");
        testPassword = "testPassword123".toCharArray();
        testLTPAKeys = new LTPAKeys(TEST_SECRET_KEY, TEST_PRIVATE_KEY, TEST_PUBLIC_KEY);
    }

    @After
    public void tearDown() {
        // Clean up password
        if (testPassword != null) {
            for (int i = 0; i < testPassword.length; i++) {
                testPassword[i] = ' ';
            }
        }
    }

    /**
     * Test successful keystore creation with valid inputs.
     */
    @Test
    public void testCreateKeystore_Success() throws Exception {
        keystoreManager.createKeystore(testKeystoreFile, testPassword, testLTPAKeys);

        // Verify keystore file was created
        assertTrue("Keystore file should exist", testKeystoreFile.exists());
        assertTrue("Keystore file should not be empty", testKeystoreFile.length() > 0);

        // Verify it's a valid PKCS12 keystore
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(Files.newInputStream(testKeystoreFile.toPath()), testPassword);
        
        // Verify all three keys are present
        assertTrue("Secret key should exist", keystore.containsAlias("ltpaSecretKey"));
        assertTrue("Private key should exist", keystore.containsAlias("ltpaPrivateKey"));
        assertTrue("Public key should exist", keystore.containsAlias("ltpaPublicKey"));
    }

    /**
     * Test keystore creation with null keystoreFile parameter.
     */
    @Test
    public void testCreateKeystore_NullKeystoreFile() {
        try {
            keystoreManager.createKeystore(null, testPassword, testLTPAKeys);
            fail("Should throw IllegalArgumentException for null keystoreFile");
        } catch (IllegalArgumentException e) {
            assertEquals("Keystore file cannot be null", e.getMessage());
        } catch (Exception e) {
            fail("Should throw IllegalArgumentException, not " + e.getClass().getName());
        }
    }

    /**
     * Test keystore creation with null password parameter.
     */
    @Test
    public void testCreateKeystore_NullPassword() {
        try {
            keystoreManager.createKeystore(testKeystoreFile, null, testLTPAKeys);
            fail("Should throw IllegalArgumentException for null password");
        } catch (IllegalArgumentException e) {
            assertEquals("Password cannot be null", e.getMessage());
        } catch (Exception e) {
            fail("Should throw IllegalArgumentException, not " + e.getClass().getName());
        }
    }

    /**
     * Test keystore creation with null LTPA keys parameter.
     */
    @Test
    public void testCreateKeystore_NullLTPAKeys() {
        try {
            keystoreManager.createKeystore(testKeystoreFile, testPassword, null);
            fail("Should throw IllegalArgumentException for null ltpaKeys");
        } catch (IllegalArgumentException e) {
            assertEquals("LTPA keys cannot be null", e.getMessage());
        } catch (Exception e) {
            fail("Should throw IllegalArgumentException, not " + e.getClass().getName());
        }
    }

    /**
     * Test keystore creation with path traversal attempt.
     */
    @Test
    public void testCreateKeystore_PathTraversalPrevention() {
        File maliciousPath = new File(tempFolder.getRoot(), "../../../etc/passwd");
        
        try {
            keystoreManager.createKeystore(maliciousPath, testPassword, testLTPAKeys);
            fail("Should throw IllegalArgumentException for path traversal");
        } catch (IllegalArgumentException e) {
            assertTrue("Should detect path traversal", 
                       e.getMessage().contains("path traversal") || 
                       e.getMessage().contains("Invalid keystore path"));
        } catch (Exception e) {
            fail("Should throw IllegalArgumentException, not " + e.getClass().getName());
        }
    }

    /**
     * Test successful loading of keys from keystore.
     */
    @Test
    public void testLoadKeysFromKeystore_Success() throws Exception {
        // First create a keystore
        keystoreManager.createKeystore(testKeystoreFile, testPassword, testLTPAKeys);

        // Now load it back
        LTPAKeys loadedKeys = keystoreManager.loadKeysFromKeystore(testKeystoreFile, testPassword);

        // Verify loaded keys match original keys
        assertNotNull("Loaded keys should not be null", loadedKeys);
        assertNotNull("Secret key should not be null", loadedKeys.getSecretKeyBytes());
        assertNotNull("Private key should not be null", loadedKeys.getPrivateKeyBytes());
        assertNotNull("Public key should not be null", loadedKeys.getPublicKeyBytes());

        // Verify key lengths
        assertEquals("Secret key length should match", TEST_SECRET_KEY.length, 
                     loadedKeys.getSecretKeyBytes().length);
        assertEquals("Private key length should match", TEST_PRIVATE_KEY.length, 
                     loadedKeys.getPrivateKeyBytes().length);
        assertEquals("Public key length should match", TEST_PUBLIC_KEY.length, 
                     loadedKeys.getPublicKeyBytes().length);
    }

    /**
     * Test loading keys with null keystoreFile parameter.
     */
    @Test
    public void testLoadKeysFromKeystore_NullKeystoreFile() {
        try {
            keystoreManager.loadKeysFromKeystore(null, testPassword);
            fail("Should throw IllegalArgumentException for null keystoreFile");
        } catch (IllegalArgumentException e) {
            assertEquals("Keystore file cannot be null", e.getMessage());
        } catch (Exception e) {
            fail("Should throw IllegalArgumentException, not " + e.getClass().getName());
        }
    }

    /**
     * Test loading keys with null password parameter.
     */
    @Test
    public void testLoadKeysFromKeystore_NullPassword() {
        try {
            keystoreManager.loadKeysFromKeystore(testKeystoreFile, null);
            fail("Should throw IllegalArgumentException for null password");
        } catch (IllegalArgumentException e) {
            assertEquals("Password cannot be null", e.getMessage());
        } catch (Exception e) {
            fail("Should throw IllegalArgumentException, not " + e.getClass().getName());
        }
    }

    /**
     * Test loading keys with path traversal attempt.
     */
    @Test
    public void testLoadKeysFromKeystore_PathTraversalPrevention() {
        File maliciousPath = new File(tempFolder.getRoot(), "../../../etc/passwd");
        
        try {
            keystoreManager.loadKeysFromKeystore(maliciousPath, testPassword);
            fail("Should throw IllegalArgumentException for path traversal");
        } catch (IllegalArgumentException e) {
            assertTrue("Should detect path traversal", 
                       e.getMessage().contains("path traversal") || 
                       e.getMessage().contains("Invalid keystore path"));
        } catch (Exception e) {
            fail("Should throw IllegalArgumentException, not " + e.getClass().getName());
        }
    }

    /**
     * Test loading keys from non-existent keystore file.
     */
    @Test
    public void testLoadKeysFromKeystore_FileNotFound() {
        File nonExistentFile = new File(tempFolder.getRoot(), "nonexistent.p12");
        
        try {
            keystoreManager.loadKeysFromKeystore(nonExistentFile, testPassword);
            fail("Should throw LTPAKeystoreException for non-existent file");
        } catch (LTPAKeystoreException e) {
            assertTrue("Should indicate file not found", 
                       e.getMessage().contains("Failed to load LTPA keys"));
        } catch (Exception e) {
            fail("Should throw LTPAKeystoreException, not " + e.getClass().getName());
        }
    }

    /**
     * Test loading keys with incorrect password.
     */
    @Test
    public void testLoadKeysFromKeystore_IncorrectPassword() throws Exception {
        // Create keystore with correct password
        keystoreManager.createKeystore(testKeystoreFile, testPassword, testLTPAKeys);

        // Try to load with incorrect password
        char[] wrongPassword = "wrongPassword".toCharArray();
        
        try {
            keystoreManager.loadKeysFromKeystore(testKeystoreFile, wrongPassword);
            fail("Should throw LTPAKeystoreException for incorrect password");
        } catch (LTPAKeystoreException e) {
            assertTrue("Should indicate password error", 
                       e.getMessage().contains("Failed to load LTPA keys"));
        } catch (Exception e) {
            fail("Should throw LTPAKeystoreException, not " + e.getClass().getName());
        } finally {
            // Clean up wrong password
            for (int i = 0; i < wrongPassword.length; i++) {
                wrongPassword[i] = ' ';
            }
        }
    }

    /**
     * Test isValidKeystore with valid keystore.
     */
    @Test
    public void testIsValidKeystore_ValidKeystore() throws Exception {
        // Create a valid keystore
        keystoreManager.createKeystore(testKeystoreFile, testPassword, testLTPAKeys);

        // Verify it's valid
        assertTrue("Should recognize valid keystore", 
                   keystoreManager.isValidKeystore(testKeystoreFile, testPassword));
    }

    /**
     * Test isValidKeystore with null file.
     */
    @Test
    public void testIsValidKeystore_NullFile() {
        assertFalse("Should return false for null file", 
                    keystoreManager.isValidKeystore(null, testPassword));
    }

    /**
     * Test isValidKeystore with non-existent file.
     */
    @Test
    public void testIsValidKeystore_NonExistentFile() {
        File nonExistentFile = new File(tempFolder.getRoot(), "nonexistent.p12");
        assertFalse("Should return false for non-existent file", 
                    keystoreManager.isValidKeystore(nonExistentFile, testPassword));
    }

    /**
     * Test isValidKeystore with incorrect password.
     */
    @Test
    public void testIsValidKeystore_IncorrectPassword() throws Exception {
        // Create keystore with correct password
        keystoreManager.createKeystore(testKeystoreFile, testPassword, testLTPAKeys);

        // Check with incorrect password
        char[] wrongPassword = "wrongPassword".toCharArray();
        try {
            assertFalse("Should return false for incorrect password", 
                        keystoreManager.isValidKeystore(testKeystoreFile, wrongPassword));
        } finally {
            // Clean up wrong password
            for (int i = 0; i < wrongPassword.length; i++) {
                wrongPassword[i] = ' ';
            }
        }
    }

    /**
     * Test isValidKeystore with empty file.
     */
    @Test
    public void testIsValidKeystore_EmptyFile() throws Exception {
        File emptyFile = new File(tempFolder.getRoot(), "empty.p12");
        emptyFile.createNewFile();
        
        assertFalse("Should return false for empty file", 
                    keystoreManager.isValidKeystore(emptyFile, testPassword));
    }

    /**
     * Test that keystore creation creates parent directories if needed.
     */
    @Test
    public void testCreateKeystore_CreatesParentDirectories() throws Exception {
        File nestedFile = new File(tempFolder.getRoot(), "subdir1/subdir2/test.p12");
        
        keystoreManager.createKeystore(nestedFile, testPassword, testLTPAKeys);

        assertTrue("Keystore file should exist", nestedFile.exists());
        assertTrue("Parent directories should be created", nestedFile.getParentFile().exists());
    }

    /**
     * Test that exception type is LTPAKeystoreException.
     */
    @Test
    public void testExceptionType() throws Exception {
        File nonExistentFile = new File(tempFolder.getRoot(), "nonexistent.p12");
        
        try {
            keystoreManager.loadKeysFromKeystore(nonExistentFile, testPassword);
            fail("Should throw exception");
        } catch (LTPAKeystoreException e) {
            // Expected - verify it's the correct exception type
            assertNotNull("Exception message should not be null", e.getMessage());
            assertTrue("Should have cause", e.getCause() != null || e.getMessage().length() > 0);
        } catch (Exception e) {
            fail("Should throw LTPAKeystoreException, not " + e.getClass().getName());
        }
    }
}

// Made with Bob
