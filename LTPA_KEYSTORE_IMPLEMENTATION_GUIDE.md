# LTPA Keystore Implementation Guide

## Overview

This guide provides detailed implementation instructions for integrating LTPA keys into Open Liberty's keystore infrastructure. It includes code examples, configuration patterns, and step-by-step procedures.

## Table of Contents

1. [Code Implementation Examples](#code-implementation-examples)
2. [Configuration Patterns](#configuration-patterns)
3. [Migration Procedures](#migration-procedures)
4. [Testing Guidelines](#testing-guidelines)
5. [Troubleshooting](#troubleshooting)

## Code Implementation Examples

### 1. Enhanced LTPAKeyInfoManager

**File:** `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeyInfoManager.java`

```java
package com.ibm.ws.security.token.ltpa;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import javax.crypto.SecretKey;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPublicKey;
import com.ibm.ws.ssl.KeyStoreService;

public class LTPAKeyInfoManager {
    private static final TraceComponent tc = Tr.register(LTPAKeyInfoManager.class);
    
    // Existing fields...
    private KeyStoreService keyStoreService;
    
    /**
     * Set the KeyStoreService for keystore-based key loading
     */
    public void setKeyStoreService(KeyStoreService service) {
        this.keyStoreService = service;
    }
    
    /**
     * Load LTPA keys from a keystore
     * 
     * @param keyStoreRef The keystore configuration ID
     * @param secretKeyAlias Alias for the 3DES secret key
     * @param privateKeyAlias Alias for the RSA private key
     * @param publicKeyAlias Alias for the RSA public key (certificate)
     * @param keyPassword Password to access the keys
     * @throws Exception if keys cannot be loaded
     */
    @Sensitive
    public synchronized void prepareLTPAKeyInfoFromKeyStore(
            String keyStoreRef,
            String secretKeyAlias,
            String privateKeyAlias,
            String publicKeyAlias,
            @Sensitive char[] keyPassword) throws Exception {
        
        if (keyStoreService == null) {
            String msg = Tr.formatMessage(tc, "CWWKS4120E", "KeyStoreService not available");
            throw new IllegalStateException(msg);
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Loading LTPA keys from keystore: " + keyStoreRef);
        }
        
        try {
            // Load the KeyStore instance
            KeyStore keyStore = keyStoreService.getKeyStore(keyStoreRef);
            
            // Load secret key (3DES)
            SecretKey secretKey = loadSecretKey(keyStore, secretKeyAlias, keyPassword);
            if (secretKey == null) {
                throw new Exception(Tr.formatMessage(tc, "CWWKS4121E", 
                    "Secret key not found", secretKeyAlias, keyStoreRef));
            }
            
            // Load private key (RSA)
            PrivateKey privateKey = loadPrivateKey(keyStore, privateKeyAlias, keyPassword);
            if (privateKey == null) {
                throw new Exception(Tr.formatMessage(tc, "CWWKS4122E", 
                    "Private key not found", privateKeyAlias, keyStoreRef));
            }
            
            // Load public key from certificate
            PublicKey publicKey = loadPublicKey(keyStore, publicKeyAlias);
            if (publicKey == null) {
                throw new Exception(Tr.formatMessage(tc, "CWWKS4123E", 
                    "Public key certificate not found", publicKeyAlias, keyStoreRef));
            }
            
            // Cache the keys
            String cacheKey = keyStoreRef + ":" + secretKeyAlias;
            this.keyCache.put(cacheKey + SECRETKEY, secretKey.getEncoded());
            this.keyCache.put(cacheKey + PRIVATEKEY, privateKey.getEncoded());
            this.keyCache.put(cacheKey + PUBLICKEY, publicKey.getEncoded());
            
            // Extract and cache realm from certificate
            String realm = extractRealmFromCertificate(keyStore, publicKeyAlias);
            this.realmCache.put(cacheKey, realm);
            
            // Mark as loaded
            this.importFileCache.add(cacheKey);
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Successfully loaded LTPA keys from keystore: " + keyStoreRef);
            }
            
        } catch (Exception e) {
            Tr.error(tc, "CWWKS4124E", keyStoreRef, e.getMessage());
            throw e;
        }
    }
    
    /**
     * Load secret key from keystore
     */
    @Sensitive
    private SecretKey loadSecretKey(KeyStore keyStore, String alias, 
                                     @Sensitive char[] password) throws Exception {
        try {
            Key key = keyStore.getKey(alias, password);
            if (key instanceof SecretKey) {
                SecretKey secretKey = (SecretKey) key;
                
                // Validate it's a 3DES key
                if (!"DESede".equals(secretKey.getAlgorithm())) {
                    Tr.warning(tc, "CWWKS4125W", alias, secretKey.getAlgorithm(), "DESede");
                }
                
                return secretKey;
            }
            return null;
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Error loading secret key: " + alias, e);
            }
            throw e;
        }
    }
    
    /**
     * Load private key from keystore
     */
    @Sensitive
    private PrivateKey loadPrivateKey(KeyStore keyStore, String alias, 
                                       @Sensitive char[] password) throws Exception {
        try {
            Key key = keyStore.getKey(alias, password);
            if (key instanceof PrivateKey) {
                PrivateKey privateKey = (PrivateKey) key;
                
                // Validate it's an RSA key
                if (!"RSA".equals(privateKey.getAlgorithm())) {
                    Tr.warning(tc, "CWWKS4126W", alias, privateKey.getAlgorithm(), "RSA");
                }
                
                return privateKey;
            }
            return null;
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Error loading private key: " + alias, e);
            }
            throw e;
        }
    }
    
    /**
     * Load public key from certificate in keystore
     */
    private PublicKey loadPublicKey(KeyStore keyStore, String alias) throws Exception {
        try {
            Certificate cert = keyStore.getCertificate(alias);
            if (cert != null) {
                PublicKey publicKey = cert.getPublicKey();
                
                // Validate it's an RSA key
                if (!"RSA".equals(publicKey.getAlgorithm())) {
                    Tr.warning(tc, "CWWKS4127W", alias, publicKey.getAlgorithm(), "RSA");
                }
                
                return publicKey;
            }
            return null;
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Error loading public key certificate: " + alias, e);
            }
            throw e;
        }
    }
    
    /**
     * Extract realm from certificate DN
     */
    private String extractRealmFromCertificate(KeyStore keyStore, String alias) {
        try {
            Certificate cert = keyStore.getCertificate(alias);
            if (cert instanceof java.security.cert.X509Certificate) {
                java.security.cert.X509Certificate x509 = 
                    (java.security.cert.X509Certificate) cert;
                String dn = x509.getSubjectX500Principal().getName();
                
                // Extract O (Organization) from DN as realm
                String[] parts = dn.split(",");
                for (String part : parts) {
                    part = part.trim();
                    if (part.startsWith("O=")) {
                        return part.substring(2);
                    }
                }
            }
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Could not extract realm from certificate", e);
            }
        }
        
        // Default realm
        return "defaultRealm";
    }
    
    /**
     * Hybrid mode: Try keystore first, fall back to file
     */
    @Sensitive
    public synchronized void prepareLTPAKeyInfoHybrid(
            WsLocationAdmin locService,
            String keyImportFile,
            @Sensitive byte[] filePassword,
            String keyStoreRef,
            String secretKeyAlias,
            String privateKeyAlias,
            String publicKeyAlias,
            @Sensitive char[] keystorePassword,
            boolean preferKeyStore) throws Exception {
        
        Exception keystoreException = null;
        
        // Try keystore first if preferred and available
        if (preferKeyStore && keyStoreRef != null && keyStoreService != null) {
            try {
                prepareLTPAKeyInfoFromKeyStore(
                    keyStoreRef, 
                    secretKeyAlias != null ? secretKeyAlias : "ltpaSecretKey",
                    privateKeyAlias != null ? privateKeyAlias : "ltpaPrivateKey",
                    publicKeyAlias != null ? publicKeyAlias : "ltpaPublicKey",
                    keystorePassword);
                
                Tr.audit(tc, "CWWKS4128I", keyStoreRef);
                return;
                
            } catch (Exception e) {
                keystoreException = e;
                Tr.warning(tc, "CWWKS4129W", keyStoreRef, e.getMessage());
            }
        }
        
        // Fall back to file-based
        if (keyImportFile != null) {
            try {
                prepareLTPAKeyInfo(locService, keyImportFile, filePassword, null, false);
                Tr.audit(tc, "CWWKS4130I", keyImportFile);
                return;
            } catch (Exception e) {
                if (keystoreException != null) {
                    // Both failed, throw composite exception
                    Exception composite = new Exception(
                        "Failed to load LTPA keys from both keystore and file", e);
                    composite.addSuppressed(keystoreException);
                    throw composite;
                }
                throw e;
            }
        }
        
        // No valid source
        if (keystoreException != null) {
            throw keystoreException;
        }
        throw new Exception("No LTPA key source configured");
    }
    
    /**
     * Get secret key for a given cache key
     */
    public byte[] getSecretKey(String cacheKey) {
        return this.keyCache.get(cacheKey + SECRETKEY);
    }
    
    /**
     * Get private key for a given cache key
     */
    public byte[] getPrivateKey(String cacheKey) {
        return this.keyCache.get(cacheKey + PRIVATEKEY);
    }
    
    /**
     * Get public key for a given cache key
     */
    public byte[] getPublicKey(String cacheKey) {
        return this.keyCache.get(cacheKey + PUBLICKEY);
    }
    
    /**
     * Get realm for a given cache key
     */
    public String getRealm(String cacheKey) {
        return this.realmCache.get(cacheKey);
    }
}
```

### 2. Enhanced LTPAConfigurationImpl

**File:** `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAConfigurationImpl.java`

```java
package com.ibm.ws.security.token.ltpa.internal;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

import com.ibm.ws.security.token.ltpa.LTPAConfiguration;
import com.ibm.ws.ssl.KeyStoreService;
import com.ibm.wsspi.kernel.service.utils.AtomicServiceReference;

@Component(
    configurationPid = "com.ibm.ws.security.token.ltpa",
    configurationPolicy = ConfigurationPolicy.REQUIRE,
    service = { LTPAConfiguration.class },
    property = { "service.vendor=IBM" }
)
public class LTPAConfigurationImpl implements LTPAConfiguration, FileBasedActionable {
    
    // Existing fields...
    
    // NEW: Keystore configuration
    private String keyStoreRef;
    private String keyAlias;
    private String secretKeyAlias;
    private String privateKeyAlias;
    private String publicKeyAlias;
    private boolean useKeyStore;
    
    // NEW: KeyStoreService reference
    static final String KEY_KEYSTORE_SERVICE = "keyStoreService";
    private final AtomicServiceReference<KeyStoreService> keyStoreServiceRef = 
        new AtomicServiceReference<>(KEY_KEYSTORE_SERVICE);
    
    @Reference(
        name = KEY_KEYSTORE_SERVICE,
        service = KeyStoreService.class,
        cardinality = ReferenceCardinality.OPTIONAL,
        policy = ReferencePolicy.DYNAMIC
    )
    protected void setKeyStoreService(ServiceReference<KeyStoreService> ref) {
        keyStoreServiceRef.setReference(ref);
    }
    
    protected void unsetKeyStoreService(ServiceReference<KeyStoreService> ref) {
        keyStoreServiceRef.unsetReference(ref);
    }
    
    @Override
    protected void activate(ComponentContext context, Map<String, Object> props) {
        cc = context;
        locationService.activate(context);
        executorService.activate(context);
        ltpaKeysChangeNotifierService.activate(context);
        keyStoreServiceRef.activate(context);  // NEW
        
        try {
            loadConfig(props);
            setupRuntimeLTPAInfrastructure();
            debugLTPAConfig();
        } catch (IllegalArgumentException e) {
            Tr.error(tc, e.getMessage());
        }
    }
    
    @Override
    protected void deactivate(ComponentContext context) {
        // Existing deactivation...
        keyStoreServiceRef.deactivate(context);  // NEW
    }
    
    @Sensitive
    private void loadConfig(Map<String, Object> props) {
        // Existing configuration loading...
        primaryKeyImportFile = (String) props.get(CFG_KEY_IMPORT_FILE);
        primaryKeyPassword = resolvePrimaryKeyPassword(props);
        keyTokenExpiration = (Long) props.get(CFG_KEY_TOKEN_EXPIRATION);
        
        // NEW: Keystore configuration
        keyStoreRef = (String) props.get("keyStoreRef");
        keyAlias = (String) props.get("keyAlias");
        secretKeyAlias = (String) props.get("secretKeyAlias");
        privateKeyAlias = (String) props.get("privateKeyAlias");
        publicKeyAlias = (String) props.get("publicKeyAlias");
        useKeyStore = props.get("useKeyStore") != null ? 
            (Boolean) props.get("useKeyStore") : false;
        
        // Validate keystore configuration
        if (useKeyStore) {
            validateKeystoreConfig();
        }
        
        // Rest of existing configuration...
    }
    
    /**
     * Validate keystore configuration
     */
    private void validateKeystoreConfig() {
        if (keyStoreRef == null || keyStoreRef.isEmpty()) {
            String msg = Tr.formatMessage(tc, "CWWKS4131E", 
                "keyStoreRef is required when useKeyStore=true");
            throw new IllegalArgumentException(msg);
        }
        
        // If keyAlias is specified, use it for all keys unless specific aliases provided
        if (keyAlias != null && !keyAlias.isEmpty()) {
            if (secretKeyAlias == null) secretKeyAlias = keyAlias + "Secret";
            if (privateKeyAlias == null) privateKeyAlias = keyAlias + "Private";
            if (publicKeyAlias == null) publicKeyAlias = keyAlias + "Public";
        } else {
            // Ensure all specific aliases are provided
            if (secretKeyAlias == null || privateKeyAlias == null || publicKeyAlias == null) {
                String msg = Tr.formatMessage(tc, "CWWKS4132E", 
                    "Either keyAlias or all specific key aliases must be provided");
                throw new IllegalArgumentException(msg);
            }
        }
    }
    
    /**
     * Setup LTPA infrastructure with keystore support
     */
    private void setupRuntimeLTPAInfrastructure() {
        // Pass KeyStoreService to LTPAKeyInfoManager
        if (ltpaKeyInfoManager != null && keyStoreServiceRef.getService() != null) {
            ltpaKeyInfoManager.setKeyStoreService(keyStoreServiceRef.getService());
        }
        
        // Existing setup...
        submitTaskToCreateLTPAKeys();
    }
    
    // NEW: Getter methods for keystore configuration
    @Override
    public String getKeyStoreRef() {
        return keyStoreRef;
    }
    
    @Override
    public String getKeyAlias() {
        return keyAlias;
    }
    
    @Override
    public String getSecretKeyAlias() {
        return secretKeyAlias;
    }
    
    @Override
    public String getPrivateKeyAlias() {
        return privateKeyAlias;
    }
    
    @Override
    public String getPublicKeyAlias() {
        return publicKeyAlias;
    }
    
    @Override
    public boolean isUseKeyStore() {
        return useKeyStore;
    }
    
    @Override
    public boolean isHybridMode() {
        return useKeyStore && primaryKeyImportFile != null;
    }
}
```

### 3. KeyStoreService Extensions

**File:** `dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/KeyStoreService.java`

```java
package com.ibm.ws.ssl;

import java.security.KeyStore;
import java.security.KeyStoreException;
import javax.crypto.SecretKey;

public interface KeyStoreService {
    
    // Existing methods...
    
    /**
     * Get a secret key from the keystore
     * 
     * @param keyStoreName The keystore's configuration ID
     * @param alias The alias of the secret key
     * @param password The password to access the key
     * @return The SecretKey for the given alias
     * @throws KeyStoreException if the keystore does not exist or key cannot be accessed
     */
    SecretKey getSecretKeyFromKeyStore(String keyStoreName, String alias, char[] password) 
        throws KeyStoreException;
    
    /**
     * Store a secret key in the keystore
     * 
     * @param keyStoreName The keystore's configuration ID
     * @param alias The alias for the secret key
     * @param key The secret key to store
     * @param password The password to protect the key
     * @throws KeyStoreException if the keystore does not exist or key cannot be stored
     */
    void setSecretKeyEntry(String keyStoreName, String alias, SecretKey key, char[] password) 
        throws KeyStoreException;
    
    /**
     * Get a private key from the keystore
     * 
     * @param keyStoreName The keystore's configuration ID
     * @param alias The alias of the private key
     * @param password The password to access the key
     * @return The PrivateKey for the given alias
     * @throws KeyStoreException if the keystore does not exist or key cannot be accessed
     */
    java.security.Key getPrivateKeyFromKeyStore(String keyStoreName, String alias, char[] password) 
        throws KeyStoreException;
    
    /**
     * Get the underlying KeyStore instance
     * 
     * @param keyStoreName The keystore's configuration ID
     * @return The KeyStore instance
     * @throws KeyStoreException if the keystore does not exist
     */
    KeyStore getKeyStore(String keyStoreName) throws KeyStoreException;
}
```

### 4. Migration Tool Implementation

**File:** `dev/com.ibm.ws.security.utility/src/com/ibm/ws/security/utility/tasks/MigrateLTPAKeysTask.java`

```java
package com.ibm.ws.security.utility.tasks;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Properties;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.ibm.websphere.crypto.PasswordUtil;
import com.ibm.ws.common.encoder.Base64Coder;
import com.ibm.ws.crypto.ltpakeyutil.KeyEncryptor;
import com.ibm.ws.crypto.ltpakeyutil.LTPAKeyFileUtility;

/**
 * Security utility task to migrate LTPA keys from file to keystore
 */
public class MigrateLTPAKeysTask extends BaseCommandTask {
    
    private static final String TASK_NAME = "migrateLTPAKeys";
    
    @Override
    public String getTaskName() {
        return TASK_NAME;
    }
    
    @Override
    public String getTaskDescription() {
        return "Migrate LTPA keys from file-based storage to keystore";
    }
    
    @Override
    public String getTaskHelp() {
        return "Usage: securityUtility migrateLTPAKeys [options]\n\n" +
               "Options:\n" +
               "  --ltpaKeysFile=<file>          Path to LTPA keys file\n" +
               "  --ltpaKeysPassword=<password>  Password for LTPA keys file\n" +
               "  --keyStore=<file>              Path to target keystore\n" +
               "  --keyStorePassword=<password>  Password for keystore\n" +
               "  --keyStoreType=<type>          Keystore type (default: PKCS12)\n" +
               "  --keyAlias=<alias>             Base alias for keys (default: ltpaKey)\n" +
               "  --secretKeyAlias=<alias>       Alias for secret key\n" +
               "  --privateKeyAlias=<alias>      Alias for private key\n" +
               "  --publicKeyAlias=<alias>       Alias for public key\n" +
               "  --overwrite                    Overwrite existing keys in keystore\n";
    }
    
    @Override
    public void execute(String[] args) {
        try {
            // Parse arguments
            MigrationConfig config = parseArguments(args);
            
            // Validate configuration
            validateConfiguration(config);
            
            // Perform migration
            migrateLTPAKeys(config);
            
            System.out.println("LTPA keys successfully migrated to keystore: " + 
                             config.keyStorePath);
            
        } catch (Exception e) {
            System.err.println("Error migrating LTPA keys: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private void migrateLTPAKeys(MigrationConfig config) throws Exception {
        // 1. Load existing LTPA keys from file
        System.out.println("Loading LTPA keys from file: " + config.ltpaKeysFile);
        Properties props = loadLTPAKeysFile(config.ltpaKeysFile);
        
        // 2. Decrypt keys
        System.out.println("Decrypting LTPA keys...");
        byte[][] keys = decryptKeys(
            config.ltpaKeysPassword.getBytes(),
            props.getProperty(LTPAKeyFileUtility.KEYIMPORT_SECRETKEY),
            props.getProperty(LTPAKeyFileUtility.KEYIMPORT_PRIVATEKEY),
            props.getProperty(LTPAKeyFileUtility.KEYIMPORT_PUBLICKEY)
        );
        
        byte[] secretKeyBytes = keys[0];
        byte[] privateKeyBytes = keys[1];
        byte[] publicKeyBytes = keys[2];
        String realm = props.getProperty(LTPAKeyFileUtility.KEYIMPORT_REALM, "defaultRealm");
        
        // 3. Create or load keystore
        System.out.println("Loading keystore: " + config.keyStorePath);
        KeyStore keyStore = loadOrCreateKeyStore(config);
        
        // 4. Store secret key
        System.out.println("Storing secret key with alias: " + config.secretKeyAlias);
        SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "DESede");
        keyStore.setEntry(
            config.secretKeyAlias,
            new KeyStore.SecretKeyEntry(secretKey),
            new KeyStore.PasswordProtection(config.keyStorePassword.toCharArray())
        );
        
        // 5. Store private key and certificate
        System.out.println("Storing private key with alias: " + config.privateKeyAlias);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(
            new PKCS8EncodedKeySpec(privateKeyBytes));
        PublicKey publicKey = keyFactory.generatePublic(
            new X509EncodedKeySpec(publicKeyBytes));
        
        // Generate self-signed certificate
        X509Certificate cert = CertificateGenerator.generateSelfSignedCertificate(
            privateKey, publicKey, realm, 3650); // 10 years validity
        
        keyStore.setKeyEntry(
            config.privateKeyAlias,
            privateKey,
            config.keyStorePassword.toCharArray(),
            new Certificate[] { cert }
        );
        
        // 6. Store public key certificate
        System.out.println("Storing public key certificate with alias: " + config.publicKeyAlias);
        keyStore.setCertificateEntry(config.publicKeyAlias, cert);
        
        // 7. Save keystore
        System.out.println("Saving keystore...");
        try (FileOutputStream fos = new FileOutputStream(config.keyStorePath)) {
            keyStore.store(fos, config.keyStorePassword.toCharArray());
        }
        
        System.out.println("Migration completed successfully!");
        System.out.println("\nKeystore configuration:");
        System.out.println("  Location: " + config.keyStorePath);
        System.out.println("  Type: " + config.keyStoreType);
        System.out.println("  Secret Key Alias: " + config.secretKeyAlias);
        System.out.println("  Private Key Alias: " + config.privateKeyAlias);
        System.out.println("  Public Key Alias: " + config.publicKeyAlias);
        System.out.println("\nAdd to server.xml:");
        System.out.println("  <keyStore id=\"ltpaKeyStore\"");
        System.out.println("            location=\"" + config.keyStorePath + "\"");
        System.out.println("            type=\"" + config.keyStoreType + "\"");
        System.out.println("            password=\"{xor}...\" />");
        System.out.println("  <ltpa keyStoreRef=\"ltpaKeyStore\"");
        System.out.println("        secretKeyAlias=\"" + config.secretKeyAlias + "\"");
        System.out.println("        privateKeyAlias=\"" + config.privateKeyAlias + "\"");
        System.out.println("        publicKeyAlias=\"" + config.publicKeyAlias + "\"");
        System.out.println("        useKeyStore=\"true\" />");
    }
    
    private Properties loadLTPAKeysFile(String filePath) throws Exception {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(filePath)) {
            props.load(fis);
        }
        return props;
    }
    
    private byte[][] decryptKeys(byte[] password, String secretKeyStr, 
                                 String privateKeyStr, String publicKeyStr) throws Exception {
        KeyEncryptor encryptor = new KeyEncryptor(password);
        
        byte[] secretKey = encryptor.decrypt(Base64Coder.base64Decode(secretKeyStr));
        byte[] privateKey = encryptor.decrypt(Base64Coder.base64Decode(privateKeyStr));
        byte[] publicKey = Base64Coder.base64Decode(publicKeyStr);
        
        return new byte[][] { secretKey, privateKey, publicKey };
    }
    
    private KeyStore loadOrCreateKeyStore(MigrationConfig config) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(config.keyStoreType);
        File ksFile = new File(config.keyStorePath);
        
        if (ksFile.exists()) {
            if (!config.overwrite) {
                System.out.println("Loading existing keystore...");
                try (FileInputStream fis = new FileInputStream(ksFile)) {
                    keyStore.load(fis, config.keyStorePassword.toCharArray());
                }
            } else {
                System.out.println("Creating new keystore (overwrite mode)...");
                keyStore.load(null, config.keyStorePassword.toCharArray());
            }
        } else {
            System.out.println("Creating new keystore...");
            keyStore.load(null, config.keyStorePassword.toCharArray());
            
            // Create parent directories if needed
            File parent = ksFile.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
        }
        
        return keyStore;
    }
    
    private MigrationConfig parseArguments(String[] args) {
        MigrationConfig config = new MigrationConfig();
        
        for (String arg : args) {
            if (arg.startsWith("--ltpaKeysFile=")) {
                config.ltpaKeysFile = arg.substring("--ltpaKeysFile=".length());
            } else if (arg.startsWith("--ltpaKeysPassword=")) {
                config.ltpaKeysPassword = arg.substring("--ltpaKeysPassword=".length());
            } else if (arg.startsWith("--keyStore=")) {
                config.keyStorePath = arg.substring("--keyStore=".length());
            } else if (arg.startsWith("--keyStorePassword=")) {
                config.keyStorePassword = arg.substring("--keyStorePassword=".length());
            } else if (arg.startsWith("--keyStoreType=")) {
                config.keyStoreType = arg.substring("--keyStoreType=".length());
            } else if (arg.startsWith("--keyAlias=")) {
                String baseAlias = arg.substring("--keyAlias=".length());
                config.secretKeyAlias = baseAlias + "Secret";
                config.privateKeyAlias = baseAlias + "Private";
                config.publicKeyAlias = baseAlias + "Public";
            } else if (arg.startsWith("--secretKeyAlias=")) {
                config.secretKeyAlias = arg.substring("--secretKeyAlias=".length());
            } else if (arg.startsWith("--privateKeyAlias=")) {
                config.privateKeyAlias = arg.substring("--privateKeyAlias=".length());
            } else if (arg.startsWith("--publicKeyAlias=")) {
                config.publicKeyAlias = arg.substring("--publicKeyAlias=".length());
            } else if (arg.equals("--overwrite")) {
                config.overwrite = true;
            }
        }
        
        return config;
    }
    
    private void validateConfiguration(MigrationConfig config) throws Exception {
        if (config.ltpaKeysFile == null || config.ltpaKeysFile.isEmpty()) {
            throw new IllegalArgumentException("--ltpaKeysFile is required");
        }
        if (config.ltpaKeysPassword == null || config.ltpaKeysPassword.isEmpty()) {
            throw new IllegalArgumentException("--ltpaKeysPassword is required");
        }
        if (config.keyStorePath == null || config.keyStorePath.isEmpty()) {
            throw new IllegalArgumentException("--keyStore is required");
        }
        if (config.keyStorePassword == null || config.keyStorePassword.isEmpty()) {
            throw new IllegalArgumentException("--keyStorePassword is required");
        }
        
        File ltpaFile = new File(config.ltpaKeysFile);
        if (!ltpaFile.exists()) {
            throw new IllegalArgumentException("LTPA keys file not found: " + config.ltpaKeysFile);
        }
    }
    
    private static class MigrationConfig {
        String ltpaKeysFile;
        String ltpaKeysPassword;
        String keyStorePath;
        String keyStorePassword;
        String keyStoreType = "PKCS12";
        String secretKeyAlias = "ltpaKeySecret";
        String privateKeyAlias = "ltpaKeyPrivate";
        String publicKeyAlias = "ltpaKeyPublic";
        boolean overwrite = false;
    }
}
```

## Configuration Patterns

### Pattern 1: Dedicated LTPA Keystore

**Use Case:** Separate keystore for LTPA keys, isolated from SSL certificates

```xml
<server>
    <!-- Dedicated LTPA keystore -->
    <keyStore id="ltpaKeyStore" 
              location="${server.config.dir}/resources/security/ltpa.p12"
              type="PKCS12" 
              password="{xor}Lz4sLCgwLTs=" />
    
    <!-- LTPA configuration -->
    <ltpa keyStoreRef="ltpaKeyStore"
          keyAlias="ltpaKey"
          useKeyStore="true"
          expiration="120m" />
    
    <!-- Separate SSL keystore -->
    <keyStore id="defaultKeyStore"
              location="${server.config.dir}/resources/security/key.p12"
              type="PKCS12"
              password="{xor}Lz4sLCgwLTs=" />
    
    <ssl id="defaultSSLConfig"
         keyStoreRef="defaultKeyStore"
         trustStoreRef="defaultKeyStore" />
</server>
```

### Pattern 2: Shared Keystore

**Use Case:** Single keystore for both LTPA and SSL

```xml
<server>
    <!-- Shared keystore -->
    <keyStore id="defaultKeyStore" 
              location="${server.config.dir}/resources/security/key.p12"
              type="PKCS12" 
              password="{xor}Lz4sLCgwLTs=" />
    
    <!-- LTPA uses shared keystore -->
    <ltpa keyStoreRef="defaultKeyStore"
          secretKeyAlias="ltpaSecret"
          privateKeyAlias="ltpaPrivate"
          publicKeyAlias="ltpaPublic"
          useKeyStore="true"
          expiration="120m" />
    
    <!-- SSL uses same keystore -->
    <ssl id="defaultSSLConfig"
         keyStoreRef="defaultKeyStore"
         trustStoreRef="defaultKeyStore" />
</server>
```

### Pattern 3: HSM-Backed Keystore

**Use Case:** Hardware security module for maximum security

```xml
<server>
    <!-- HSM keystore configuration -->
    <keyStore id="hsmKeyStore"
              type="PKCS11"
              provider="SunPKCS11"
              location="/opt/hsm/pkcs11.cfg"
              password="{aes}..." />
    
    <!-- LTPA with HSM -->
    <ltpa keyStoreRef="hsmKeyStore"
          secretKeyAlias="ltpaSecret"
          privateKeyAlias="ltpaPrivate"
          publicKeyAlias="ltpaPublic"
          useKeyStore="true"
          expiration="120m" />
</server>
```

### Pattern 4: Hybrid Mode (Migration)

**Use Case:** Gradual migration from file to keystore

```xml
<server>
    <!-- Keystore for new keys -->
    <keyStore id="ltpaKeyStore" 
              location="${server.config.dir}/resources/security/ltpa.p12"
              type="PKCS12" 
              password="{xor}Lz4sLCgwLTs=" />
    
    <!-- Hybrid configuration -->
    <ltpa keysFileName="${server.output.dir}/resources/security/ltpa.keys"
          keysPassword="{xor}Lz4sLCgwLTs="
          keyStoreRef="ltpaKeyStore"
          keyAlias="ltpaKey"
          useKeyStore="false"
          expiration="120m" />
    
    <!-- After migration, change useKeyStore to true -->
</server>
```

### Pattern 5: Multiple Validation Keys

**Use Case:** Support tokens from multiple sources

```xml
<server>
    <keyStore id="primaryKeyStore" 
              location="${server.config.dir}/resources/security/primary.p12"
              type="PKCS12" 
              password="{xor}..." />
    
    <keyStore id="partnerKeyStore" 
              location="${server.config.dir}/resources/security/partner.p12"
              type="PKCS12" 
              password="{xor}..." />
    
    <ltpa keyStoreRef="primaryKeyStore"
          keyAlias="currentKey"
          useKeyStore="true">
        
        <!-- Previous key for rotation -->
        <validationKeys keyStoreRef="primaryKeyStore"
                        keyAlias="previousKey"
                        validUntilDate="2026-12-31T23:59:59Z" />
        
        <!-- Partner organization key -->
        <validationKeys keyStoreRef="partnerKeyStore"
                        keyAlias="partnerKey"
                        validUntilDate="2027-06-30T23:59:59Z" />
    </ltpa>
</server>
```

## Migration Procedures

### Procedure 1: Basic Migration

**Step 1: Backup existing LTPA keys**
```bash
cp ${WLP_OUTPUT_DIR}/resources/security/ltpa.keys \
   ${WLP_OUTPUT_DIR}/resources/security/ltpa.keys.backup
```

**Step 2: Run migration tool**
```bash
securityUtility migrateLTPAKeys \
    --ltpaKeysFile=${WLP_OUTPUT_DIR}/resources/security/ltpa.keys \
    --ltpaKeysPassword=myPassword \
    --keyStore=${WLP_USER_DIR}/servers/myServer/resources/security/ltpa.p12 \
    --keyStorePassword=keystorePassword \
    --keyStoreType=PKCS12 \
    --keyAlias=ltpaKey
```

**Step 3: Update server.xml**
```xml
<keyStore id="ltpaKeyStore" 
          location="${server.config.dir}/resources/security/ltpa.p12"
          type="PKCS12" 
          password="{xor}..." />

<ltpa keyStoreRef="ltpaKeyStore"
      keyAlias="ltpaKey"
      useKeyStore="true"
      expiration="120m" />
```

**Step 4: Restart server and verify**
```bash
server stop myServer
server start myServer
```

Check logs for:
```
CWWKS4128I: LTPA keys loaded from keystore: ltpaKeyStore
```

### Procedure 2: Zero-Downtime Migration

**Step 1: Enable hybrid mode**
```xml
<keyStore id="ltpaKeyStore" 
          location="${server.config.dir}/resources/security/ltpa.p12"
          type="PKCS12" 
          password="{xor}..." />

<ltpa keysFileName="${server.output.dir}/resources/security/ltpa.keys"
      keysPassword="{xor}..."
      keyStoreRef="ltpaKeyStore"
      keyAlias="ltpaKey"
      useKeyStore="false"
      expiration="120m" />
```

**Step 2: Migrate keys while server is running**
```bash
securityUtility migrateLTPAKeys \
    --ltpaKeysFile=${WLP_OUTPUT_DIR}/resources/security/ltpa.keys \
    --ltpaKeysPassword=myPassword \
    --keyStore=${WLP_USER_DIR}/servers/myServer/resources/security/ltpa.p12 \
    --keyStorePassword=keystorePassword \
    --keyAlias=ltpaKey
```

**Step 3: Switch to keystore mode**
```xml
<ltpa keysFileName="${server.output.dir}/resources/security/ltpa.keys"
      keysPassword="{xor}..."
      keyStoreRef="ltpaKeyStore"
      keyAlias="ltpaKey"
      useKeyStore="true"
      expiration="120m" />
```

Server will automatically reload configuration without restart.

**Step 4: Remove file-based configuration (optional)**
```xml
<ltpa keyStoreRef="ltpaKeyStore"
      keyAlias="ltpaKey"
      useKeyStore="true"
      expiration="120m" />
```

## Testing Guidelines

### Unit Test Example

```java
@Test
public void testLoadLTPAKeysFromKeyStore() throws Exception {
    // Setup
    KeyStore keyStore = createTestKeyStore();
    KeyStoreService mockService = mock(KeyStoreService.class);
    when(mockService.getKeyStore("testKeyStore")).thenReturn(keyStore);
    
    LTPAKeyInfoManager manager = new LTPAKeyInfoManager();
    manager.setKeyStoreService(mockService);
    
    // Execute
    manager.prepareLTPAKeyInfoFromKeyStore(
        "testKeyStore",
        "ltpaKeySecret",
        "ltpaKeyPrivate",
        "ltpaKeyPublic",
        "password".toCharArray()
    );
    
    // Verify
    assertNotNull(manager.getSecretKey("testKeyStore:ltpaKeySecret"));
    assertNotNull(manager.getPrivateKey("testKeyStore:ltpaKeySecret"));
    assertNotNull(manager.getPublicKey("testKeyStore:ltpaKeySecret"));
}
```

### Integration Test Example

```java
@Test
public void testLTPATokenWithKeystoreKeys() throws Exception {
    // Configure server with keystore
    server.setServerConfigurationFile("ltpa_keystore.xml");
    server.startServer();
    
    // Wait for LTPA to be ready
    assertNotNull(server.waitForStringInLog("CWWKS4128I.*ltpaKeyStore"));
    
    // Test token creation
    String token = createLTPAToken("testuser");
    assertNotNull(token);
    
    // Test token validation
    Subject subject = validateLTPAToken(token);
    assertEquals("testuser", getUserName(subject));
}
```

## Troubleshooting

### Common Issues

**Issue 1: Keystore not found**
```
CWWKS4120E: KeyStoreService not available
```
**Solution:** Ensure `ssl-1.0` feature is enabled in server.xml

**Issue 2: Key alias not found**
```
CWWKS4121E: Secret key not found [ltpaKeySecret] in keystore [ltpaKeyStore]
```
**Solution:** Verify key aliases match keystore contents using:
```bash
keytool -list -keystore ltpa.p12 -storepass password
```

**Issue 3: Wrong key type**
```
CWWKS4125W: Key [ltpaKeySecret] has algorithm [AES] but expected [DESede]
```
**Solution:** Ensure secret key is 3DES type during migration

**Issue 4: Password mismatch**
```
CWPKI0033E: The keystore did not load
```
**Solution:** Verify keystore password is correct and properly encoded

### Debug Logging

Enable trace logging:
```xml
<logging traceSpecification="com.ibm.ws.security.token.ltpa.*=all:com.ibm.ws.ssl.*=all" />
```

Look for:
- `Loading LTPA keys from keystore: <keystoreRef>`
- `Successfully loaded LTPA keys from keystore`
- Key loading details and any errors

## Conclusion

This implementation guide provides the code, configurations, and procedures needed to integrate LTPA keys into Open Liberty's keystore infrastructure. Follow the patterns and procedures appropriate for your deployment scenario.