# LTPA Keystore Implementation Plan

## Status: Ready to Implement

The `com.ibm.ws.security.token.ltpa` module builds successfully. We have analyzed the tWAS implementation and identified the correct approach for storing LTPA keys in keystores.

## Key Discovery from tWAS Analysis

**Critical Insight**: tWAS stores LTPA keys in keystores **WITHOUT generating X.509 certificates**. Keys are stored with a `null` certificate chain using the standard Java KeyStore API.

## Implementation Approach

### 1. Create LTPAKeystoreManager.java

Location: `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeystoreManager.java`

**Purpose**: Manage LTPA keystore operations (create, load, store keys)

**Key Methods**:

```java
public class LTPAKeystoreManager {
    
    /**
     * Create a new PKCS12 keystore with LTPA keys
     * @param keystoreFile The keystore file path
     * @param password The keystore password
     * @param ltpaKeys The LTPA keys to store (secret, private, public)
     */
    public void createKeystore(File keystoreFile, char[] password, LTPAKeys ltpaKeys) 
        throws Exception {
        
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(null, password);
        
        // Store secret key (3DES/AES) with null certificate chain
        SecretKey secretKey = new SecretKeySpec(
            ltpaKeys.getSecretKeyBytes(), 
            "DESede"  // or "AES" for FIPS
        );
        keystore.setEntry("ltpaSecretKey", 
            new KeyStore.SecretKeyEntry(secretKey),
            new KeyStore.PasswordProtection(password));
        
        // Store private key with null certificate chain
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(
            new PKCS8EncodedKeySpec(ltpaKeys.getPrivateKeyBytes())
        );
        keystore.setKeyEntry("ltpaPrivateKey", privateKey, password, null);
        
        // Store public key (as encoded bytes or minimal cert)
        PublicKey publicKey = keyFactory.generatePublic(
            new X509EncodedKeySpec(ltpaKeys.getPublicKeyBytes())
        );
        // Option 1: Store as certificate entry
        // Option 2: Store encoded bytes separately
        
        // Save keystore
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            keystore.store(fos, password);
        }
    }
    
    /**
     * Load LTPA keys from existing keystore
     */
    public LTPAKeys loadKeysFromKeystore(File keystoreFile, char[] password) 
        throws Exception {
        
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            keystore.load(fis, password);
        }
        
        // Retrieve secret key
        SecretKey secretKey = (SecretKey) keystore.getKey(
            "ltpaSecretKey", 
            password
        );
        
        // Retrieve private key
        PrivateKey privateKey = (PrivateKey) keystore.getKey(
            "ltpaPrivateKey", 
            password
        );
        
        // Retrieve public key
        PublicKey publicKey = // retrieve from keystore
        
        return new LTPAKeys(
            secretKey.getEncoded(),
            privateKey.getEncoded(),
            publicKey.getEncoded()
        );
    }
    
    /**
     * Migrate .keys file to keystore
     */
    public void migrateKeysFileToKeystore(File keysFile, File keystoreFile, 
                                          char[] password) throws Exception {
        // Load keys from .keys file
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(keysFile)) {
            props.load(fis);
        }
        
        // Decrypt and decode keys
        LTPAKeys ltpaKeys = decodeKeysFromProperties(props, password);
        
        // Create keystore with keys
        createKeystore(keystoreFile, password, ltpaKeys);
    }
}
```

### 2. Create LTPAKeys.java

Location: `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeys.java`

**Purpose**: Simple data holder for LTPA key bytes

```java
public class LTPAKeys {
    private final byte[] secretKeyBytes;
    private final byte[] privateKeyBytes;
    private final byte[] publicKeyBytes;
    
    public LTPAKeys(byte[] secretKey, byte[] privateKey, byte[] publicKey) {
        this.secretKeyBytes = secretKey;
        this.privateKeyBytes = privateKey;
        this.publicKeyBytes = publicKey;
    }
    
    public byte[] getSecretKeyBytes() { return secretKeyBytes; }
    public byte[] getPrivateKeyBytes() { return privateKeyBytes; }
    public byte[] getPublicKeyBytes() { return publicKeyBytes; }
}
```

### 3. Update LTPAKeyInfoManager.java

Add keystore support alongside existing .keys file support:

```java
// Add field
private LTPAKeystoreManager keystoreManager;

// In loadLTPAKeys() method, check for keystore first
File keystoreFile = new File(serverOutputDir, "resources/security/ltpa.p12");
if (keystoreFile.exists()) {
    // Load from keystore
    LTPAKeys keys = keystoreManager.loadKeysFromKeystore(
        keystoreFile, 
        keystorePassword
    );
    // Convert to existing format
} else {
    // Fall back to .keys file
    // existing code...
}
```

### 4. Update LTPAConfigurationImpl.java

Add keystore configuration properties:

```java
// Add configuration fields
private String keystoreLocation;
private String keystorePassword;
private boolean useKeystore = true;  // default to keystore

// Add OSGi configuration methods
@Modified
protected void modified(Map<String, Object> properties) {
    keystoreLocation = (String) properties.get("keystoreLocation");
    keystorePassword = (String) properties.get("keystorePassword");
    useKeystore = (Boolean) properties.getOrDefault("useKeystore", true);
}
```

### 5. Update metatype.xml

Add keystore configuration options:

```xml
<AD id="keystoreLocation" name="%keystoreLocation" 
    description="%keystoreLocation.desc" 
    type="String" 
    default="${server.output.dir}/resources/security/ltpa.p12"/>

<AD id="keystorePassword" name="%keystorePassword" 
    description="%keystorePassword.desc" 
    type="String" 
    ibm:type="password"/>

<AD id="useKeystore" name="%useKeystore" 
    description="%useKeystore.desc" 
    type="Boolean" 
    default="true"/>
```

### 6. Update LTPAKeyCreateTask.java

Modify to create keystore instead of .keys file when configured:

```java
if (config.useKeystore()) {
    // Generate keys using existing LTPAKeyFileUtilityImpl
    byte[][] keys = LTPAKeyFileUtilityImpl.generateLTPAKeys();
    
    // Create keystore
    LTPAKeys ltpaKeys = new LTPAKeys(keys[0], keys[1], keys[2]);
    keystoreManager.createKeystore(
        new File(config.getKeystoreLocation()),
        config.getKeystorePassword().toCharArray(),
        ltpaKeys
    );
} else {
    // Create .keys file (existing code)
}
```

## Implementation Steps

1. ✅ **Build Verification** - Module builds successfully
2. ✅ **tWAS Analysis** - Completed, documented in LTPA_KEYSTORE_TWAS_ANALYSIS.md
3. **Create LTPAKeys.java** - Simple data holder class
4. **Create LTPAKeystoreManager.java** - Core keystore operations
5. **Update LTPAKeyInfoManager.java** - Add keystore loading
6. **Update LTPAConfigurationImpl.java** - Add keystore configuration
7. **Update metatype.xml** - Add configuration properties
8. **Update LTPAKeyCreateTask.java** - Create keystore on startup
9. **Add message keys** - For logging and errors
10. **Test** - Verify keystore creation and key loading
11. **Test Migration** - Verify .keys to keystore migration

## Key Differences from Previous Attempt

| Aspect | Previous Attempt | New Approach |
|--------|-----------------|--------------|
| Certificate Generation | Used sun.security.x509 | No certificates needed |
| Certificate Chain | Generated self-signed certs | Use null certificate chain |
| Dependencies | Required BouncyCastle | Standard Java only |
| Complexity | High (cert generation) | Low (direct key storage) |
| Compatibility | Unknown | Proven in tWAS |

## Testing Strategy

1. **Unit Tests**
   - Test keystore creation with valid keys
   - Test key loading from keystore
   - Test migration from .keys to keystore

2. **Integration Tests**
   - Start Liberty with keystore configuration
   - Verify LTPA tokens work correctly
   - Test SSO between servers using keystores

3. **Compatibility Tests**
   - Verify tWAS keystore can be read by Liberty
   - Verify Liberty keystore can be read by tWAS
   - Test mixed environment (some .keys, some keystores)

## Security Considerations

1. **Keystore Password Protection**
   - Use Liberty's password encryption
   - Support password from environment variables
   - Support password from external files

2. **File Permissions**
   - Ensure keystore file has restricted permissions
   - Log warnings if permissions are too open

3. **Key Rotation**
   - Support creating new keystores with new keys
   - Maintain backward compatibility during rotation

## Documentation Updates

1. Update Liberty documentation for keystore configuration
2. Create migration guide from .keys to keystore
3. Document tWAS compatibility
4. Add troubleshooting section

## References

- tWAS Implementation: `/Users/utle/wasbld/WAS90.SERV1-f5282615.03/SERV1/ws/code/security.impl/src/com/ibm/ws/security/ltpa/`
- Analysis Document: `LTPA_KEYSTORE_TWAS_ANALYSIS.md`
- Java KeyStore API: https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyStore.html