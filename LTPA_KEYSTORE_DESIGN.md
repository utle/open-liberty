# Design: LTPA Keys in Keystore

## Executive Summary

This design proposes integrating LTPA (Lightweight Third Party Authentication) keys into Open Liberty's keystore infrastructure instead of storing them in separate flat files. This enhancement will improve security, simplify key management, and provide better integration with existing SSL/TLS infrastructure.

## Current Architecture Analysis

### Current LTPA Key Storage

**File-Based Storage:**
- LTPA keys are currently stored in properties files (default: `${server.output.dir}/resources/security/ltpa.keys`)
- Keys are encrypted using a password (from `keysPassword` config or environment variables)
- Three key types stored:
  - `com.ibm.websphere.ltpa.3DESKey` - Secret key for token encryption
  - `com.ibm.websphere.ltpa.PrivateKey` - RSA private key for signing
  - `com.ibm.websphere.ltpa.PublicKey` - RSA public key for verification

**Key Components:**
- [`LTPAKeyInfoManager`](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeyInfoManager.java) - Manages loading/storing LTPA keys
- [`LTPAConfigurationImpl`](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAConfigurationImpl.java) - Configuration management
- [`LTPAConfiguration`](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAConfiguration.java) - Configuration interface

**Password Resolution Order:**
1. `keysPassword` attribute in server.xml
2. `ltpa_keys_password` environment variable
3. `keystore_password` environment variable (with re-encryption support)
4. Error if none provided

### Existing Keystore Infrastructure

**KeyStore Service:**
- [`KeyStoreService`](dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/KeyStoreService.java) - Provides access to configured keystores
- Supports multiple keystore types (JKS, PKCS12, etc.)
- Manages certificates, private keys, and secret keys
- Integrated with SSL/TLS configuration

**SSL Configuration Pattern:**
- Keystores defined via `<keyStore>` elements in server.xml
- Referenced by `<ssl>` elements using `keyStoreRef` and `trustStoreRef`
- Supports key aliases for selecting specific keys

## Design Goals

1. **Security Enhancement**: Store LTPA keys in secure keystores with hardware security module (HSM) support
2. **Unified Management**: Use same keystore infrastructure as SSL/TLS certificates
3. **Backward Compatibility**: Support existing file-based configuration during transition
4. **Migration Path**: Provide tools to migrate existing LTPA keys to keystores
5. **Flexibility**: Support both keystore and file-based storage simultaneously

## Proposed Design

### Configuration Model

#### New Configuration Attributes

Add to `<ltpa>` element in server.xml:

```xml
<ltpa 
    keysFileName="ltpa.keys"                    <!-- Existing: file-based keys -->
    keysPassword="password"                      <!-- Existing: file password -->
    keyStoreRef="ltpaKeyStore"                   <!-- NEW: keystore reference -->
    keyAlias="ltpaKey"                           <!-- NEW: key alias in keystore -->
    privateKeyAlias="ltpaPrivateKey"             <!-- NEW: private key alias -->
    publicKeyAlias="ltpaPublicKey"               <!-- NEW: public key alias -->
    secretKeyAlias="ltpaSecretKey"               <!-- NEW: secret key alias -->
    useKeyStore="true"                           <!-- NEW: enable keystore mode -->
    expiration="120m" />
```

#### Example Configurations

**Option 1: Keystore-Only Mode**
```xml
<keyStore id="ltpaKeyStore" 
          location="${server.config.dir}/resources/security/ltpa.p12"
          type="PKCS12" 
          password="keystorePassword" />

<ltpa keyStoreRef="ltpaKeyStore"
      keyAlias="ltpaKey"
      useKeyStore="true"
      expiration="120m" />
```

**Option 2: Hybrid Mode (Backward Compatible)**
```xml
<keyStore id="ltpaKeyStore" 
          location="${server.config.dir}/resources/security/ltpa.p12"
          type="PKCS12" 
          password="keystorePassword" />

<ltpa keysFileName="ltpa.keys"
      keysPassword="filePassword"
      keyStoreRef="ltpaKeyStore"
      keyAlias="ltpaKey"
      useKeyStore="false"
      expiration="120m" />
```

**Option 3: Shared SSL Keystore**
```xml
<keyStore id="defaultKeyStore" 
          location="${server.config.dir}/resources/security/key.p12"
          type="PKCS12" 
          password="keystorePassword" />

<ssl id="defaultSSLConfig" 
     keyStoreRef="defaultKeyStore" 
     trustStoreRef="defaultKeyStore" />

<ltpa keyStoreRef="defaultKeyStore"
      secretKeyAlias="ltpaSecret"
      privateKeyAlias="ltpaPrivate"
      publicKeyAlias="ltpaPublic"
      useKeyStore="true"
      expiration="120m" />
```

### Architecture Changes

#### Component Modifications

**1. LTPAConfiguration Interface**

Add new methods to [`LTPAConfiguration`](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAConfiguration.java):

```java
public interface LTPAConfiguration {
    // Existing methods...
    
    // NEW: Keystore integration
    String getKeyStoreRef();
    String getKeyAlias();
    String getPrivateKeyAlias();
    String getPublicKeyAlias();
    String getSecretKeyAlias();
    boolean isUseKeyStore();
    boolean isHybridMode();
}
```

**2. LTPAConfigurationImpl**

Modify [`LTPAConfigurationImpl`](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAConfigurationImpl.java):

```java
public class LTPAConfigurationImpl implements LTPAConfiguration {
    // Existing fields...
    
    // NEW: Keystore support
    private String keyStoreRef;
    private String keyAlias;
    private String privateKeyAlias;
    private String publicKeyAlias;
    private String secretKeyAlias;
    private boolean useKeyStore;
    
    // NEW: Service reference
    private final AtomicServiceReference<KeyStoreService> keyStoreServiceRef = 
        new AtomicServiceReference<>("keyStoreService");
    
    @Reference(name = "keyStoreService", 
               service = KeyStoreService.class,
               cardinality = ReferenceCardinality.OPTIONAL)
    protected void setKeyStoreService(ServiceReference<KeyStoreService> ref) {
        keyStoreServiceRef.setReference(ref);
    }
    
    protected void unsetKeyStoreService(ServiceReference<KeyStoreService> ref) {
        keyStoreServiceRef.unsetReference(ref);
    }
}
```

**3. LTPAKeyInfoManager**

Enhance [`LTPAKeyInfoManager`](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeyInfoManager.java):

```java
public class LTPAKeyInfoManager {
    // Existing fields...
    
    // NEW: Keystore support
    private KeyStoreService keyStoreService;
    
    /**
     * Load LTPA keys from keystore
     */
    public synchronized void prepareLTPAKeyInfoFromKeyStore(
            String keyStoreRef,
            String secretKeyAlias,
            String privateKeyAlias, 
            String publicKeyAlias,
            char[] keyPassword) throws Exception {
        
        if (keyStoreService == null) {
            throw new IllegalStateException("KeyStoreService not available");
        }
        
        // Load secret key
        SecretKey secretKey = keyStoreService.getSecretKeyFromKeyStore(
            keyStoreRef, secretKeyAlias, keyPassword);
        
        // Load private key
        PrivateKey privateKey = (PrivateKey) keyStoreService.getPrivateKeyFromKeyStore(
            keyStoreRef, privateKeyAlias, keyPassword);
        
        // Load public key from certificate
        Certificate cert = keyStoreService.getCertificateFromKeyStore(
            keyStoreRef, publicKeyAlias);
        PublicKey publicKey = cert.getPublicKey();
        
        // Cache keys
        String cacheKey = keyStoreRef + ":" + secretKeyAlias;
        this.keyCache.put(cacheKey + SECRETKEY, secretKey.getEncoded());
        this.keyCache.put(cacheKey + PRIVATEKEY, privateKey.getEncoded());
        this.keyCache.put(cacheKey + PUBLICKEY, publicKey.getEncoded());
        
        // Store realm (could be from certificate DN or config)
        this.realmCache.put(cacheKey, extractRealmFromCertificate(cert));
    }
    
    /**
     * Hybrid mode: Try keystore first, fall back to file
     */
    public synchronized void prepareLTPAKeyInfoHybrid(
            WsLocationAdmin locService,
            String keyImportFile,
            byte[] filePassword,
            String keyStoreRef,
            String keyAlias,
            char[] keystorePassword) throws Exception {
        
        try {
            if (keyStoreRef != null && keyStoreService != null) {
                prepareLTPAKeyInfoFromKeyStore(
                    keyStoreRef, keyAlias, keyAlias, keyAlias, keystorePassword);
                return;
            }
        } catch (Exception e) {
            Tr.warning(tc, "LTPA_KEYSTORE_LOAD_FAILED", keyStoreRef, e.getMessage());
        }
        
        // Fall back to file-based
        prepareLTPAKeyInfo(locService, keyImportFile, filePassword, null, false);
    }
}
```

**4. New KeyStoreService Methods**

Extend [`KeyStoreService`](dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/KeyStoreService.java):

```java
public interface KeyStoreService {
    // Existing methods...
    
    /**
     * Get a secret key from the keystore
     */
    SecretKey getSecretKeyFromKeyStore(String keyStoreName, String alias, char[] password) 
        throws KeyStoreException;
    
    /**
     * Get a private key from the keystore
     */
    Key getPrivateKeyFromKeyStore(String keyStoreName, String alias, char[] password) 
        throws KeyStoreException;
    
    /**
     * Store a secret key in the keystore
     */
    void setSecretKeyEntry(String keyStoreName, String alias, SecretKey key, char[] password) 
        throws KeyStoreException;
    
    /**
     * Get the underlying KeyStore instance
     */
    KeyStore getKeyStore(String keyStoreName) throws KeyStoreException;
}
```

### Key Storage Format in Keystore

**PKCS12 Keystore Structure:**
```
ltpa.p12
├── ltpaSecretKey (SecretKeyEntry)
│   └── 3DES key for token encryption
├── ltpaPrivateKey (PrivateKeyEntry)
│   ├── RSA private key for signing
│   └── Certificate chain
└── ltpaPublicKey (TrustedCertificateEntry)
    └── RSA public key certificate
```

**Alternative: Single Entry with Multiple Keys**
```
ltpa.p12
└── ltpaKey (PrivateKeyEntry)
    ├── RSA private key
    ├── Certificate (contains public key)
    └── Attributes:
        └── secretKey: 3DES key (stored as key attribute)
```

### Migration Strategy

#### Phase 1: Add Keystore Support (Backward Compatible)

1. Add new configuration attributes to `<ltpa>` element
2. Implement keystore loading in `LTPAKeyInfoManager`
3. Default behavior: use file-based keys (existing behavior)
4. When `useKeyStore="true"`: use keystore
5. Support hybrid mode for gradual migration

#### Phase 2: Migration Tool

Create a command-line utility to migrate existing LTPA keys:

```bash
# Migrate LTPA keys from file to keystore
securityUtility migrateLTPAKeys \
    --ltpaKeysFile=/path/to/ltpa.keys \
    --ltpaKeysPassword=filePassword \
    --keyStore=/path/to/ltpa.p12 \
    --keyStorePassword=keystorePassword \
    --keyStoreType=PKCS12 \
    --keyAlias=ltpaKey
```

**Migration Tool Implementation:**

```java
public class LTPAKeyMigrationTool {
    public void migrateLTPAKeys(
            String ltpaKeysFile,
            String ltpaKeysPassword,
            String keyStorePath,
            String keyStorePassword,
            String keyStoreType,
            String keyAlias) throws Exception {
        
        // 1. Load existing LTPA keys from file
        Properties props = loadLTPAKeysFile(ltpaKeysFile);
        byte[][] keys = decryptKeys(
            ltpaKeysPassword.getBytes(),
            props.getProperty("com.ibm.websphere.ltpa.3DESKey"),
            props.getProperty("com.ibm.websphere.ltpa.PrivateKey"),
            props.getProperty("com.ibm.websphere.ltpa.PublicKey")
        );
        
        // 2. Create or load keystore
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        File ksFile = new File(keyStorePath);
        if (ksFile.exists()) {
            try (FileInputStream fis = new FileInputStream(ksFile)) {
                keyStore.load(fis, keyStorePassword.toCharArray());
            }
        } else {
            keyStore.load(null, keyStorePassword.toCharArray());
        }
        
        // 3. Store secret key
        SecretKey secretKey = new SecretKeySpec(keys[0], "DESede");
        keyStore.setEntry(
            keyAlias + "Secret",
            new KeyStore.SecretKeyEntry(secretKey),
            new KeyStore.PasswordProtection(keyStorePassword.toCharArray())
        );
        
        // 4. Store private key and certificate
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(
            new PKCS8EncodedKeySpec(keys[1]));
        PublicKey publicKey = keyFactory.generatePublic(
            new X509EncodedKeySpec(keys[2]));
        
        // Generate self-signed certificate for public key
        X509Certificate cert = generateSelfSignedCertificate(
            privateKey, publicKey, 
            props.getProperty("com.ibm.websphere.ltpa.Realm", "defaultRealm"));
        
        keyStore.setKeyEntry(
            keyAlias + "Private",
            privateKey,
            keyStorePassword.toCharArray(),
            new Certificate[] { cert }
        );
        
        // 5. Save keystore
        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            keyStore.store(fos, keyStorePassword.toCharArray());
        }
        
        System.out.println("LTPA keys successfully migrated to keystore: " + keyStorePath);
    }
}
```

#### Phase 3: Deprecation (Future)

1. Mark file-based configuration as deprecated
2. Provide migration warnings in logs
3. Eventually remove file-based support (major version update)

### Security Considerations

#### Enhanced Security Features

1. **Hardware Security Module (HSM) Support**
   - Keystores can be backed by HSMs (PKCS11)
   - LTPA keys never leave secure hardware
   - Example configuration:
   ```xml
   <keyStore id="hsmKeyStore" 
             type="PKCS11"
             provider="SunPKCS11"
             location="/path/to/pkcs11.cfg" />
   ```

2. **Key Rotation**
   - Easier key rotation using keystore tools
   - Support multiple key versions with different aliases
   - Validation keys can reference different keystore entries

3. **Access Control**
   - Leverage OS-level keystore permissions
   - Separate keystores for different security domains
   - Integration with enterprise key management systems

4. **Audit Trail**
   - Keystore access can be audited
   - Integration with security event logging
   - Track key usage and modifications

#### Password Management

**Priority Order (Enhanced):**
1. `keysPassword` attribute (for file-based)
2. Keystore password from `<keyStore>` element
3. `ltpa_keys_password` environment variable
4. `keystore_password` environment variable
5. Shared password from SSL configuration

**Security Best Practices:**
- Use encoded passwords (`{xor}`, `{aes}`)
- Leverage `securityUtility encode` command
- Support password aliases for centralized management

### Validation Keys Support

**Current:** Validation keys stored in separate files
**Enhanced:** Validation keys in same or different keystores

```xml
<ltpa keyStoreRef="primaryKeyStore"
      keyAlias="currentLTPAKey"
      useKeyStore="true">
    
    <validationKeys keyStoreRef="primaryKeyStore"
                    keyAlias="previousLTPAKey"
                    validUntilDate="2026-12-31T23:59:59Z" />
    
    <validationKeys keyStoreRef="partnerKeyStore"
                    keyAlias="partnerLTPAKey"
                    validUntilDate="2027-06-30T23:59:59Z" />
</ltpa>
```

### Error Handling

**Configuration Validation:**
- Validate keystore exists and is accessible
- Verify key aliases exist in keystore
- Check key types match requirements (3DES, RSA)
- Provide clear error messages for misconfigurations

**Runtime Handling:**
- Graceful fallback to file-based if keystore unavailable
- Retry logic for transient keystore access failures
- Detailed logging for troubleshooting

**Error Messages:**
```
CWWKS4110E: The LTPA keystore [{0}] could not be accessed. Verify the keystore exists and the password is correct.
CWWKS4111E: The LTPA key alias [{0}] was not found in keystore [{1}].
CWWKS4112E: The key [{0}] in keystore [{1}] is not the correct type. Expected [{2}], found [{3}].
CWWKS4113W: Failed to load LTPA keys from keystore [{0}]. Falling back to file-based keys.
```

### Performance Considerations

1. **Caching**: Cache loaded keys in memory (existing behavior)
2. **Lazy Loading**: Load keys only when needed
3. **Connection Pooling**: Reuse keystore connections for HSMs
4. **Monitoring**: Track keystore access performance metrics

### Testing Strategy

#### Unit Tests
- Test keystore loading with various configurations
- Test migration tool with different key formats
- Test error handling and fallback scenarios
- Test password resolution priority

#### Integration Tests
- Test with PKCS12, JKS, and PKCS11 keystores
- Test hybrid mode (keystore + file)
- Test validation keys from multiple keystores
- Test key rotation scenarios

#### Security Tests
- Verify keys are properly protected
- Test HSM integration
- Verify audit logging
- Test access control

### Documentation Requirements

1. **Configuration Guide**
   - How to configure LTPA with keystores
   - Migration from file-based to keystore
   - Best practices for key management

2. **Security Guide**
   - HSM integration instructions
   - Key rotation procedures
   - Access control recommendations

3. **Troubleshooting Guide**
   - Common configuration errors
   - Debugging keystore access issues
   - Performance tuning

4. **API Documentation**
   - New configuration attributes
   - KeyStoreService extensions
   - Migration tool usage

## Implementation Plan

### Phase 1: Foundation (Sprint 1-2)
- [ ] Add new configuration attributes to LTPA metatype
- [ ] Extend `LTPAConfiguration` interface
- [ ] Implement `KeyStoreService` extensions
- [ ] Add keystore loading to `LTPAKeyInfoManager`
- [ ] Unit tests for keystore loading

### Phase 2: Integration (Sprint 3-4)
- [ ] Implement hybrid mode support
- [ ] Add configuration validation
- [ ] Implement error handling and fallback
- [ ] Integration tests
- [ ] Performance testing

### Phase 3: Migration Tool (Sprint 5)
- [ ] Implement `securityUtility migrateLTPAKeys` command
- [ ] Add migration validation
- [ ] Create migration documentation
- [ ] Test migration scenarios

### Phase 4: Validation Keys (Sprint 6)
- [ ] Extend validation keys to support keystores
- [ ] Test multi-keystore scenarios
- [ ] Document validation key configuration

### Phase 5: Documentation & Release (Sprint 7)
- [ ] Complete user documentation
- [ ] Create migration guide
- [ ] Security best practices guide
- [ ] Release notes

## Backward Compatibility

**Guaranteed Compatibility:**
- Existing file-based configurations continue to work
- No changes required for existing deployments
- Opt-in model for keystore support

**Migration Path:**
- Hybrid mode allows gradual migration
- Migration tool automates key transfer
- Clear documentation for migration process

## Future Enhancements

1. **Automatic Key Rotation**
   - Scheduled key rotation
   - Automatic validation key management
   - Zero-downtime key updates

2. **Cloud Key Management Integration**
   - AWS KMS integration
   - Azure Key Vault integration
   - Google Cloud KMS integration

3. **Certificate-Based LTPA**
   - Use X.509 certificates for LTPA tokens
   - PKI integration
   - Certificate revocation support

4. **Key Escrow**
   - Backup and recovery procedures
   - Key archival for compliance
   - Disaster recovery support

## Conclusion

This design provides a comprehensive approach to integrating LTPA keys into Open Liberty's keystore infrastructure. The phased implementation ensures backward compatibility while providing a clear migration path. The enhanced security features, including HSM support and improved key management, will significantly improve the security posture of LTPA-based authentication in Open Liberty.

## References

- [LTPAConfiguration.java](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAConfiguration.java)
- [LTPAConfigurationImpl.java](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security.token.ltpa/internal/LTPAConfigurationImpl.java)
- [LTPAKeyInfoManager.java](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeyInfoManager.java)
- [KeyStoreService.java](dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/KeyStoreService.java)
- Open Liberty Security Documentation
- Java KeyStore API Documentation
- PKCS#11 Cryptographic Token Interface Standard