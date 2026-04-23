# LTPA Keystore Design Specification for Open Liberty

## Executive Summary

This document specifies the design for implementing LTPA key storage in **dedicated PKCS12 keystores** for Open Liberty.

**CRITICAL DESIGN PRINCIPLES**:
1. **Primary LTPA Keystore**: Contains only primary LTPA keys (separate keystore)
2. **Validation LTPA Keystore**: Contains ALL validation keys with indexed aliases (separate keystore)
3. **SSL Keystore**: Contains SSL certificates (completely separate)
4. **No Mixing**: Either use `.keys` files OR keystores - NOT both in same environment
5. **Automatic Migration**: Configurable one-time migration from `.keys` to keystores on server startup

## Keystore Architecture

### Three-Keystore Model

| Keystore | Purpose | File | Contains |
|----------|---------|------|----------|
| **Primary LTPA** | Primary LTPA keys only | `ltpa.p12` | 3 keys: secret, private, public |
| **Validation LTPA** | ALL validation keys | `ltpa_validation.p12` | N sets of 3 keys each (indexed) |
| **SSL** | SSL certificates | `key.p12` | SSL certs (SEPARATE) |

### Primary LTPA Keystore Structure

**File**: `ltpa.p12`

| Alias | Type | Content |
|-------|------|---------|
| `ltpaSecretKey` | SecretKey | 3DES shared secret (168-bit) |
| `ltpaPrivateKey` | PrivateKey | RSA private key (2048-bit) |
| `ltpaPublicKey` | Certificate | X.509 cert with RSA public key |

### Validation LTPA Keystore Structure

**File**: `ltpa_validation.p12` (ONE keystore for ALL validation keys)

| Alias | Type | Content |
|-------|------|---------|
| `ltpaSecretKey_1` | SecretKey | Validation set 1 - 3DES key |
| `ltpaPrivateKey_1` | PrivateKey | Validation set 1 - RSA private |
| `ltpaPublicKey_1` | Certificate | Validation set 1 - RSA public |
| `ltpaSecretKey_2` | SecretKey | Validation set 2 - 3DES key |
| `ltpaPrivateKey_2` | PrivateKey | Validation set 2 - RSA private |
| `ltpaPublicKey_2` | Certificate | Validation set 2 - RSA public |
| ... | ... | ... |
| `ltpaSecretKey_N` | SecretKey | Validation set N - 3DES key |
| `ltpaPrivateKey_N` | PrivateKey | Validation set N - RSA private |
| `ltpaPublicKey_N` | Certificate | Validation set N - RSA public |

## Configuration Examples

### Keystore-Based Configuration (Recommended)

```xml
<!-- Primary LTPA Keystore -->
<keyStore id="ltpaKeyStore" 
          location="${server.output.dir}/resources/security/ltpa.p12"
          type="PKCS12" 
          password="{xor}Lz4sLCgwLTs=" />

<!-- Validation LTPA Keystore -->
<keyStore id="ltpaValidationKeyStore" 
          location="${server.output.dir}/resources/security/ltpa_validation.p12"
          type="PKCS12" 
          password="{xor}Lz4sLCgwLTs=" />

<!-- SSL Keystore (separate) -->
<keyStore id="defaultKeyStore"
          location="${server.output.dir}/resources/security/key.p12"
          type="PKCS12"
          password="{xor}Lz4sLCgwLTs=" />

<ltpa keysFileName="ltpaKeyStore" 
      validationKeysFileName="ltpaValidationKeyStore"
      expiration="120m" />
```

### With Validation Key Metadata

```xml
<ltpa keysFileName="ltpaKeyStore" 
      validationKeysFileName="ltpaValidationKeyStore"
      expiration="120m">
    <validationKeys index="1" validUntilDate="2027-12-31T23:59:59Z" />
    <validationKeys index="2" validUntilDate="2028-12-31T23:59:59Z" />
</ltpa>
```

### Legacy .keys File Configuration

```xml
<ltpa keysFileName="${server.output.dir}/resources/security/ltpa.keys"
      keysPassword="{xor}Lz4sLCgwLTs="
      expiration="120m">
    <validationKeys fileName="${server.output.dir}/resources/security/ltpa_validation_1.keys"
                    password="{xor}Lz4sLCgwLTs=" />
</ltpa>
```

## Automatic Migration from .keys to Keystores

### Enable Automatic Migration

Add `autoMigrate="true"` to enable one-time automatic migration:

```xml
<!-- Define target keystores -->
<keyStore id="ltpaKeyStore" 
          location="${server.output.dir}/resources/security/ltpa.p12"
          type="PKCS12" 
          password="{xor}Lz4sLCgwLTs=" />

<keyStore id="ltpaValidationKeyStore" 
          location="${server.output.dir}/resources/security/ltpa_validation.p12"
          type="PKCS12" 
          password="{xor}Lz4sLCgwLTs=" />

<!-- Enable automatic migration -->
<ltpa keysFileName="${server.output.dir}/resources/security/ltpa.keys"
      keysPassword="{xor}Lz4sLCgwLTs="
      autoMigrate="true"
      migrateToKeystore="ltpaKeyStore"
      migrateValidationToKeystore="ltpaValidationKeyStore"
      expiration="120m">
    <validationKeys fileName="${server.output.dir}/resources/security/ltpa_validation_1.keys"
                    password="{xor}Lz4sLCgwLTs=" />
    <validationKeys fileName="${server.output.dir}/resources/security/ltpa_validation_2.keys"
                    password="{xor}Lz4sLCgwLTs=" />
</ltpa>
```

### Migration Process

**On server startup with `autoMigrate="true"`**:

1. Server checks if target keystores exist
2. If keystores DON'T exist:
   - Reads primary keys from `ltpa.keys`
   - Creates `ltpa.p12` with standard aliases
   - Reads all validation `.keys` files
   - Creates `ltpa_validation.p12` with indexed aliases (_1, _2, etc.)
   - Backs up original files as `.keys.backup`
   - Logs: `CWWKS4146I: Successfully migrated LTPA keys...`
3. If keystores ALREADY exist:
   - Skips migration (already done)
   - Logs: `CWWKS4147I: Automatic migration skipped...`
   - Uses existing keystores

### After Migration

Update `server.xml` to remove migration settings:

```xml
<!-- Remove autoMigrate and .keys references -->
<ltpa keysFileName="ltpaKeyStore" 
      validationKeysFileName="ltpaValidationKeyStore"
      expiration="120m">
    <validationKeys index="1" validUntilDate="2027-12-31T23:59:59Z" />
    <validationKeys index="2" validUntilDate="2028-12-31T23:59:59Z" />
</ltpa>
```

### Migration Safety

- **Idempotent**: Only migrates once (checks if keystores exist)
- **Backup**: Original `.keys` files saved as `.keys.backup`
- **Validation**: Keystores validated after creation
- **Logging**: Clear messages about migration status
- **Rollback**: Keep `.keys.backup` files for rollback

## Implementation Components

### 1. LTPAKeystoreManager (New Class)

```java
public class LTPAKeystoreManager {
    // Alias constants
    private static final String LTPA_SECRET_KEY_ALIAS = "ltpaSecretKey";
    private static final String LTPA_PRIVATE_KEY_ALIAS = "ltpaPrivateKey";
    private static final String LTPA_PUBLIC_KEY_ALIAS = "ltpaPublicKey";
    private static final String LTPA_SECRET_KEY_PATTERN = "ltpaSecretKey_%d";
    private static final String LTPA_PRIVATE_KEY_PATTERN = "ltpaPrivateKey_%d";
    private static final String LTPA_PUBLIC_KEY_PATTERN = "ltpaPublicKey_%d";
    
    // Load primary keys from keystore
    public LTPAKeys loadPrimaryKeysFromKeystore(String keystoreId, byte[] password);
    
    // Store primary keys to keystore
    public void storePrimaryKeysToKeystore(String keystoreId, byte[] password, LTPAKeys keys);
    
    // Load ALL validation keys from validation keystore
    public Map<Integer, LTPAKeys> loadValidationKeysFromKeystore(String keystoreId, byte[] password);
    
    // Store validation key set with index
    public void storeValidationKeysToKeystore(String keystoreId, byte[] password, int index, LTPAKeys keys);
    
    // Automatic migration
    public void performAutoMigration(String primaryKeysFile, byte[] primaryPassword,
                                     List<String> validationFiles, List<byte[]> validationPasswords,
                                     String primaryKeystoreId, String validationKeystoreId);
}
```

### 2. LTPAKeyInfoManager Updates

```java
public class LTPAKeyInfoManager {
    private LTPAKeystoreManager ltpaKeystoreManager;
    
    private LTPAKeys loadPrimaryKeys(String keysFileName, byte[] password) {
        if (ltpaKeystoreManager.isKeystoreReference(keysFileName)) {
            return ltpaKeystoreManager.loadPrimaryKeysFromKeystore(keysFileName, password);
        } else {
            return loadFromKeysFile(keysFileName, password);
        }
    }
    
    private Map<Integer, LTPAKeys> loadValidationKeys(
            String validationKeysFileName, 
            byte[] password,
            List<Properties> validationKeysMetadata) {
        
        boolean usingKeystore = (validationKeysFileName != null && 
            ltpaKeystoreManager.isKeystoreReference(validationKeysFileName));
        boolean usingFiles = (validationKeysMetadata != null && !validationKeysMetadata.isEmpty());
        
        // Validate: cannot use both
        if (usingKeystore && usingFiles) {
            throw new IllegalStateException("Cannot mix keystore and .keys files");
        }
        
        if (usingKeystore) {
            return ltpaKeystoreManager.loadValidationKeysFromKeystore(validationKeysFileName, password);
        } else {
            return loadValidationKeysFromFiles(validationKeysMetadata);
        }
    }
}
```

### 3. LTPAConfigurationImpl Updates

```java
public class LTPAConfigurationImpl implements LTPAConfiguration {
    private String primaryKeyImportFile;
    @Sensitive
    private String primaryKeyPassword;
    
    private String validationKeysFileName;
    @Sensitive
    private String validationKeysPassword;
    
    // Auto-migration settings
    private boolean autoMigrate = false;
    private String migrateToKeystore;
    private String migrateValidationToKeystore;
    
    private List<Properties> validationKeysMetadata;
    
    @Activate
    protected void activate(ComponentContext cc, Map<String, Object> properties) {
        // Check for auto-migration
        if (autoMigrate && migrateToKeystore != null) {
            performAutoMigrationIfNeeded();
        }
    }
    
    private void performAutoMigrationIfNeeded() {
        // Check if target keystores already exist
        if (keystoresExist()) {
            Tr.info(tc, "LTPA_AUTO_MIGRATION_SKIPPED", migrateToKeystore, migrateValidationToKeystore);
            return;
        }
        
        // Perform migration
        Tr.info(tc, "LTPA_AUTO_MIGRATION_START");
        ltpaKeystoreManager.performAutoMigration(
            primaryKeyImportFile, primaryKeyPassword,
            validationFiles, validationPasswords,
            migrateToKeystore, migrateValidationToKeystore);
        Tr.info(tc, "LTPA_AUTO_MIGRATION_SUCCESS", migrateToKeystore, migrateValidationToKeystore, validationCount);
    }
}
```

## Metatype Configuration

```xml
<OCD id="com.ibm.ws.security.token.ltpa.configuration" 
     name="%ltpa.token.config" 
     description="%ltpa.token.config.desc"
     ibm:alias="ltpa">
     
    <AD id="keysFileName" name="%keysFileName" description="%keysFileName.desc"
        required="false" type="String" 
        default="${server.output.dir}/resources/security/ltpa.keys" />
    
    <AD id="keysPassword" name="%keysPassword" description="%keysPassword.desc"
        required="false" type="String" ibm:type="password" />
    
    <AD id="validationKeysFileName" name="%validationKeysFileName" 
        description="%validationKeysFileName.desc"
        required="false" type="String" />
    
    <AD id="validationKeysPassword" name="%validationKeysPassword" 
        description="%validationKeysPassword.desc"
        required="false" type="String" ibm:type="password" />
    
    <!-- Auto-migration settings -->
    <AD id="autoMigrate" name="%autoMigrate" 
        description="%autoMigrate.desc"
        required="false" type="Boolean" default="false" />
    
    <AD id="migrateToKeystore" name="%migrateToKeystore" 
        description="%migrateToKeystore.desc"
        required="false" type="String" />
    
    <AD id="migrateValidationToKeystore" name="%migrateValidationToKeystore" 
        description="%migrateValidationToKeystore.desc"
        required="false" type="String" />
    
    <AD id="expiration"  name="%expiration" description="%expiration.desc"
        required="false" type="String" ibm:type="duration(m)" default="120m" />
    
    <AD id="validationKeys" ibm:type="pid" 
        ibm:reference="com.ibm.ws.security.token.ltpa.validationKeys" 
        required="false" type="String" ibm:flat="true" cardinality="2147483647"/>
</OCD>
```

## Message Bundle

```properties
autoMigrate=Auto-migrate to keystore
autoMigrate.desc=Automatically migrate LTPA keys from .keys files to keystores on server startup. This is a one-time operation. After migration completes, update the configuration to remove this setting and the .keys file references.

migrateToKeystore=Primary keystore for migration
migrateToKeystore.desc=The ID of the keystore to migrate primary LTPA keys to. Required when autoMigrate is true. The keystore will be created if it does not exist.

migrateValidationToKeystore=Validation keystore for migration
migrateValidationToKeystore.desc=The ID of the keystore to migrate validation LTPA keys to. Required when autoMigrate is true and validation keys exist. The keystore will be created if it does not exist.
```

## Error Messages

```properties
LTPA_MIXED_CONFIG_ERROR=CWWKS4140E: Cannot mix keystore and .keys file formats. Primary keys use [{0}] and validation keys use [{1}]. Use either all keystores or all .keys files.

LTPA_AUTO_MIGRATION_START=CWWKS4145I: Starting automatic migration of LTPA keys from .keys files to keystores.

LTPA_AUTO_MIGRATION_SUCCESS=CWWKS4146I: Successfully migrated LTPA keys to keystores. Primary: [{0}], Validation: [{1}] with [{2}] key sets. Original .keys files backed up.

LTPA_AUTO_MIGRATION_SKIPPED=CWWKS4147I: Automatic migration skipped. Target keystores already exist: Primary [{0}], Validation [{1}].

LTPA_AUTO_MIGRATION_ERROR=CWWKS4148E: Failed to automatically migrate LTPA keys. Exception: {0}

LTPA_AUTO_MIGRATION_CONFIG_ERROR=CWWKS4149E: Auto-migration enabled but required configuration missing. Need: autoMigrate=true, migrateToKeystore, and source .keys files.
```

## Security Considerations

### Keystore Separation

1. **Primary LTPA Keystore**: Only primary keys (no index)
2. **Validation LTPA Keystore**: Only validation keys (indexed)
3. **SSL Keystore**: Only SSL certificates
4. **No Mixing**: Each keystore has one purpose

### Password Management

**Password Resolution Order**:

For Primary Keys:
1. `password` in `<keyStore id="ltpaKeyStore">`
2. `keysPassword` in `<ltpa>`
3. `ltpa_keys_password` environment variable
4. `keystore_password` environment variable

For Validation Keys:
1. `password` in `<keyStore id="ltpaValidationKeyStore">`
2. `validationKeysPassword` in `<ltpa>`
3. Primary keys password (fallback)

## Testing Strategy

### Unit Tests

1. **LTPAKeystoreManagerTest**:
   - Load/store primary keys
   - Load/store validation keys with indexing
   - Auto-migration logic
   - Idempotent migration

2. **Configuration Validation Tests**:
   - Detect mixing of keystores and .keys files
   - Validate auto-migration configuration

### Functional Tests (FAT)

1. **Auto-Migration Tests**:
   - First startup: migration occurs
   - Second startup: migration skipped
   - Verify indexed aliases
   - Verify backup files

2. **Configuration Tests**:
   - Keystore-only configuration
   - .keys-only configuration
   - Reject mixed configurations

## Implementation Phases

### Phase 1: Core Infrastructure (Weeks 1-2)
- Implement `LTPAKeystoreManager`
- Add KeyStoreService integration
- Support indexed validation keys

### Phase 2: Auto-Migration (Weeks 3-4)
- Implement auto-migration logic
- Add configuration validation
- Update metatype definitions

### Phase 3: Testing (Weeks 5-6)
- Unit tests
- FAT tests
- Migration scenarios

### Phase 4: Review (Week 7)
- Code review
- Security review
- Documentation

## Success Criteria

✅ Primary LTPA keys in dedicated keystore  
✅ ALL validation keys in single keystore with indexed aliases  
✅ Complete separation from SSL keystores  
✅ NO mixing of keystores and .keys files  
✅ Automatic one-time migration with `autoMigrate="true"`  
✅ Idempotent migration (only runs once)  
✅ FIPS compliant  
✅ >80% test coverage  

## Summary

This design provides a secure LTPA key storage solution with:

1. **Two Dedicated LTPA Keystores**: Primary and validation (indexed)
2. **No Mixing**: Either all keystores OR all .keys files
3. **Automatic Migration**: One-time migration with `autoMigrate="true"`
4. **Separation**: LTPA keystores separate from SSL
5. **Backward Compatible**: Continue supporting .keys files
6. **Secure**: FIPS compliant, proper password management