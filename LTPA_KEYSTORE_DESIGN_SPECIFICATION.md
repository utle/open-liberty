# LTPA Keystore Design Specification for Open Liberty

## Executive Summary

This document specifies the design for implementing LTPA key storage in **dedicated PKCS12 keystores** for Open Liberty. 

**CRITICAL DESIGN**:
- **Primary LTPA Keystore**: Contains only primary LTPA keys (separate keystore)
- **Validation LTPA Keystore**: Contains ALL validation keys with indexed aliases (separate keystore)
- **SSL Keystore**: Contains SSL certificates (completely separate)

## Key Design Principles

1. **Three-Keystore Model**: Primary LTPA, Validation LTPA, and SSL keystores are separate
2. **Primary Keys**: Stored in dedicated keystore with standard aliases
3. **Validation Keys**: ALL stored in ONE keystore with indexed aliases
4. **PKCS12 Format**: Industry-standard keystore type
5. **Backward Compatible**: Continue supporting legacy `.keys` files

## Keystore Structure

### Keystore Separation Model

| Keystore | Purpose | Location | Contains |
|----------|---------|----------|----------|
| **Primary LTPA Keystore** | Primary LTPA keys only | `ltpa.p12` | Primary secret, private, public keys |
| **Validation LTPA Keystore** | ALL validation keys | `ltpa_validation.p12` | All validation keys (indexed) |
| **SSL Keystore** | SSL certificates | `key.p12` | SSL certs (SEPARATE) |
| **SSL Truststore** | Trusted CAs | `trust.p12` | CA certs (SEPARATE) |

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
| `ltpaSecretKey_N` | SecretKey | Validation set N - 3DES key |
| `ltpaPrivateKey_N` | PrivateKey | Validation set N - RSA private |
| `ltpaPublicKey_N` | Certificate | Validation set N - RSA public |

**Key Points**:
- Primary keys use standard aliases (no index)
- Validation keys use indexed aliases (_1, _2, _3, etc.)
- All validation keys in ONE keystore
- Similar to current `.keys` file approach but in keystore format

## Configuration Examples

### Basic Configuration: Primary and Validation Keystores

```xml
<!-- Primary LTPA Keystore (dedicated) -->
<keyStore id="ltpaKeyStore" 
          location="${server.output.dir}/resources/security/ltpa.p12"
          type="PKCS12" 
          password="{xor}Lz4sLCgwLTs=" />

<!-- Validation LTPA Keystore (dedicated, contains ALL validation keys) -->
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

### Configuration with Individual Validation Key Metadata

```xml
<!-- Primary LTPA Keystore -->
<keyStore id="ltpaKeyStore" 
          location="${server.output.dir}/resources/security/ltpa.p12"
          type="PKCS12" 
          password="{xor}Lz4sLCgwLTs=" />

<!-- Validation LTPA Keystore (ALL validation keys) -->
<keyStore id="ltpaValidationKeyStore" 
          location="${server.output.dir}/resources/security/ltpa_validation.p12"
          type="PKCS12" 
          password="{xor}Lz4sLCgwLTs=" />

<ltpa keysFileName="ltpaKeyStore" 
      validationKeysFileName="ltpaValidationKeyStore"
      expiration="120m">
    <!-- Metadata for validation key set 1 (stored in ltpaValidationKeyStore) -->
    <validationKeys index="1" 
                    validUntilDate="2027-12-31T23:59:59Z" />
    <!-- Metadata for validation key set 2 (stored in ltpaValidationKeyStore) -->
    <validationKeys index="2" 
                    validUntilDate="2028-12-31T23:59:59Z" />
</ltpa>
```

### Backward Compatible: Legacy .keys Files

```xml
<!-- Primary keys in legacy format -->
<ltpa keysFileName="${server.output.dir}/resources/security/ltpa.keys"
      keysPassword="{xor}Lz4sLCgwLTs="
      expiration="120m">
    <!-- Validation keys in legacy format -->
    <validationKeys fileName="${server.output.dir}/resources/security/ltpa_validation_1.keys"
                    password="{xor}Lz4sLCgwLTs="
                    validUntilDate="2027-12-31T23:59:59Z" />
</ltpa>
```

### Mixed Configuration: Primary in Keystore, Validation in .keys

```xml
<!-- Primary in keystore -->
<keyStore id="ltpaKeyStore" 
          location="${server.output.dir}/resources/security/ltpa.p12"
          type="PKCS12" 
          password="{xor}Lz4sLCgwLTs=" />

<ltpa keysFileName="ltpaKeyStore" expiration="120m">
    <!-- Validation keys still in legacy .keys files -->
    <validationKeys fileName="${server.output.dir}/resources/security/ltpa_validation_1.keys"
                    password="{xor}Lz4sLCgwLTs="
                    validUntilDate="2027-12-31T23:59:59Z" />
</ltpa>
```

## Architecture Overview

### Component Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    LTPA Configuration                        │
│                  (LTPAConfigurationImpl)                     │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ├──────────────────┬──────────────────────┐
                     │                  │                      │
         ┌───────────▼──────────┐  ┌───▼──────────┐  ┌───────▼────────┐
         │  LTPAKeyInfoManager  │  │ KeyStore     │  │  Legacy .keys  │
         │                      │  │ Service      │  │  File Support  │
         └──────────────────────┘  └──────────────┘  └────────────────┘
                     │                  │
                     │                  │
         ┌───────────▼──────────────────▼─────────────────────┐
         │         LTPAKeystoreManager                         │
         │  (New component for LTPA keystore operations)       │
         └─────────────────────────────────────────────────────┘
                     │
         ┌───────────▼──────────────────────────────────────┐
         │    Java KeyStore API (PKCS12)                     │
         │                                                    │
         │  Primary Keystore (ltpa.p12):                     │
         │    - ltpaSecretKey                                │
         │    - ltpaPrivateKey                               │
         │    - ltpaPublicKey                                │
         │                                                    │
         │  Validation Keystore (ltpa_validation.p12):       │
         │    - ltpaSecretKey_1, ltpaPrivateKey_1, ...       │
         │    - ltpaSecretKey_2, ltpaPrivateKey_2, ...       │
         │    - ltpaSecretKey_N, ltpaPrivateKey_N, ...       │
         └───────────────────────────────────────────────────┘
```

## Implementation Components

### 1. LTPAKeystoreManager (New Class)

**Location**: `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeystoreManager.java`

**Responsibilities**:
- Load LTPA keys from dedicated PKCS12 keystores
- Store LTPA keys to dedicated PKCS12 keystores
- Generate new LTPA keys and store in appropriate keystore
- Migrate from `.keys` files to keystore format
- Handle indexed validation keys in single keystore
- Integrate with `KeyStoreService`

**Key Methods**:
```java
public class LTPAKeystoreManager {
    // Primary key aliases (no index)
    private static final String LTPA_SECRET_KEY_ALIAS = "ltpaSecretKey";
    private static final String LTPA_PRIVATE_KEY_ALIAS = "ltpaPrivateKey";
    private static final String LTPA_PUBLIC_KEY_ALIAS = "ltpaPublicKey";
    
    // Validation key alias patterns (with index)
    private static final String LTPA_SECRET_KEY_PATTERN = "ltpaSecretKey_%d";
    private static final String LTPA_PRIVATE_KEY_PATTERN = "ltpaPrivateKey_%d";
    private static final String LTPA_PUBLIC_KEY_PATTERN = "ltpaPublicKey_%d";
    
    // Load primary keys from dedicated primary keystore
    public LTPAKeys loadPrimaryKeysFromKeystore(String keystoreId, 
                                                byte[] password) throws Exception;
    
    // Store primary keys to dedicated primary keystore
    public void storePrimaryKeysToKeystore(String keystoreId, 
                                          byte[] password,
                                          LTPAKeys keys) throws Exception;
    
    // Load validation keys from dedicated validation keystore
    // Returns map of index -> LTPAKeys
    public Map<Integer, LTPAKeys> loadValidationKeysFromKeystore(
                                          String keystoreId,
                                          byte[] password) throws Exception;
    
    // Store validation key set to validation keystore with index
    public void storeValidationKeysToKeystore(String keystoreId,
                                              byte[] password,
                                              int index,
                                              LTPAKeys keys) throws Exception;
    
    // Get next available index in validation keystore
    public int getNextValidationKeyIndex(String keystoreId) throws Exception;
    
    // Generate and store primary keys in dedicated keystore
    public LTPAKeys generateAndStorePrimaryKeys(String keystoreId,
                                               byte[] password,
                                               String realm) throws Exception;
    
    // Migrate primary keys from .keys file to keystore
    public void migratePrimaryKeysFromFile(String keysFile, 
                                          byte[] keysPassword,
                                          String keystoreId, 
                                          byte[] keystorePassword) throws Exception;
    
    // Migrate all validation keys from .keys files to single keystore
    public void migrateValidationKeysFromFiles(List<String> keysFiles,
                                              List<byte[]> passwords,
                                              String keystoreId,
                                              byte[] keystorePassword) throws Exception;
    
    // Check if reference is a keystore ID (not a file path)
    public boolean isKeystoreReference(String reference);
    
    // Validate that keystore contains LTPA keys (not SSL certs)
    public boolean isLTPAKeystore(String keystoreId) throws Exception;
    
    // Check if keystore is primary (no indexed keys) or validation (has indexed keys)
    public boolean isPrimaryKeystore(String keystoreId) throws Exception;
    public boolean isValidationKeystore(String keystoreId) throws Exception;
}
```

### 2. LTPAKeyInfoManager Enhancements

**Modifications**:
- Add keystore support alongside existing `.keys` file support
- Detect whether references are keystore IDs or file paths
- Delegate to `LTPAKeystoreManager` for keystore operations
- Handle validation keys from both single validation keystore and multiple `.keys` files
- Maintain backward compatibility

**Key Changes**:
```java
public class LTPAKeyInfoManager {
    private LTPAKeystoreManager ltpaKeystoreManager;
    private AtomicServiceReference<KeyStoreService> keyStoreServiceRef;
    
    // Load primary keys (from keystore or .keys file)
    private LTPAKeys loadPrimaryKeys(String keysFileName, byte[] password) {
        if (ltpaKeystoreManager.isKeystoreReference(keysFileName)) {
            // Load from primary keystore
            return ltpaKeystoreManager.loadPrimaryKeysFromKeystore(
                keysFileName, password);
        } else {
            // Load from legacy .keys file
            return loadFromKeysFile(keysFileName, password);
        }
    }
    
    // Load validation keys (from validation keystore or .keys files)
    private Map<Integer, LTPAKeys> loadValidationKeys(
            String validationKeysFileName, 
            byte[] password,
            List<Properties> validationKeysMetadata) {
        
        if (validationKeysFileName != null && 
            ltpaKeystoreManager.isKeystoreReference(validationKeysFileName)) {
            // Load ALL validation keys from single validation keystore
            return ltpaKeystoreManager.loadValidationKeysFromKeystore(
                validationKeysFileName, password);
        } else {
            // Load from individual .keys files (legacy)
            return loadValidationKeysFromFiles(validationKeysMetadata);
        }
    }
}
```

### 3. LTPAConfigurationImpl Updates

**Changes**:
- Add `KeyStoreService` reference
- Support both keystore and file-based configuration
- Add `validationKeysFileName` attribute for validation keystore
- Handle password resolution for keystores
- Support validation key metadata (index, validUntilDate)

**New Configuration Attributes**:
```java
public class LTPAConfigurationImpl implements LTPAConfiguration {
    // Existing
    private String primaryKeyImportFile;  // Can be keystore ID or file path
    @Sensitive
    private String primaryKeyPassword;
    
    // New for validation keystore
    private String validationKeysFileName;  // Keystore ID for ALL validation keys
    @Sensitive
    private String validationKeysPassword;
    
    // Validation key metadata
    private List<Properties> validationKeysMetadata;  // index, validUntilDate
    
    // KeyStoreService reference
    private final AtomicServiceReference<KeyStoreService> keyStoreServiceRef = 
        new AtomicServiceReference<KeyStoreService>("keyStoreService");
    
    @Reference(service = KeyStoreService.class, 
               name = "keyStoreService",
               policy = ReferencePolicy.DYNAMIC,
               cardinality = ReferenceCardinality.OPTIONAL)
    protected void setKeyStoreService(ServiceReference<KeyStoreService> ref) {
        keyStoreServiceRef.setReference(ref);
    }
    
    protected void unsetKeyStoreService(ServiceReference<KeyStoreService> ref) {
        keyStoreServiceRef.unsetReference(ref);
    }
}
```

### 4. Metatype Configuration Updates

**File**: `dev/com.ibm.ws.security.token.ltpa/resources/OSGI-INF/metatype/metatype.xml`

**Changes**:
```xml
<OCD id="com.ibm.ws.security.token.ltpa.configuration" 
     name="%ltpa.token.config" 
     description="%ltpa.token.config.desc"
     ibm:alias="ltpa">
     
    <!-- Primary keys: can be keystore ID or file path -->
    <AD id="keysFileName" name="%keysFileName" description="%keysFileName.desc"
        required="false" type="String" 
        default="${server.output.dir}/resources/security/ltpa.keys" />
    
    <!-- Primary keys password -->
    <AD id="keysPassword" name="%keysPassword" description="%keysPassword.desc"
        required="false" type="String" ibm:type="password" />
    
    <!-- NEW: Validation keys keystore (single keystore for ALL validation keys) -->
    <AD id="validationKeysFileName" name="%validationKeysFileName" 
        description="%validationKeysFileName.desc"
        required="false" type="String" />
    
    <!-- NEW: Validation keys password -->
    <AD id="validationKeysPassword" name="%validationKeysPassword" 
        description="%validationKeysPassword.desc"
        required="false" type="String" ibm:type="password" />
    
    <!-- Token expiration -->
    <AD id="expiration"  name="%expiration" description="%expiration.desc"
        required="false" type="String" ibm:type="duration(m)"
        default="120m" />
    
    <!-- Monitor interval -->
    <AD id="monitorInterval" name="%ltpa.monitorInterval" 
        description="%ltpa.monitorInterval.desc"
        required="false" type="String" ibm:type="duration" 
        default="0ms" />
    
    <!-- Monitor validation keys directory (for .keys files only) -->
    <AD id="monitorValidationKeysDir" name="%ltpa.monitorValidationKeysDir" 
        description="%ltpa.monitorValidationKeysDir.desc" 
        required="false" type="Boolean"
        default="false"/>
    
    <!-- Update trigger -->
    <AD id="updateTrigger" name="%ltpa.updateTrigger" 
        description="%ltpa.updateTrigger.desc" 
        required="false" type="String"
        default="polled">
        <Option label="%ltpa.updateTrigger.timed" value="polled"/>
        <Option label="%ltpa.updateTrigger.external" value="mbean"/>
        <Option label="%ltpa.updateTrigger.disabled" value="disabled"/>
    </AD>
    
    <!-- Auth filter reference -->
    <AD id="authFilterRef" name="%authFilterRef" description="%authFilterRef.desc" 
        required="false" type="String" ibm:type="pid" 
        ibm:reference="com.ibm.ws.security.authentication.filter"/>
    
    <AD id="authenticationFilter.target" name="internal" description="internal use only"
        required="false" type="String"  
        default="(service.pid=${authFilterRef})" />
    
    <AD id="expirationDifferenceAllowed" name="internal" description="internal use only"
        required="false" type="String" ibm:type="duration(ms)" 
        default="3000ms" /> 
    
    <!-- Validation keys metadata (for individual key management) -->
    <AD id="validationKeys" ibm:type="pid" 
        ibm:reference="com.ibm.ws.security.token.ltpa.validationKeys" 
        required="false" type="String" 
        ibm:flat="true" cardinality="2147483647"/>
</OCD>

<Designate pid="com.ibm.ws.security.token.ltpa.LTPAConfiguration">
    <Object ocdref="com.ibm.ws.security.token.ltpa.configuration" />
</Designate>

<!-- Validation Keys Metadata Configuration -->
<OCD id="com.ibm.ws.security.token.ltpa.validationKeys.metatype" 
     name="%validationKeys" 
     description="%validationKeys.desc">
     
    <!-- For keystore mode: index of validation key set -->
    <AD id="index" name="%validationKeyIndex" 
        description="%validationKeyIndex.desc" 
        required="false" type="Integer" />
    
    <!-- For .keys file mode: file name -->
    <AD id="fileName" name="%fileName" description="%fileName.desc" 
        required="false" type="String" />
    
    <!-- For .keys file mode: password -->
    <AD id="password" name="%password" description="%password.desc" 
        required="false" type="String" ibm:type="password" />
    
    <!-- Valid until date (applies to both modes) -->
    <AD id="validUntilDate" name="%validUntilDate" 
        description="%validUntilDate.desc" 
        required="false" type="String" />
</OCD>

<Designate factoryPid="com.ibm.ws.security.token.ltpa.validationKeys">
    <Object ocdref="com.ibm.ws.security.token.ltpa.validationKeys.metatype" />
</Designate>
```

### 5. Message Bundle Updates

**File**: `dev/com.ibm.ws.security.token.ltpa/resources/OSGI-INF/l10n/metatype.properties`

**Updated/New Messages**:
```properties
# LTPA Token Configuration
ltpa.token.config=LTPA Token
ltpa.token.config.desc=Lightweight Third Party Authentication (LTPA) token configuration.

keysFileName=Primary LTPA keys file or keystore
keysFileName.desc=The path to the file that contains the primary LTPA keys, or the ID of a keystore that contains the primary LTPA keys. LTPA keys can be stored in either a legacy .keys file or a PKCS12 keystore. When using a keystore, specify the keystore ID (not the file path). The primary keystore must be dedicated to primary LTPA keys and should not contain SSL certificates or validation keys.

keysPassword=Primary LTPA keys password
keysPassword.desc=Password for the primary LTPA keys file or keystore. If no value is specified, the 'ltpa_keys_password' or 'keystore_password' value from the ${server.config.dir}/server.env file is used if they are set. If both are set, the 'ltpa_keys_password' takes precedence. The best practice is to encrypt the password by using the securityUtility tool.

validationKeysFileName=Validation LTPA keys keystore
validationKeysFileName.desc=The ID of the keystore that contains ALL LTPA validation keys. All validation key sets are stored in this single keystore with indexed aliases (ltpaSecretKey_1, ltpaPrivateKey_1, ltpaPublicKey_1, etc.). This keystore must be dedicated to LTPA validation keys and separate from the primary LTPA keystore and SSL keystores. If not specified, validation keys can be configured using individual .keys files in the validationKeys element.

validationKeysPassword=Validation LTPA keys password
validationKeysPassword.desc=Password for the validation LTPA keys keystore. If not specified, the primary keys password is used. The best practice is to encrypt the password by using the securityUtility tool.

expiration=LTPA token expiration
expiration.desc=Amount of time after which a token expires. The value can be specified in milliseconds, seconds, and minutes by using the following suffixes: "ms", "s", and "m".

ltpa.monitorInterval=LTPA keys polling rate
ltpa.monitorInterval.desc=Rate at which the server checks for updates to the LTPA keys files or keystores. This rate applies to both the primary keys and the validation keys.

ltpa.monitorValidationKeysDir=LTPA monitor validation keys directory
ltpa.monitorValidationKeysDir.desc=If set to "true", the directory that contains LTPA primary keys is monitored for any modifications on files with the .keys suffix. This setting only applies to legacy .keys files, not keystores. All validation files must use the same password as the LTPA primary keys password and must have the .keys suffix.

ltpa.updateTrigger=LTPA keys update trigger
ltpa.updateTrigger.desc=Specifies the update method or trigger that is used to update the LTPA keys. The following values are supported: "polled", "mbean" and "disabled". The default value is "polled".
ltpa.updateTrigger.timed=The server scans for LTPA key file or keystore changes at the monitor interval and updates if the LTPA keys have any detectable changes. 
ltpa.updateTrigger.external=All the LTPA keys are reloaded when triggered by an MBean call. This is typically called by an external program, such as an integrated development environment or a management application.
ltpa.updateTrigger.disabled=This disables all update monitoring on all LTPA key files and keystores including primary key and validation keys. Changes to the LTPA keys are not applied while the server is running.

authFilterRef=Authentication Filter Reference
authFilterRef$Ref=Authentication filter reference
authFilterRef.desc=Specifies the authentication filter reference. 

validationKeys=LTPA Validation Keys
validationKeys.desc=The LTPA keys that are used only for validating existing LTPA tokens, not for creating new LTPA tokens. When using a validation keystore (validationKeysFileName), this element provides metadata for individual validation key sets (index, validUntilDate). When using legacy .keys files, this element specifies the file name and password for each validation key set.

validationKeyIndex=Validation key index
validationKeyIndex.desc=The index of the validation key set in the validation keystore. Used when validationKeysFileName is specified. The index corresponds to the suffix in the key aliases (ltpaSecretKey_1, ltpaPrivateKey_1, etc.).

fileName=LTPA validation keys file
fileName.desc=The name of the file that contains the LTPA validation keys. Used for legacy .keys file format. When using a validation keystore, use the validationKeysFileName attribute on the ltpa element instead.

password=LTPA validation keys password
password.desc=The password for the LTPA validation keys file. Used for legacy .keys file format. When using a validation keystore, use the validationKeysPassword attribute on the ltpa element instead. The best practice is to encrypt the password by using the securityUtility tool.

validUntilDate=LTPA validation keys valid until date
validUntilDate.desc=A date and time value in ISO date format that the LTPA validation key is valid until. After the specified time, the validation keys is no longer used for LTPA token validation. The following example shows the ISO date format: "2023-11-18T18:08:35Z". If no value is specified, the LTPA validation keys can be used indefinitely.
```

### 6. NLS Messages Updates

**File**: `dev/com.ibm.ws.security.token.ltpa/resources/com/ibm/ws/security/token/ltpa/internal/resources/LTPAMessages.nlsprops`

**New Messages**:
```properties
# Primary keystore messages
LTPA_PRIMARY_KEYSTORE_LOAD_ERROR=CWWKS4120E: Failed to load primary LTPA keys from keystore [{0}]. Exception: {1}
LTPA_PRIMARY_KEYSTORE_LOAD_ERROR.explanation=The primary LTPA keys could not be loaded from the specified keystore.
LTPA_PRIMARY_KEYSTORE_LOAD_ERROR.useraction=Verify that the keystore exists, is accessible, contains valid primary LTPA keys, and is not an SSL certificate keystore.

LTPA_PRIMARY_KEYSTORE_STORE_ERROR=CWWKS4121E: Failed to store primary LTPA keys to keystore [{0}]. Exception: {1}
LTPA_PRIMARY_KEYSTORE_STORE_ERROR.explanation=The primary LTPA keys could not be stored to the specified keystore.
LTPA_PRIMARY_KEYSTORE_STORE_ERROR.useraction=Verify that the keystore location is writable and the keystore password is correct.

# Validation keystore messages
LTPA_VALIDATION_KEYSTORE_LOAD_ERROR=CWWKS4122E: Failed to load validation LTPA keys from keystore [{0}]. Exception: {1}
LTPA_VALIDATION_KEYSTORE_LOAD_ERROR.explanation=The validation LTPA keys could not be loaded from the specified keystore.
LTPA_VALIDATION_KEYSTORE_LOAD_ERROR.useraction=Verify that the validation keystore exists, is accessible, and contains valid LTPA validation keys with indexed aliases.

LTPA_VALIDATION_KEYSTORE_STORE_ERROR=CWWKS4123E: Failed to store validation LTPA keys to keystore [{0}] at index [{1}]. Exception: {2}
LTPA_VALIDATION_KEYSTORE_STORE_ERROR.explanation=The validation LTPA keys could not be stored to the specified keystore.
LTPA_VALIDATION_KEYSTORE_STORE_ERROR.useraction=Verify that the keystore location is writable and the keystore password is correct.

# Migration messages
LTPA_PRIMARY_MIGRATION_START=CWWKS4124I: Migrating primary LTPA keys from file [{0}] to keystore [{1}].
LTPA_PRIMARY_MIGRATION_START.explanation=The primary LTPA keys are being migrated from the legacy .keys file format to a dedicated PKCS12 keystore.
LTPA_PRIMARY_MIGRATION_START.useraction=No action is required.

LTPA_PRIMARY_MIGRATION_SUCCESS=CWWKS4125I: Successfully migrated primary LTPA keys from file [{0}] to keystore [{1}].
LTPA_PRIMARY_MIGRATION_SUCCESS.explanation=The primary LTPA keys have been successfully migrated to the keystore format.
LTPA_PRIMARY_MIGRATION_SUCCESS.useraction=The original .keys file has been backed up. You may delete it after verifying the migration.

LTPA_PRIMARY_MIGRATION_ERROR=CWWKS4126E: Failed to migrate primary LTPA keys from file [{0}] to keystore [{1}]. Exception: {2}
LTPA_PRIMARY_MIGRATION_ERROR.explanation=An error occurred while migrating the primary LTPA keys to keystore format.
LTPA_PRIMARY_MIGRATION_ERROR.useraction=Review the exception details and ensure both the source file and target keystore are accessible.

LTPA_VALIDATION_MIGRATION_START=CWWKS4127I: Migrating validation LTPA keys from [{0}] file(s) to keystore [{1}].
LTPA_VALIDATION_MIGRATION_START.explanation=The validation LTPA keys are being migrated from legacy .keys files to a single dedicated PKCS12 keystore with indexed aliases.
LTPA_VALIDATION_MIGRATION_START.useraction=No action is required.

LTPA_VALIDATION_MIGRATION_SUCCESS=CWWKS4128I: Successfully migrated [{0}] validation LTPA key set(s) to keystore [{1}].
LTPA_VALIDATION_MIGRATION_SUCCESS.explanation=The validation LTPA keys have been successfully migrated to the keystore format.
LTPA_VALIDATION_MIGRATION_SUCCESS.useraction=The original validation .keys files have been backed up.

LTPA_VALIDATION_MIGRATION_ERROR=CWWKS4129E: Failed to migrate validation LTPA keys to keystore [{0}]. Exception: {1}
LTPA_VALIDATION_MIGRATION_ERROR.explanation=An error occurred while migrating the validation LTPA keys to keystore format.
LTPA_VALIDATION_MIGRATION_ERROR.useraction=Review the exception details and ensure both the source files and target keystore are accessible.

# Validation messages
LTPA_KEYSTORE_INVALID_REFERENCE=CWWKS4130E: The keysFileName [{0}] is neither a valid file path nor a valid keystore ID.
LTPA_KEYSTORE_INVALID_REFERENCE.explanation=The specified keysFileName could not be resolved to either a file or a configured keystore.
LTPA_KEYSTORE_INVALID_REFERENCE.useraction=Verify that the keysFileName refers to either an existing .keys file or a configured keystore ID.

LTPA_PRIMARY_KEYSTORE_MISSING_KEYS=CWWKS4131E: The primary keystore [{0}] does not contain required LTPA keys. Missing: {1}
LTPA_PRIMARY_KEYSTORE_MISSING_KEYS.explanation=The primary keystore is missing one or more required LTPA key entries.
LTPA_PRIMARY_KEYSTORE_MISSING_KEYS.useraction=Ensure the primary keystore contains entries for ltpaSecretKey, ltpaPrivateKey, and ltpaPublicKey (without index suffix).

LTPA_VALIDATION_KEYSTORE_MISSING_KEYS=CWWKS4132E: The validation keystore [{0}] does not contain required LTPA validation keys at index [{1}]. Missing: {2}
LTPA_VALIDATION_KEYSTORE_MISSING_KEYS.explanation=The validation keystore is missing one or more required LTPA validation key entries for the specified index.
LTPA_VALIDATION_KEYSTORE_MISSING_KEYS.useraction=Ensure the validation keystore contains entries for ltpaSecretKey_{1}, ltpaPrivateKey_{1}, and ltpaPublicKey_{1}.

LTPA_KEYSTORE_NOT_LTPA=CWWKS4133W: The keystore [{0}] appears to contain SSL certificates rather than LTPA keys. LTPA keys should be stored in dedicated keystores separate from SSL certificates.
LTPA_KEYSTORE_NOT_LTPA.explanation=The specified keystore contains certificate entries that suggest it is an SSL keystore, not an LTPA keystore.
LTPA_KEYSTORE_NOT_LTPA.useraction=Create dedicated keystores for LTPA keys, separate from SSL certificate keystores.

LTPA_PRIMARY_KEYSTORE_HAS_INDEXED_KEYS=CWWKS4134W: The primary keystore [{0}] contains indexed validation keys. Primary keystore should only contain primary keys (ltpaSecretKey, ltpaPrivateKey, ltpaPublicKey).
LTPA_PRIMARY_KEYSTORE_HAS_INDEXED_KEYS.explanation=The primary keystore contains keys with index suffixes (_1, _2, etc.), which should only be in the validation keystore.
LTPA_PRIMARY_KEYSTORE_HAS_INDEXED_KEYS.useraction=Move validation keys to the dedicated validation keystore.

LTPA_VALIDATION_KEYSTORE_HAS_PRIMARY_KEYS=CWWKS4135W: The validation keystore [{0}] contains primary keys without index. Validation keystore should only contain indexed validation keys (ltpaSecretKey_1, ltpaPrivateKey_1, etc.).
LTPA_VALIDATION_KEYSTORE_HAS_PRIMARY_KEYS.explanation=The validation keystore contains keys without index suffixes, which should only be in the primary keystore.
LTPA_VALIDATION_KEYSTORE_HAS_PRIMARY_KEYS.useraction=Move primary keys to the dedicated primary keystore.

LTPA_KEYSTORE_DEDICATED_REQUIRED=CWWKS4136E: LTPA keys must be stored in dedicated keystores, separate from SSL certificates. The keystore [{0}] contains both LTPA keys and SSL certificates.
LTPA_KEYSTORE_DEDICATED_REQUIRED.explanation=For security and operational reasons, LTPA keys must be stored in their own dedicated keystores, not mixed with SSL certificates.
LTPA_KEYSTORE_DEDICATED_REQUIRED.useraction=Create separate keystores: one for primary LTPA keys, one for validation LTPA keys, and another for SSL certificates.

LTPA_VALIDATION_KEY_INDEX_DUPLICATE=CWWKS4137E: Duplicate validation key index [{0}] found in validation keystore [{1}].
LTPA_VALIDATION_KEY_INDEX_DUPLICATE.explanation=The validation keystore contains multiple key sets with the same index.
LTPA_VALIDATION_KEY_INDEX_DUPLICATE.useraction=Ensure each validation key set has a unique index in the validation keystore.

LTPA_VALIDATION_KEY_INDEX_INVALID=CWWKS4138E: Invalid validation key index [{0}]. Index must be a positive integer starting from 1.
LTPA_VALIDATION_KEY_INDEX_INVALID.explanation=The validation key index must be a positive integer (1, 2, 3, etc.).
LTPA_VALIDATION_KEY_INDEX_INVALID.useraction=Use valid index values starting from 1 for validation keys.
```

## Key Generation and Storage

### Generating Primary Keys

When primary LTPA keys need to be generated:

1. Create dedicated primary PKCS12 keystore (separate from SSL and validation)
2. Generate 3DES shared secret key (168-bit)
3. Generate RSA key pair (2048-bit minimum, 4096-bit for FIPS)
4. Create self-signed X.509 certificate wrapping the public key
5. Store with standard aliases (no index):
   - `ltpaSecretKey`
   - `ltpaPrivateKey`
   - `ltpaPublicKey`
6. Save keystore with file permissions 600

### Generating Validation Keys

When validation LTPA keys need to be added:

1. Use existing validation keystore or create if doesn't exist
2. Determine next available index (1, 2, 3, etc.)
3. Generate 3DES shared secret key (168-bit)
4. Generate RSA key pair (2048-bit minimum, 4096-bit for FIPS)
5. Create self-signed X.509 certificate wrapping the public key
6. Store with indexed aliases:
   - `ltpaSecretKey_N`
   - `ltpaPrivateKey_N`
   - `ltpaPublicKey_N`
7. Save keystore

### Certificate Details

**For Public Key Wrapping** (NOT for SSL use):
- Subject: `CN=LTPA Token Key, O=IBM, OU=WebSphere, C=US`
- Validity: 20 years
- Signature Algorithm: SHA256withRSA (or SHA256withRSAandMGF1 for FIPS)
- Key Usage: Digital Signature, Key Encipherment
- Extended Key Usage: None (not for SSL/TLS)

## Migration Strategy

### Automatic Migration

#### Primary Keys Migration

When server starts with primary keystore reference but keystore doesn't exist:

1. Check if legacy `ltpa.keys` file exists
2. If found:
   - Load primary keys from `.keys` file
   - Create dedicated primary keystore
   - Store keys with standard aliases (no index)
   - Backup original file (`.keys.backup`)
   - Log success

#### Validation Keys Migration

When server starts with validation keystore reference but keystore doesn't exist:

1. Check for legacy validation `.keys` files
2. If found:
   - Create dedicated validation keystore
   - For each validation `.keys` file:
     - Load keys from file
     - Assign next index (1, 2, 3, etc.)
     - Store in validation keystore with indexed aliases
   - Backup original files
   - Log success with count

### Manual Migration

#### Migrate Primary Keys

```bash
securityUtility migrateLTPAKeys \
    --keysFile=/path/to/ltpa.keys \
    --keysPassword=password \
    --keystoreFile=/path/to/ltpa.p12 \
    --keystorePassword=password \
    --keystoreType=PKCS12 \
    --primary
```

#### Migrate Validation Keys

```bash
securityUtility migrateLTPAKeys \
    --keysFiles=/path/to/ltpa_val1.keys,/path/to/ltpa_val2.keys \
    --keysPasswords=password1,password2 \
    --keystoreFile=/path/to/ltpa_validation.p12 \
    --keystorePassword=password \
    --keystoreType=PKCS12 \
    --validation
```

### Backward Compatibility

- Continue to support `.keys` file format indefinitely
- Auto-detect format based on reference type
- No breaking changes to existing configurations
- Keystore format is opt-in
- Mixed configurations supported:
  - Primary in keystore, validation in `.keys` files
  - Primary in `.keys` file, validation in keystore

## Security Considerations

### Keystore Separation Enforcement

1. **Validation Checks**:
   - Verify primary keystore contains only non-indexed keys
   - Verify validation keystore contains only indexed keys
   - Check for SSL certificate indicators

2. **Warning Messages**:
   - Issue warnings if SSL certificates detected in LTPA keystores
   - Warn if primary keys found in validation keystore
   - Warn if validation keys found in primary keystore

3. **Best Practice Documentation**:
   - Clearly document three-keystore model
   - Provide migration examples
   - Explain security rationale

### Password Management

**Password Sources** (precedence order):

For Primary Keys:
1. `password` in primary `<keyStore>` element
2. `keysPassword` in `<ltpa>` element
3. `ltpa_keys_password` env var
4. `keystore_password` env var

For Validation Keys:
1. `password` in validation `<keyStore>` element
2. `validationKeysPassword` in `<ltpa>` element
3. Primary keys password (fallback)
4. `ltpa_keys_password` env var
5. `keystore_password` env var

**Password Encoding**:
- XOR encoding: `{xor}Lz4sLCgwLTs=`
- AES encryption: `{aes}...`
- Plain text (not recommended)

### FIPS 140-3 Compliance

When FIPS mode enabled:
- RSA: 2048-bit min, 4096-bit recommended
- Provider: IBMJCEFIPS
- Signature: SHA256withRSAandMGF1
- Type: PKCS12 (FIPS-approved)
- Separate keystores maintained

## Testing Strategy

### Unit Tests

1. **LTPAKeystoreManagerTest**:
   - Primary key generation and storage
   - Primary key loading
   - Validation key generation with indexing
   - Validation key loading (all keys)
   - Index management
   - Migration from `.keys` to keystores
   - Keystore type validation
   - Error handling

2. **LTPAKeyInfoManagerTest**:
   - Keystore reference detection
   - Primary vs validation keystore handling
   - Backward compatibility with `.keys` files
   - Mixed configurations

### Functional Tests (FAT)

1. **Basic Keystore Operations**:
   - Generate primary keys in dedicated keystore
   - Generate validation keys in validation keystore
   - Load keys from keystores
   - Token creation and validation
   - Verify keystore separation

2. **Migration Tests**:
   - Automatic primary keys migration
   - Automatic validation keys migration
   - Manual migration via utility
   - Verify backup files created
   - Verify indexed aliases in validation keystore

3. **Configuration Tests**:
   - Primary and validation keystores
   - Validation key metadata (index, validUntilDate)
   - Mixed configurations
   - Password resolution

4. **Security Tests**:
   - Password encoding (XOR, AES)
   - FIPS mode operation
   - File permissions
   - Keystore separation enforcement
   - Validation key index uniqueness

5. **Backward Compatibility Tests**:
   - Existing `.keys` file configurations
   - No regression in token validation
   - Mixed keystore and file configurations

6. **Validation Keys Tests**:
   - Multiple validation key sets in one keystore
   - Validation key rotation
   - validUntilDate enforcement
   - Index management

## Performance Considerations

### Keystore Loading

- Cache loaded keystores
- Lazy load validation keys
- Monitor file changes for hot-reload
- Validation keystore loaded once, all keys cached

### Key Access

- Cache decrypted keys in memory
- No performance degradation vs `.keys` files
- One-time keystore operations at startup
- Indexed access to validation keys

## Implementation Phases

### Phase 1: Core Infrastructure (Weeks 1-2)
- Implement `LTPAKeystoreManager`
- Add `KeyStoreService` integration
- Implement keystore separation validation
- Support indexed validation keys
- Update `LTPAKeyInfoManager`
- Unit tests

### Phase 2: Configuration and Migration (Weeks 3-4)
- Update metatype definitions
- Add `validationKeysFileName` attribute
- Implement automatic migration
- Add manual migration utility
- Configuration tests

### Phase 3: Validation Keys Support (Week 5)
- Validation keystore with indexed keys
- Validation key metadata handling
- Update file monitoring
- Validation keys tests

### Phase 4: Testing and Documentation (Weeks 6-7)
- Comprehensive FAT suite
- Performance testing
- Security testing
- Keystore separation testing
- Documentation updates

### Phase 5: Review and Refinement (Week 8)
- Code review
- Security review
- Performance optimization
- Beta testing

## Success Criteria

✅ Primary LTPA keys in dedicated keystore  
✅ ALL validation keys in single dedicated keystore with indexed aliases  
✅ Separate from SSL keystores  
✅ Backward compatible with `.keys` files  
✅ Automatic migration works  
✅ FIPS 140-3 compliant  
✅ No performance regression  
✅ >80% test coverage  
✅ Complete documentation  

## Summary

This design provides a comprehensive solution for storing LTPA keys in PKCS12 keystores while maintaining complete separation from SSL keystores. The key features are:

1. **Two Dedicated LTPA Keystores**:
   - Primary keystore for primary keys only
   - Validation keystore for ALL validation keys (indexed)

2. **Clear Separation**: LTPA keystores are completely separate from SSL keystores

3. **Indexed Validation Keys**: All validation keys stored in one keystore with indexed aliases (_1, _2, _3, etc.)

4. **Backward Compatible**: Continues to support legacy `.keys` files

5. **Flexible Configuration**: Supports mixed configurations (keystore + .keys files)

6. **Automatic Migration**: Seamless migration from `.keys` files to keystores

7. **Security**: Enforces keystore separation, supports FIPS, proper password management

This design aligns with both Liberty's SSL keystore patterns and tWAS's LTPA keystore approach while providing a modern, secure, and maintainable solution.