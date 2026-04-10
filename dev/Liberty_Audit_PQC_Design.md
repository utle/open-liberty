# Liberty Audit Post-Quantum Cryptography (PQC) Design

## Executive Summary

This document outlines the design for adding Post-Quantum Cryptography (PQC) support to Liberty's Security Audit feature. The design enables audit records to be signed and encrypted using quantum-resistant algorithms while maintaining backward compatibility with existing RSA-based implementations.

## Current Audit Architecture

### 1. **Audit Components**

Liberty's audit system consists of:
- **AuditServiceImpl**: Core audit service managing event generation
- **AuditSigningImpl**: Digital signature implementation for audit records
- **AuditEncryptionImpl**: Encryption implementation for audit records
- **AuditCrypto**: Low-level cryptographic operations
- **AuditKeyEncryptor**: Key encryption/decryption utilities
- **Audit Events**: Various event types (authentication, authorization, JMX, etc.)

### 2. **Current Cryptographic Operations**

```
Audit Record Signing Flow:
1. Generate audit event (JSON format)
2. Sign with RSA private key (SHA512withRSA)
3. Attach signature to audit record
4. Write to audit log

Audit Record Encryption Flow:
1. Generate audit event
2. Encrypt with AES-256-CBC
3. Encrypt AES key with RSA public key
4. Write encrypted record to audit log

Audit Record Verification Flow:
1. Read audit record from log
2. Verify RSA signature with public key
3. Decrypt AES key with RSA private key
4. Decrypt audit record with AES key
```

### 3. **Key Components**

- **AuditSigningImpl.java**: RSA signature operations (SHA512withRSA)
- **AuditCrypto.java**: AES-256-CBC encryption/decryption
- **AuditKeyEncryptor.java**: RSA key wrapping for AES keys
- **AuditEncryptionImpl.java**: Orchestrates encryption operations

## PQC Design Goals

1. **Quantum Resistance**: Protect audit records against quantum computer attacks
2. **Backward Compatibility**: Support existing RSA-signed audit records
3. **Hybrid Approach**: Combine classical and PQC algorithms for defense-in-depth
4. **Long-term Integrity**: Ensure audit records remain verifiable for years
5. **Standards Compliance**: Use NIST-approved PQC algorithms
6. **Performance**: Minimize impact on audit logging performance

## Proposed PQC Architecture

### 1. **PQC Algorithm Selection**

#### Digital Signatures (replacing RSA)
- **Primary**: **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm, FIPS 204)
  - ML-DSA-44: ~2,420 bytes signature, security level 2
  - ML-DSA-65: ~3,309 bytes signature, security level 3 (recommended)
  - ML-DSA-87: ~4,627 bytes signature, security level 5

#### Key Encapsulation (for AES key wrapping)
- **Primary**: **ML-KEM** (Module-Lattice-Based Key Encapsulation Mechanism, FIPS 203)
  - ML-KEM-512: security level 1
  - ML-KEM-768: security level 3 (recommended)
  - ML-KEM-1024: security level 5

#### Symmetric Encryption (current AES is quantum-resistant)
- **Continue using**: AES-256-GCM (quantum-resistant with larger key size)
- **Upgrade from**: AES-256-CBC to AES-256-GCM for authenticated encryption

### 2. **Hybrid Signature Scheme**

Implement a hybrid approach combining classical and PQC algorithms:

```
Hybrid Signature = RSA-Signature || ML-DSA-Signature
```

**Benefits**:
- Security if either algorithm is broken
- Gradual migration path
- Backward compatibility during transition

### 3. **Enhanced Audit Record Format**

#### Current Format (RSA)
```json
{
  "eventType": "SECURITY_AUTHN",
  "outcome": "SUCCESS",
  "timestamp": "2026-04-10T01:00:00.000Z",
  "data": { ... },
  "signature": "<base64-rsa-signature>",
  "signatureAlgorithm": "SHA512withRSA"
}
```

#### New Format (PQC)
```json
{
  "eventType": "SECURITY_AUTHN",
  "outcome": "SUCCESS",
  "timestamp": "2026-04-10T01:00:00.000Z",
  "data": { ... },
  "signature": "<base64-pqc-signature>",
  "signatureAlgorithm": "ML-DSA-65",
  "signatureVersion": "3.0",
  "hybridSignature": {
    "rsaSignature": "<base64-rsa-signature>",
    "pqcSignature": "<base64-mldsa-signature>"
  }
}
```

### 4. **New Cryptographic Classes**

#### AuditPQCCrypto.java
```java
public class AuditPQCCrypto {
    // ML-DSA signature operations
    public static byte[] signMLDSA(byte[] data, MLDSAPrivateKey key);
    public static boolean verifyMLDSA(byte[] data, byte[] signature, MLDSAPublicKey key);
    
    // Hybrid signature operations
    public static byte[] signHybrid(byte[] data, PrivateKey rsaKey, MLDSAPrivateKey pqcKey);
    public static boolean verifyHybrid(byte[] data, byte[] signature, 
                                      PublicKey rsaKey, MLDSAPublicKey pqcKey);
    
    // ML-KEM key encapsulation
    public static byte[] encapsulateKey(byte[] aesKey, MLKEMPublicKey kemKey);
    public static byte[] decapsulateKey(byte[] encapsulatedKey, MLKEMPrivateKey kemKey);
    
    // AES-256-GCM encryption
    public static byte[] encryptAES256GCM(byte[] data, byte[] key);
    public static byte[] decryptAES256GCM(byte[] encryptedData, byte[] key);
}
```

#### AuditPQCSigningImpl.java
```java
public class AuditPQCSigningImpl implements AuditSigning {
    private SignatureAlgorithm signatureAlgorithm; // RSA, ML_DSA, HYBRID
    private int pqcSecurityLevel; // 2, 3, or 5
    private MLDSAPrivateKey pqcPrivateKey;
    private MLDSAPublicKey pqcPublicKey;
    private PrivateKey rsaPrivateKey;
    private PublicKey rsaPublicKey;
    
    @Override
    public byte[] sign(byte[] data) throws AuditSigningException;
    
    @Override
    public boolean verify(byte[] data, byte[] signature) throws AuditSigningException;
    
    public byte[] signHybrid(byte[] data) throws AuditSigningException;
    public boolean verifyHybrid(byte[] data, byte[] signature) throws AuditSigningException;
}
```

#### AuditPQCEncryptionImpl.java
```java
public class AuditPQCEncryptionImpl implements AuditEncryption {
    private boolean enablePQC;
    private int kemSecurityLevel; // 1, 3, or 5
    private MLKEMPublicKey kemPublicKey;
    private MLKEMPrivateKey kemPrivateKey;
    
    @Override
    public byte[] encrypt(byte[] data) throws AuditEncryptingException;
    
    @Override
    public byte[] decrypt(byte[] encryptedData) throws AuditDecryptionException;
    
    public byte[] encryptWithKEM(byte[] data) throws AuditEncryptingException;
    public byte[] decryptWithKEM(byte[] encryptedData) throws AuditDecryptionException;
}
```

### 5. **Configuration Enhancements**

#### server.xml Configuration

```xml
<auditFileHandler 
    maxFiles="100" 
    maxFileSize="20" 
    compact="false"
    encrypt="true"
    sign="true">
    
    <!-- PQC Configuration -->
    <pqcConfig
        enablePQC="true"
        signatureAlgorithm="HYBRID"
        pqcSecurityLevel="3"
        kemSecurityLevel="3"
        allowLegacyRecords="true"
        hybridMode="true"/>
    
    <!-- Signing Configuration -->
    <signing
        keyStoreName="auditSigningKeyStore"
        keyStorePath="${server.config.dir}/resources/security/auditSigningKeyStore.p12"
        keyStoreType="PKCS12"
        keyStorePassword="{xor}Lz4sLCgwLTs="
        keyAlias="auditsigner"
        pqcKeyAlias="auditsigner_pqc"/>
    
    <!-- Encryption Configuration -->
    <encryption
        keyStoreName="auditEncryptionKeyStore"
        keyStorePath="${server.config.dir}/resources/security/auditEncryptionKeyStore.p12"
        keyStoreType="PKCS12"
        keyStorePassword="{xor}Lz4sLCgwLTs="
        certificateAlias="auditencryption"
        pqcKemAlias="auditkem_pqc"/>
</auditFileHandler>
```

#### Configuration Properties

| Property | Values | Default | Description |
|----------|--------|---------|-------------|
| `enablePQC` | true, false | false | Enable PQC support |
| `signatureAlgorithm` | RSA, ML-DSA, HYBRID | HYBRID | Signature algorithm |
| `pqcSecurityLevel` | 2, 3, 5 | 3 | NIST security level for signatures |
| `kemSecurityLevel` | 1, 3, 5 | 3 | NIST security level for KEM |
| `allowLegacyRecords` | true, false | true | Accept RSA-only records |
| `hybridMode` | true, false | true | Use hybrid signatures |

### 6. **KeyStore Format**

#### Enhanced KeyStore Structure

```
auditSigningKeyStore.p12:
├── auditsigner (RSA private key + certificate)
├── auditsigner_pqc (ML-DSA private key)
└── auditsigner_pqc_pub (ML-DSA public key)

auditEncryptionKeyStore.p12:
├── auditencryption (RSA certificate for key wrapping)
├── auditkem_pqc (ML-KEM private key)
└── auditkem_pqc_pub (ML-KEM public key)
```

### 7. **Audit Record Signing Flow (PQC)**

```
1. Generate audit event (JSON)
2. Serialize event to bytes
3. Determine signature algorithm from configuration:
   a. RSA-only: Sign with RSA private key (SHA512withRSA)
   b. ML-DSA-only: Sign with ML-DSA private key
   c. HYBRID: Sign with both, concatenate signatures
4. Add signature and metadata to event
5. Write to audit log
```

### 8. **Audit Record Encryption Flow (PQC)**

```
1. Generate audit event
2. Generate random AES-256 key
3. Encrypt event with AES-256-GCM
4. Encapsulate AES key:
   a. Legacy: Wrap with RSA public key
   b. PQC: Encapsulate with ML-KEM public key
5. Attach encapsulated key to encrypted record
6. Write to audit log
```

### 9. **Audit Record Verification Flow (PQC)**

```
1. Read audit record from log
2. Detect signature version/algorithm
3. Verify signature:
   a. RSA: Verify with RSA public key
   b. ML-DSA: Verify with ML-DSA public key
   c. HYBRID: Verify both signatures (both must pass)
4. If encrypted:
   a. Decapsulate AES key (RSA or ML-KEM)
   b. Decrypt record with AES-256-GCM
5. Parse and return audit event
```

### 10. **Migration Strategy**

#### Phase 1: Preparation (Months 1-2)
- Add PQC provider support (BouncyCastle PQC)
- Implement AuditPQCCrypto class
- Add configuration options
- Create key generation utilities
- Update audit reader to support PQC

#### Phase 2: Hybrid Mode (Months 3-6)
- Deploy with `signatureAlgorithm="HYBRID"`
- Generate both RSA and ML-DSA keys
- Sign audit records with hybrid signatures
- Verify both RSA-only and hybrid records
- Monitor performance impact

#### Phase 3: PQC-Only Mode (Months 7-12)
- After all systems support PQC
- Switch to `signatureAlgorithm="ML-DSA"`
- Generate PQC-only signatures
- Still verify legacy records if `allowLegacyRecords="true"`

#### Phase 4: Legacy Deprecation (Year 2+)
- Set `allowLegacyRecords="false"`
- Reject RSA-only audit records
- Full PQC deployment

### 11. **Implementation Classes**

#### New Classes to Create

1. **com.ibm.ws.security.audit.encryption.AuditPQCCrypto.java**
   - ML-DSA signature operations
   - ML-KEM key encapsulation
   - AES-256-GCM encryption
   - Hybrid signature operations

2. **com.ibm.ws.security.audit.encryption.AuditPQCSigningImpl.java**
   - PQC-enabled audit signing
   - Hybrid signature support
   - Algorithm selection logic

3. **com.ibm.ws.security.audit.encryption.AuditPQCEncryptionImpl.java**
   - PQC-enabled audit encryption
   - ML-KEM key encapsulation
   - AES-256-GCM encryption

4. **com.ibm.ws.security.audit.encryption.AuditPQCKeyUtil.java**
   - PQC key generation
   - KeyStore management
   - Key serialization/deserialization

5. **com.ibm.ws.security.audit.source.AuditPQCConfiguration.java**
   - PQC configuration management
   - Algorithm selection
   - Security level validation

6. **com.ibm.ws.security.audit.reader.AuditPQCReader.java**
   - Read and verify PQC-signed audit records
   - Decrypt PQC-encrypted audit records
   - Support for hybrid records

#### Modified Classes

1. **AuditSigningImpl.java**
   - Add PQC algorithm support
   - Route to appropriate signing implementation
   - Support signature version detection

2. **AuditEncryptionImpl.java**
   - Add ML-KEM support
   - Route to appropriate encryption implementation
   - Support encryption version detection

3. **AuditCrypto.java**
   - Add AES-256-GCM support
   - Maintain backward compatibility with AES-256-CBC

4. **AuditServiceImpl.java**
   - Initialize PQC components
   - Configure based on server.xml settings

### 12. **Security Considerations**

#### Signature Size Impact
- RSA-2048 signature: ~256 bytes
- ML-DSA-65 signature: ~3,309 bytes
- Hybrid signature: ~3,565 bytes
- **Impact**: Audit log files will be ~13x larger
- **Mitigation**: Compression, log rotation, archival strategies

#### Performance Impact
- ML-DSA signing: ~2-3x slower than RSA
- ML-DSA verification: ~2-3x slower than RSA
- ML-KEM encapsulation: ~1.5x slower than RSA
- **Mitigation**: Asynchronous audit logging, batching, caching

#### Key Storage
- ML-DSA keys are larger than RSA keys
- ML-DSA-65 public key: ~1,952 bytes
- ML-DSA-65 private key: ~4,032 bytes
- ML-KEM-768 public key: ~1,184 bytes
- ML-KEM-768 private key: ~2,400 bytes
- **Mitigation**: Efficient KeyStore format, secure storage

#### Long-term Integrity
- Audit records must remain verifiable for years
- Hybrid signatures provide transition period
- Archive old keys for historical verification
- Document algorithm versions and parameters

### 13. **Audit Reader Enhancements**

#### Command-Line Tool Updates

```bash
# Verify PQC-signed audit records
auditUtility verify --file audit.log --keystore auditSigningKeyStore.p12 --algorithm ML-DSA

# Verify hybrid-signed audit records
auditUtility verify --file audit.log --keystore auditSigningKeyStore.p12 --algorithm HYBRID

# Decrypt PQC-encrypted audit records
auditUtility decrypt --file audit.log --keystore auditEncryptionKeyStore.p12 --algorithm ML-KEM

# Convert RSA-signed records to PQC
auditUtility convert --input audit_rsa.log --output audit_pqc.log --algorithm ML-DSA
```

### 14. **Testing Strategy**

#### Unit Tests
- PQC signature generation and verification
- ML-KEM key encapsulation/decapsulation
- Hybrid signature operations
- AES-256-GCM encryption/decryption
- Key generation and serialization

#### Integration Tests
- End-to-end audit record signing with PQC
- End-to-end audit record encryption with PQC
- Hybrid mode testing
- Migration scenarios (RSA → Hybrid → PQC)
- Audit reader verification

#### Performance Tests
- Audit logging throughput with PQC
- Signature verification performance
- Encryption/decryption performance
- Memory usage analysis

#### Security Tests
- Signature tampering detection
- Encryption strength validation
- Key rotation scenarios
- Long-term integrity verification

### 15. **Performance Optimization**

#### Caching Strategy
```java
public class AuditPQCCache {
    // Cache verified signatures
    private static final Cache<String, Boolean> signatureCache;
    
    // Cache ML-DSA public keys
    private static final Cache<String, MLDSAPublicKey> publicKeyCache;
    
    // Cache ML-KEM public keys
    private static final Cache<String, MLKEMPublicKey> kemKeyCache;
}
```

#### Asynchronous Logging
- Use separate thread pool for audit logging
- Batch audit records for signing
- Compress audit logs before writing

#### Lazy Initialization
- Load PQC provider only when needed
- Defer key generation until first use
- Initialize crypto objects on-demand

### 16. **Monitoring and Metrics**

Add metrics for:
- Audit record signing time by algorithm
- Audit record verification time by algorithm
- Audit record size by algorithm
- Signature verification success/failure rates
- Encryption/decryption performance
- Key rotation events
- Migration progress (RSA vs PQC record ratio)

### 17. **Documentation Requirements**

1. **Administrator Guide**
   - PQC configuration options
   - Migration procedures
   - Performance tuning
   - Troubleshooting
   - Key management

2. **Developer Guide**
   - API changes
   - Audit record format specifications
   - Custom audit handlers
   - PQC algorithm details

3. **Security Guide**
   - PQC algorithm details
   - Security levels
   - Key management best practices
   - Compliance considerations

## Implementation Roadmap

### Milestone 1: Foundation (Q1)
- [ ] Add PQC provider dependency (BouncyCastle PQC)
- [ ] Implement ML-DSA key generation
- [ ] Implement ML-KEM key generation
- [ ] Create AuditPQCCrypto class
- [ ] Add configuration schema

### Milestone 2: Core Functionality (Q2)
- [ ] Implement ML-DSA signing/verification
- [ ] Implement ML-KEM encapsulation/decapsulation
- [ ] Implement hybrid signature mode
- [ ] Add AES-256-GCM encryption
- [ ] Create KeyStore utilities

### Milestone 3: Integration (Q3)
- [ ] Integrate with AuditServiceImpl
- [ ] Add signature version detection
- [ ] Implement backward compatibility
- [ ] Update audit reader
- [ ] Create migration utilities

### Milestone 4: Testing & Optimization (Q4)
- [ ] Performance optimization
- [ ] Comprehensive testing
- [ ] Documentation
- [ ] Beta release

### Milestone 5: Production (Q1 next year)
- [ ] Production hardening
- [ ] Final performance tuning
- [ ] GA release
- [ ] Migration support

## Conclusion

This design provides a comprehensive approach to adding PQC support to Liberty Audit while maintaining backward compatibility and providing a clear migration path. The hybrid approach ensures security during the transition period, and the modular design allows for future algorithm updates as PQC standards evolve.

## References

1. NIST Post-Quantum Cryptography Standardization
2. ML-DSA (FIPS 204) - Module-Lattice-Based Digital Signature Standard
3. ML-KEM (FIPS 203) - Module-Lattice-Based Key-Encapsulation Mechanism Standard
4. BouncyCastle PQC Provider Documentation
5. NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes
6. Liberty Audit Documentation
7. WebSphere Security Audit Specification