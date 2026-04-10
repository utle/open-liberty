# Liberty LTPA Post-Quantum Cryptography (PQC) Design

## Executive Summary

This document outlines the design for adding Post-Quantum Cryptography (PQC) support to Liberty's LTPA (Lightweight Third Party Authentication) token system. The design enables LTPA to use quantum-resistant algorithms while maintaining backward compatibility with existing RSA-based tokens.

## Current LTPA Architecture

### 1. **Token Structure (LTPAToken2)**

Current LTPA tokens use:
- **Encryption**: AES-CBC (128/256-bit) for token payload encryption
- **Signature**: RSA with ISO9796 padding (1024/2048-bit keys)
- **Hash**: SHA-1 or SHA-256 for message digest
- **Key Management**: RSA key pairs + shared AES key

### 2. **Cryptographic Operations**

```
Token Creation Flow:
1. Create UserData (user identity + attributes)
2. Hash UserData with SHA-1/SHA-256
3. Sign hash with RSA private key (ISO9796)
4. Encrypt (UserData + expiration + signature) with AES shared key
5. Base64 encode encrypted bytes

Token Validation Flow:
1. Base64 decode token bytes
2. Decrypt with AES shared key
3. Extract UserData, expiration, signature
4. Hash UserData
5. Verify signature with RSA public key
6. Check expiration
```

### 3. **Key Components**

- **LTPAToken2.java**: Token creation, encryption, signing, validation
- **LTPACrypto.java**: Low-level crypto operations (RSA, AES, hashing)
- **LTPADigSignature.java**: RSA key generation and signature operations
- **LTPAKeyUtil.java**: Utility methods for key operations
- **LTPAConfigurationImpl.java**: Configuration and key management

## PQC Design Goals

1. **Quantum Resistance**: Protect against quantum computer attacks
2. **Backward Compatibility**: Support existing RSA-based tokens during migration
3. **Hybrid Approach**: Combine classical and PQC algorithms for defense-in-depth
4. **Performance**: Minimize performance impact
5. **Standards Compliance**: Use NIST-approved PQC algorithms

## Proposed PQC Architecture

### 1. **PQC Algorithm Selection**

#### Digital Signatures (replacing RSA)
- **Primary**: **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm, formerly Dilithium)
  - ML-DSA-44: ~2,420 bytes signature, security level 2
  - ML-DSA-65: ~3,309 bytes signature, security level 3
  - ML-DSA-87: ~4,627 bytes signature, security level 5

#### Key Encapsulation (for future key exchange)
- **Primary**: **ML-KEM** (Module-Lattice-Based Key Encapsulation Mechanism, formerly Kyber)
  - ML-KEM-512: security level 1
  - ML-KEM-768: security level 3
  - ML-KEM-1024: security level 5

#### Symmetric Encryption (current AES is quantum-resistant)
- **Continue using**: AES-256-GCM (quantum-resistant with larger key size)

### 2. **Hybrid Signature Scheme**

Implement a hybrid approach combining classical and PQC algorithms:

```
Hybrid Signature = RSA-Signature || ML-DSA-Signature
```

**Benefits**:
- Security if either algorithm is broken
- Gradual migration path
- Backward compatibility option

### 3. **New Token Format: LTPAToken3**

Create a new token version to support PQC:

```java
public class LTPAToken3 implements Token, Serializable {
    private final short version = 3; // New version for PQC
    private byte[] signature;        // Hybrid or pure PQC signature
    private byte[] encryptedBytes;
    private UserData userData;
    private long expirationInMilliseconds;
    private byte[] sharedKey;        // AES-256 key
    private SignatureAlgorithm signatureAlgorithm; // RSA, ML-DSA, or HYBRID
    private LTPAPrivateKey privateKey;  // Can be RSA or ML-DSA
    private LTPAPublicKey publicKey;    // Can be RSA or ML-DSA
}
```

### 4. **Enhanced Cryptographic Layer**

#### New Classes

**LTPAPQCCrypto.java**:
```java
public class LTPAPQCCrypto {
    // ML-DSA signature operations
    public static byte[] signMLDSA(byte[] data, MLDSAPrivateKey key);
    public static boolean verifyMLDSA(byte[] data, byte[] signature, MLDSAPublicKey key);
    
    // Hybrid signature operations
    public static byte[] signHybrid(byte[] data, RSAPrivateKey rsaKey, MLDSAPrivateKey pqcKey);
    public static boolean verifyHybrid(byte[] data, byte[] signature, RSAPublicKey rsaKey, MLDSAPublicKey pqcKey);
    
    // Key generation
    public static MLDSAKeyPair generateMLDSAKeyPair(int securityLevel);
}
```

**LTPAPQCKeyUtil.java**:
```java
public class LTPAPQCKeyUtil {
    public static byte[] encryptAES256GCM(byte[] data, byte[] key);
    public static byte[] decryptAES256GCM(byte[] data, byte[] key);
    
    public static MLDSAKeyPair generateMLDSAKeys(int securityLevel);
    public static byte[] serializeMLDSAPublicKey(MLDSAPublicKey key);
    public static MLDSAPublicKey deserializeMLDSAPublicKey(byte[] keyBytes);
}
```

### 5. **Configuration Enhancements**

#### server.xml Configuration

```xml
<ltpa 
    keysFileName="ltpa.keys"
    keysPassword="{xor}Lz4sLCgwLTs="
    expiration="120"
    signatureAlgorithm="HYBRID"
    pqcSecurityLevel="3"
    enablePQC="true"
    allowLegacyTokens="true"
    monitorInterval="60s">
    
    <pqcConfig
        algorithm="ML-DSA-65"
        hybridMode="true"
        keyRotationInterval="90d"/>
</ltpa>
```

#### Configuration Properties

| Property | Values | Default | Description |
|----------|--------|---------|-------------|
| `signatureAlgorithm` | RSA, ML-DSA, HYBRID | HYBRID | Signature algorithm to use |
| `pqcSecurityLevel` | 1, 2, 3, 5 | 3 | NIST security level |
| `enablePQC` | true, false | false | Enable PQC support |
| `allowLegacyTokens` | true, false | true | Accept RSA-only tokens |
| `hybridMode` | true, false | true | Use hybrid signatures |

### 6. **Key File Format**

#### Enhanced ltpa.keys File

```properties
# Traditional keys (for backward compatibility)
com.ibm.websphere.ltpa.version=1.0
com.ibm.websphere.ltpa.3DESKey=<base64-encoded-aes-key>
com.ibm.websphere.ltpa.PrivateKey=<base64-encoded-rsa-private-key>
com.ibm.websphere.ltpa.PublicKey=<base64-encoded-rsa-public-key>

# PQC keys (new)
com.ibm.websphere.ltpa.pqc.version=3.0
com.ibm.websphere.ltpa.pqc.algorithm=ML-DSA-65
com.ibm.websphere.ltpa.pqc.PrivateKey=<base64-encoded-mldsa-private-key>
com.ibm.websphere.ltpa.pqc.PublicKey=<base64-encoded-mldsa-public-key>
com.ibm.websphere.ltpa.pqc.AES256Key=<base64-encoded-aes256-key>
com.ibm.websphere.ltpa.pqc.created=<timestamp>
com.ibm.websphere.ltpa.pqc.keyRotation=<rotation-date>
```

### 7. **Token Creation Flow (PQC)**

```
1. Create UserData (user identity + attributes)
2. Hash UserData with SHA-256 or SHA-384
3. Generate signature based on configuration:
   a. RSA-only: Sign with RSA private key
   b. ML-DSA-only: Sign with ML-DSA private key
   c. HYBRID: Sign with both, concatenate signatures
4. Encrypt (UserData + expiration + signature + algorithm-id) with AES-256-GCM
5. Base64 encode encrypted bytes
6. Add version prefix: "v3:" + encoded-token
```

### 8. **Token Validation Flow (PQC)**

```
1. Check version prefix
   - "v3:": PQC-enabled token
   - No prefix or "v2:": Legacy RSA token
2. Base64 decode token bytes
3. Decrypt with appropriate AES key (128 or 256)
4. Extract UserData, expiration, signature, algorithm-id
5. Hash UserData
6. Verify signature based on algorithm-id:
   a. RSA: Verify with RSA public key
   b. ML-DSA: Verify with ML-DSA public key
   c. HYBRID: Verify both signatures (both must pass)
7. Check expiration
```

### 9. **Migration Strategy**

#### Phase 1: Preparation (Months 1-2)
- Add PQC provider support (BouncyCastle PQC or similar)
- Implement LTPAToken3 class
- Add configuration options
- Create key generation utilities

#### Phase 2: Hybrid Mode (Months 3-6)
- Deploy with `signatureAlgorithm="HYBRID"`
- Generate both RSA and ML-DSA keys
- Create tokens with hybrid signatures
- Validate both RSA-only and hybrid tokens

#### Phase 3: PQC-Only Mode (Months 7-12)
- After all systems support PQC
- Switch to `signatureAlgorithm="ML-DSA"`
- Generate PQC-only tokens
- Still validate legacy tokens if `allowLegacyTokens="true"`

#### Phase 4: Legacy Deprecation (Year 2+)
- Set `allowLegacyTokens="false"`
- Reject RSA-only tokens
- Full PQC deployment

### 10. **Implementation Classes**

#### New Classes to Create

1. **com.ibm.ws.security.token.ltpa.internal.LTPAToken3.java**
   - PQC-enabled token implementation
   - Hybrid signature support
   - Enhanced encryption with AES-256-GCM

2. **com.ibm.ws.crypto.ltpakeyutil.LTPAPQCCrypto.java**
   - ML-DSA signature operations
   - Hybrid signature operations
   - AES-256-GCM encryption

3. **com.ibm.ws.crypto.ltpakeyutil.MLDSAKeyPair.java**
   - ML-DSA key pair container
   - Serialization/deserialization

4. **com.ibm.ws.crypto.ltpakeyutil.MLDSAPrivateKey.java**
   - ML-DSA private key wrapper

5. **com.ibm.ws.crypto.ltpakeyutil.MLDSAPublicKey.java**
   - ML-DSA public key wrapper

6. **com.ibm.ws.security.token.ltpa.internal.LTPAToken3Factory.java**
   - Factory for creating LTPAToken3 instances
   - Algorithm selection logic

7. **com.ibm.ws.security.token.ltpa.internal.LTPAPQCConfiguration.java**
   - PQC-specific configuration
   - Algorithm selection
   - Security level management

#### Modified Classes

1. **LTPAConfigurationImpl.java**
   - Add PQC configuration properties
   - Support multiple key formats
   - Key rotation for PQC keys

2. **LTPAKeyFileCreatorImpl.java**
   - Generate PQC keys
   - Write enhanced key file format

3. **LTPATokenService.java**
   - Route to appropriate token version
   - Support token version negotiation

### 11. **Security Considerations**

#### Signature Size Impact
- RSA-2048 signature: ~256 bytes
- ML-DSA-65 signature: ~3,309 bytes
- Hybrid signature: ~3,565 bytes
- **Mitigation**: Use compression, optimize token attributes

#### Performance Impact
- ML-DSA signing: ~2-3x slower than RSA
- ML-DSA verification: ~2-3x slower than RSA
- **Mitigation**: Caching, optimized implementations, hardware acceleration

#### Key Storage
- ML-DSA keys are larger than RSA keys
- ML-DSA-65 public key: ~1,952 bytes
- ML-DSA-65 private key: ~4,032 bytes
- **Mitigation**: Efficient serialization, secure key storage

#### Backward Compatibility
- Support token version detection
- Graceful fallback to RSA for legacy systems
- Clear migration documentation

### 12. **Testing Strategy**

#### Unit Tests
- PQC signature generation and verification
- Hybrid signature operations
- Token encryption/decryption with AES-256-GCM
- Key generation and serialization

#### Integration Tests
- Token creation with different algorithms
- Token validation across versions
- Migration scenarios (RSA → Hybrid → PQC)
- Performance benchmarks

#### Security Tests
- Signature verification failures
- Token tampering detection
- Expiration validation
- Key rotation scenarios

### 13. **Performance Optimization**

#### Caching Strategy
```java
public class LTPAPQCCache {
    // Cache verified signatures to avoid repeated verification
    private static final Cache<String, Boolean> signatureCache;
    
    // Cache ML-DSA public keys
    private static final Cache<String, MLDSAPublicKey> publicKeyCache;
    
    // Token validation cache
    private static final Cache<String, TokenValidationResult> tokenCache;
}
```

#### Lazy Initialization
- Load PQC provider only when needed
- Defer key generation until first use
- Initialize crypto objects on-demand

### 14. **Monitoring and Metrics**

Add metrics for:
- Token creation time by algorithm
- Token validation time by algorithm
- Token size by algorithm
- Signature verification success/failure rates
- Key rotation events
- Migration progress (RSA vs PQC token ratio)

### 15. **Documentation Requirements**

1. **Administrator Guide**
   - PQC configuration options
   - Migration procedures
   - Performance tuning
   - Troubleshooting

2. **Developer Guide**
   - API changes
   - Token format specifications
   - Custom token handlers

3. **Security Guide**
   - PQC algorithm details
   - Security levels
   - Key management best practices

## Implementation Roadmap

### Milestone 1: Foundation (Q1)
- [ ] Add PQC provider dependency (BouncyCastle PQC)
- [ ] Implement ML-DSA key generation
- [ ] Create LTPAToken3 class structure
- [ ] Add configuration schema

### Milestone 2: Core Functionality (Q2)
- [ ] Implement ML-DSA signing/verification
- [ ] Implement hybrid signature mode
- [ ] Add AES-256-GCM encryption
- [ ] Create key file utilities

### Milestone 3: Integration (Q3)
- [ ] Integrate with LTPATokenService
- [ ] Add token version detection
- [ ] Implement backward compatibility
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

This design provides a comprehensive approach to adding PQC support to Liberty LTPA while maintaining backward compatibility and providing a clear migration path. The hybrid approach ensures security during the transition period, and the modular design allows for future algorithm updates as PQC standards evolve.

## References

1. NIST Post-Quantum Cryptography Standardization
2. ML-DSA (FIPS 204) - Module-Lattice-Based Digital Signature Standard
3. ML-KEM (FIPS 203) - Module-Lattice-Based Key-Encapsulation Mechanism Standard
4. BouncyCastle PQC Provider Documentation
5. NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes