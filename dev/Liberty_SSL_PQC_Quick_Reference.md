# Liberty SSL PQC - Quick Reference Guide

## For Developers

### Key Files to Modify

#### Phase 1: Foundation
```
com.ibm.websphere.ssl/
└── Constants.java (ADD PQC constants)

com.ibm.ws.ssl/src/com/ibm/ws/ssl/pqc/
├── PQCConstants.java (NEW)
└── PQCProviderManager.java (NEW)
```

#### Phase 2: Configuration
```
com.ibm.ws.ssl/resources/OSGI-INF/
├── metatype/metatype.xml (MODIFY)
└── l10n/metatype.properties (MODIFY)

com.ibm.ws.ssl/src/com/ibm/ws/ssl/pqc/
└── PQCConfigManager.java (NEW)
```

#### Phase 3: Protocol Integration
```
com.ibm.ws.ssl/src/com/ibm/ws/ssl/config/
└── ProtocolHelper.java (MODIFY)

com.ibm.websphere.ssl/
└── Constants.java (MODIFY cipher methods)
```

#### Phase 4: Key Management
```
com.ibm.ws.ssl/src/com/ibm/ws/ssl/pqc/
└── PQCKeyManager.java (NEW)

com.ibm.ws.security.utility/src/com/ibm/ws/security/utility/tasks/
└── CreatePQCKeysTask.java (NEW)
```

### Quick Start Implementation

#### 1. Add PQC Constants
```java
// In Constants.java
public static final String PQC_ALGORITHM_MLKEM768 = "ML-KEM-768";
public static final String SSLPROP_PQC_ENABLED = "com.ibm.ssl.pqc.enabled";
public static final String PQC_MODE_HYBRID = "hybrid";
```

#### 2. Initialize PQC Provider
```java
// In PQCProviderManager.java
public static boolean initializePQCProvider() {
    Class<?> providerClass = Class.forName(
        "org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider");
    Provider provider = (Provider) providerClass.getDeclaredConstructor().newInstance();
    Security.addProvider(provider);
    return true;
}
```

#### 3. Configure PQC in server.xml
```xml
<ssl id="defaultSSLConfig" 
     keyStoreRef="defaultKeyStore"
     pqcEnabled="true"
     pqcMode="hybrid"
     pqcKemAlgorithm="ML-KEM-768"/>
```

## For Users

### Basic Configuration
```xml
<server>
    <featureManager>
        <feature>ssl-1.0</feature>
    </featureManager>
    
    <keyStore id="defaultKeyStore" 
              location="key.p12" 
              password="password"/>
    
    <ssl id="defaultSSLConfig" 
         keyStoreRef="defaultKeyStore"
         pqcEnabled="true"
         pqcMode="hybrid"/>
</server>
```

### Generate PQC Keys
```bash
securityUtility createPQCKeys \
    --keystore=pqc-key.p12 \
    --password=myPassword \
    --algorithm=ML-KEM-768 \
    --alias=pqcKey
```

### Recommended Settings
- **Mode**: hybrid (for compatibility)
- **KEM Algorithm**: ML-KEM-768 (NIST Level 3)
- **Signature Algorithm**: ML-DSA-65 (NIST Level 3)
- **Protocol**: TLSv1.3

## Testing Checklist

### Unit Tests
- [ ] PQC provider initialization
- [ ] Configuration validation
- [ ] Key generation
- [ ] Cipher suite selection

### Integration Tests
- [ ] SSL handshake with PQC
- [ ] Hybrid mode fallback
- [ ] Client authentication
- [ ] Certificate validation

### Performance Tests
- [ ] Handshake latency
- [ ] Throughput impact
- [ ] Memory consumption
- [ ] CPU utilization

## Common Issues

### Issue: PQC Provider Not Found
```
CWPKI0840E: PQC provider not available
```
**Solution**: Add bcpqc-jdk18on.jar to ${server.config.dir}/lib

### Issue: Unsupported Algorithm
```
CWPKI0842E: Unsupported PQC KEM algorithm
```
**Solution**: Use ML-KEM-512, ML-KEM-768, or ML-KEM-1024

### Issue: Performance Degradation
**Solution**: 
- Use ML-KEM-768 instead of ML-KEM-1024
- Enable connection pooling
- Implement session resumption

## Build Dependencies

### Maven
```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpqc-jdk18on</artifactId>
    <version>1.78</version>
</dependency>
```

### Gradle
```gradle
implementation 'org.bouncycastle:bcpqc-jdk18on:1.78'
```

## Algorithm Comparison

| Algorithm | Security | Performance | Recommended |
|-----------|----------|-------------|-------------|
| ML-KEM-512 | Level 1 | Fast | Testing only |
| ML-KEM-768 | Level 3 | Balanced | ✅ Production |
| ML-KEM-1024 | Level 5 | Slow | High security |

## Resources

- **Design Document**: Liberty_SSL_PQC_Design_Complete.md
- **Implementation Summary**: Liberty_SSL_PQC_Implementation_Summary.md
- **NIST PQC**: https://csrc.nist.gov/projects/post-quantum-cryptography
- **BouncyCastle**: https://www.bouncycastle.org/java.html

---

**Version**: 1.0  
**Last Updated**: 2026-04-10