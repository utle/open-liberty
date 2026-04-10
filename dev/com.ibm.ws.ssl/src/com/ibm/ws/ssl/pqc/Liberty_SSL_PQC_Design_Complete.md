"/>
```

### 12.2 Emergency Disable
Set environment variable to disable PQC:
```bash
export IBM_SSL_PQC_DISABLED=true
```

### 12.3 Monitoring During Rollback
- Track error rates
- Monitor connection failures
- Verify classical SSL functionality

## 13. Conclusion

This design provides a comprehensive approach to integrating Post-Quantum Cryptography into IBM WebSphere Liberty's SSL infrastructure. The phased implementation ensures:

1. **Backward Compatibility**: Existing SSL configurations continue to work
2. **Flexibility**: Support for hybrid and pure PQC modes
3. **Standards Compliance**: Adherence to NIST and IETF standards
4. **Performance**: Optimized for production use
5. **Security**: Quantum-resistant cryptography for future-proofing

The implementation will position Liberty as a leader in post-quantum security, providing customers with the tools they need to protect against future quantum computing threats.

## Appendix A: PQC Algorithm Comparison

| Algorithm | Type | Key Size | Signature Size | Security Level | Performance |
|-----------|------|----------|----------------|----------------|-------------|
| ML-KEM-512 | KEM | 800 bytes | N/A | NIST Level 1 | Fast |
| ML-KEM-768 | KEM | 1184 bytes | N/A | NIST Level 3 | Medium |
| ML-KEM-1024 | KEM | 1568 bytes | N/A | NIST Level 5 | Slow |
| ML-DSA-44 | Signature | 1312 bytes | 2420 bytes | NIST Level 2 | Fast |
| ML-DSA-65 | Signature | 1952 bytes | 3293 bytes | NIST Level 3 | Medium |
| ML-DSA-87 | Signature | 2592 bytes | 4595 bytes | NIST Level 5 | Slow |

## Appendix B: Configuration Examples

### Example 1: Basic Hybrid Configuration
```xml
<server>
    <featureManager>
        <feature>ssl-1.0</feature>
        <feature>transportSecurity-1.0</feature>
    </featureManager>
    
    <keyStore id="defaultKeyStore" 
              location="key.p12" 
              password="password"/>
    
    <ssl id="defaultSSLConfig" 
         keyStoreRef="defaultKeyStore"
         pqcEnabled="true"
         pqcMode="hybrid"
         sslProtocol="TLSv1.3"/>
</server>
```

### Example 2: Advanced PQC Configuration
```xml
<server>
    <keyStore id="pqcKeyStore" 
              location="pqc-key.p12" 
              password="{xor}Lz4sLCgwLTs="/>
    
    <keyStore id="classicalKeyStore" 
              location="classical-key.p12" 
              password="{xor}Lz4sLCgwLTs="/>
    
    <ssl id="advancedPQC" 
         keyStoreRef="pqcKeyStore"
         trustStoreRef="classicalKeyStore"
         pqcEnabled="true"
         pqcMode="hybrid"
         pqcKemAlgorithm="ML-KEM-768"
         pqcSignatureAlgorithm="ML-DSA-65"
         sslProtocol="TLSv1.3"
         enabledCiphers="TLS_AES_256_GCM_SHA384"/>
</server>
```

### Example 3: Outbound PQC Configuration
```xml
<server>
    <ssl id="outboundPQC" 
         keyStoreRef="defaultKeyStore"
         pqcEnabled="true"
         pqcMode="hybrid"
         clientAuthentication="true"/>
    
    <outboundConnection 
         sslRef="outboundPQC"
         remoteHost="secure.example.com"
         remotePort="443"/>
</server>
```

## Appendix C: Error Messages

| Message ID | Message | Action |
|------------|---------|--------|
| CWPKI0840E | PQC provider not available | Install BouncyCastle PQC provider |
| CWPKI0841E | Invalid PQC mode: {0} | Use hybrid, pure, or disabled |
| CWPKI0842E | Unsupported PQC KEM algorithm: {0} | Use ML-KEM-512, 768, or 1024 |
| CWPKI0843E | PQC key generation failed | Check provider and algorithm |
| CWPKI0844W | PQC handshake fallback to classical | Normal in hybrid mode |
| CWPKI0845I | PQC provider initialized: {0} | Informational |

## Appendix D: References

1. NIST Post-Quantum Cryptography Standardization
   - https://csrc.nist.gov/projects/post-quantum-cryptography

2. FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
   - https://csrc.nist.gov/pubs/fips/203/final

3. FIPS 204: Module-Lattice-Based Digital Signature Standard
   - https://csrc.nist.gov/pubs/fips/204/final

4. RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
   - https://datatracker.ietf.org/doc/html/rfc8446

5. BouncyCastle PQC Provider Documentation
   - https://www.bouncycastle.org/java.html

6. IETF TLS Working Group
   - https://datatracker.ietf.org/wg/tls/documents/

---

**Document Version**: 1.0  
**Last Updated**: 2026-04-10  
**Author**: Liberty SSL Team  
**Status**: Design Complete - Ready for Implementation