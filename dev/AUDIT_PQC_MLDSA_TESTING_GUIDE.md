# Testing Guide: ML-DSA Signing for Audit Logs

## Overview
This guide explains how to test the ML-DSA (quantum-resistant) signing implementation for Open Liberty audit logs.

## Prerequisites

### Required
- **Java 26 or later** (for ML-DSA support)
- Open Liberty build with ML-DSA changes
- Access to command line

### Check Java Version
```bash
java -version
```
Should show Java 26 or later for ML-DSA support.

## Testing Approach

### Test 1: Verify ML-DSA Algorithm Detection

**Objective:** Confirm that the system detects ML-DSA support at runtime.

**Steps:**

1. Create a simple test class:
```bash
cd /Users/niyathar/libertyGit/open-liberty/dev
cat > TestMLDSADetection.java << 'EOF'
import com.ibm.ws.security.audit.pqc.AuditPQCRuntimeSupport;

public class TestMLDSADetection {
    public static void main(String[] args) {
        System.out.println("Java Version: " + System.getProperty("java.version"));
        System.out.println("PQC Supported: " + AuditPQCRuntimeSupport.isPQCSupported());
        System.out.println("ML-DSA Available: " + AuditPQCRuntimeSupport.isMLDSAAvailable());
        
        // Try to get ML-DSA signature instance
        try {
            java.security.Signature sig = java.security.Signature.getInstance("ML-DSA-65");
            System.out.println("✅ ML-DSA-65 Signature: Available");
            System.out.println("   Provider: " + sig.getProvider().getName());
        } catch (Exception e) {
            System.out.println("❌ ML-DSA-65 Signature: Not Available");
            System.out.println("   Reason: " + e.getMessage());
        }
    }
}
EOF
```

2. Compile and run:
```bash
javac -cp "com.ibm.ws.security.audit.source/bin:com.ibm.ws.kernel.service/bin" TestMLDSADetection.java
java -cp ".:com.ibm.ws.security.audit.source/bin:com.ibm.ws.kernel.service/bin" TestMLDSADetection
```

**Expected Output (Java 26+):**
```
Java Version: 26.0.0
PQC Supported: true
ML-DSA Available: true
✅ ML-DSA-65 Signature: Available
   Provider: SUN
```

**Expected Output (Java 17-25):**
```
Java Version: 17.0.12
PQC Supported: false
ML-DSA Available: false
❌ ML-DSA-65 Signature: Not Available
   Reason: ML-DSA-65 Signature not available
```

---

### Test 2: Generate ML-DSA Signing Keys

**Objective:** Create ML-DSA key pair for audit signing.

**Steps:**

1. Use the existing key generation utility:
```bash
cd /Users/niyathar/libertyGit/open-liberty/dev

# Create test directory
mkdir -p test-keys

# Generate ML-DSA signing keys
java -cp "com.ibm.ws.security.audit.source/bin:com.ibm.ws.kernel.service/bin:lib/*" \
  com.ibm.ws.security.audit.crypto.AuditPQCKeyLoader \
  generateMLDSA test-keys/audit_signing.pem
```

2. Verify the key file was created:
```bash
ls -lh test-keys/audit_signing.pem
cat test-keys/audit_signing.pem | head -20
```

**Expected Output:**
```
-rw-r--r--  1 user  staff   3.2K Jul  8 15:20 test-keys/audit_signing.pem

-----BEGIN PRIVATE KEY-----
MIIJpAIBADANBgkqhkiG9w0BAQEFAASC...
[ML-DSA-65 private key data]
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
[ML-DSA-65 public key data]
-----END PUBLIC KEY-----
```

---

### Test 3: Test Signature Creation and Verification

**Objective:** Verify ML-DSA signing and verification works.

**Steps:**

1. Create a test program:
```bash
cat > TestMLDSASigning.java << 'EOF'
import java.security.*;
import java.nio.charset.StandardCharsets;
import com.ibm.ws.security.audit.crypto.AuditPQCKeyLoader;

public class TestMLDSASigning {
    public static void main(String[] args) throws Exception {
        System.out.println("=== ML-DSA Signing Test ===\n");
        
        // Load key pair
        String keyFile = "test-keys/audit_signing.pem";
        System.out.println("1. Loading ML-DSA key pair from: " + keyFile);
        KeyPair keyPair = AuditPQCKeyLoader.loadMLDSAKeyPair(keyFile);
        System.out.println("   ✅ Keys loaded successfully");
        System.out.println("   Private Key Algorithm: " + keyPair.getPrivate().getAlgorithm());
        System.out.println("   Public Key Algorithm: " + keyPair.getPublic().getAlgorithm());
        
        // Create test data
        String testData = "This is a test audit log entry";
        byte[] dataBytes = testData.getBytes(StandardCharsets.UTF_8);
        System.out.println("\n2. Test data: \"" + testData + "\"");
        
        // Sign the data
        System.out.println("\n3. Signing data with ML-DSA-65...");
        Signature signer = Signature.getInstance("ML-DSA-65");
        signer.initSign(keyPair.getPrivate());
        signer.update(dataBytes);
        byte[] signature = signer.sign();
        System.out.println("   ✅ Signature created");
        System.out.println("   Signature length: " + signature.length + " bytes");
        
        // Verify the signature
        System.out.println("\n4. Verifying signature...");
        Signature verifier = Signature.getInstance("ML-DSA-65");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(dataBytes);
        boolean valid = verifier.verify(signature);
        
        if (valid) {
            System.out.println("   ✅ Signature verification: PASSED");
        } else {
            System.out.println("   ❌ Signature verification: FAILED");
        }
        
        // Test with tampered data
        System.out.println("\n5. Testing with tampered data...");
        byte[] tamperedData = "This is TAMPERED audit log entry".getBytes(StandardCharsets.UTF_8);
        verifier = Signature.getInstance("ML-DSA-65");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(tamperedData);
        boolean tamperedValid = verifier.verify(signature);
        
        if (!tamperedValid) {
            System.out.println("   ✅ Tampered data rejected: PASSED");
        } else {
            System.out.println("   ❌ Tampered data accepted: FAILED");
        }
        
        System.out.println("\n=== Test Complete ===");
    }
}
EOF
```

2. Compile and run:
```bash
javac -cp "com.ibm.ws.security.audit.source/bin:com.ibm.ws.kernel.service/bin:lib/*" TestMLDSASigning.java
java -cp ".:com.ibm.ws.security.audit.source/bin:com.ibm.ws.kernel.service/bin:lib/*" TestMLDSASigning
```

**Expected Output:**
```
=== ML-DSA Signing Test ===

1. Loading ML-DSA key pair from: test-keys/audit_signing.pem
   ✅ Keys loaded successfully
   Private Key Algorithm: ML-DSA
   Public Key Algorithm: ML-DSA

2. Test data: "This is a test audit log entry"

3. Signing data with ML-DSA-65...
   ✅ Signature created
   Signature length: 3309 bytes

4. Verifying signature...
   ✅ Signature verification: PASSED

5. Testing with tampered data...
   ✅ Tampered data rejected: PASSED

=== Test Complete ===
```

---

### Test 4: Integration Test with Audit Logs

**Objective:** Test ML-DSA signing in actual audit log scenario.

**Steps:**

1. Build the audit modules:
```bash
cd /Users/niyathar/libertyGit/open-liberty/dev
./gradlew com.ibm.ws.security.audit.source:build com.ibm.ws.security.audit.file:build
```

2. Create a test server configuration:
```bash
mkdir -p test-server/resources/security
cp test-keys/audit_signing.pem test-server/resources/security/
```

3. Create server.xml with audit configuration:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<server description="ML-DSA Audit Test Server">
    <featureManager>
        <feature>audit-1.0</feature>
    </featureManager>
    
    <auditFileHandler
        enabled="true"
        encrypt="true"
        sign="true"
        encryptKeyStoreRef="auditEncKeyStore"
        signingKeyStoreRef="auditSignKeyStore"/>
    
    <keyStore id="auditEncKeyStore"
        location="${server.config.dir}/resources/security/audit_encryption.pem"
        type="PEM"/>
    
    <keyStore id="auditSignKeyStore"
        location="${server.config.dir}/resources/security/audit_signing.pem"
        type="PEM"/>
</server>
```

4. Start the server and check logs:
```bash
# Look for ML-DSA initialization messages
grep -i "ML-DSA" test-server/logs/messages.log
grep -i "PQC" test-server/logs/messages.log
```

**Expected Log Messages:**
```
[AUDIT] Initialized ML-DSA-65 signature for PQC mode
[AUDIT] PQC mode enabled, using ML-KEM for key encapsulation and ML-DSA for signing
```

---

### Test 5: Verify Fallback to RSA (Java 17)

**Objective:** Confirm graceful fallback when ML-DSA is unavailable.

**Steps:**

1. Run the same tests with Java 17:
```bash
# Set JAVA_HOME to Java 17
export JAVA_HOME=/path/to/java17
java -version  # Should show 17.x

# Run detection test
java -cp ".:com.ibm.ws.security.audit.source/bin:com.ibm.ws.kernel.service/bin" TestMLDSADetection
```

**Expected Output:**
```
Java Version: 17.0.12
PQC Supported: false
ML-DSA Available: false
❌ ML-DSA-65 Signature: Not Available
   Reason: no such algorithm: ML-DSA-65 for provider SUN
```

2. Check audit logs for fallback message:
```bash
grep -i "SHA512withRSA" test-server/logs/messages.log
```

**Expected:**
```
[AUDIT] Initialized SHA512withRSA signature (PQC not available)
```

---

## Performance Testing

### Benchmark Signature Operations

```bash
cat > BenchmarkMLDSA.java << 'EOF'
import java.security.*;
import java.nio.charset.StandardCharsets;
import com.ibm.ws.security.audit.crypto.AuditPQCKeyLoader;

public class BenchmarkMLDSA {
    public static void main(String[] args) throws Exception {
        KeyPair keyPair = AuditPQCKeyLoader.loadMLDSAKeyPair("test-keys/audit_signing.pem");
        byte[] data = "Audit log entry".getBytes(StandardCharsets.UTF_8);
        
        int iterations = 1000;
        
        // Benchmark signing
        long startSign = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            Signature signer = Signature.getInstance("ML-DSA-65");
            signer.initSign(keyPair.getPrivate());
            signer.update(data);
            byte[] sig = signer.sign();
        }
        long endSign = System.nanoTime();
        double avgSign = (endSign - startSign) / 1_000_000.0 / iterations;
        
        // Benchmark verification
        Signature signer = Signature.getInstance("ML-DSA-65");
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();
        
        long startVerify = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            Signature verifier = Signature.getInstance("ML-DSA-65");
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            verifier.verify(signature);
        }
        long endVerify = System.nanoTime();
        double avgVerify = (endVerify - startVerify) / 1_000_000.0 / iterations;
        
        System.out.println("ML-DSA-65 Performance (" + iterations + " iterations):");
        System.out.println("  Average Sign Time: " + String.format("%.3f", avgSign) + " ms");
        System.out.println("  Average Verify Time: " + String.format("%.3f", avgVerify) + " ms");
    }
}
EOF
```

---

## Troubleshooting

### Issue: "ML-DSA-65 Signature not available"
**Solution:** Ensure you're running Java 26 or later.

### Issue: "Key file not found"
**Solution:** Generate keys first using `AuditPQCKeyLoader.generateAndSaveMLDSA()`.

### Issue: "Signature verification failed"
**Solution:** Ensure you're using the same key pair for signing and verification.

### Issue: Build errors
**Solution:** The build errors in other modules are pre-existing. Our modules compile successfully.

---

## Quick Test Script

Save this as `test-mldsa.sh`:

```bash
#!/bin/bash
set -e

echo "=== ML-DSA Audit Signing Test Suite ==="
echo ""

# Check Java version
echo "1. Checking Java version..."
java -version
echo ""

# Generate keys
echo "2. Generating ML-DSA keys..."
mkdir -p test-keys
java -cp "com.ibm.ws.security.audit.source/bin:lib/*" \
  com.ibm.ws.security.audit.crypto.AuditPQCKeyLoader \
  generateMLDSA test-keys/audit_signing.pem
echo "   ✅ Keys generated"
echo ""

# Test detection
echo "3. Testing ML-DSA detection..."
javac -cp "com.ibm.ws.security.audit.source/bin:com.ibm.ws.kernel.service/bin" TestMLDSADetection.java
java -cp ".:com.ibm.ws.security.audit.source/bin:com.ibm.ws.kernel.service/bin" TestMLDSADetection
echo ""

# Test signing
echo "4. Testing ML-DSA signing..."
javac -cp "com.ibm.ws.security.audit.source/bin:com.ibm.ws.kernel.service/bin:lib/*" TestMLDSASigning.java
java -cp ".:com.ibm.ws.security.audit.source/bin:com.ibm.ws.kernel.service/bin:lib/*" TestMLDSASigning
echo ""

echo "=== All Tests Complete ==="
```

Run with:
```bash
chmod +x test-mldsa.sh
./test-mldsa.sh
```

---

## Summary

The ML-DSA signing implementation can be tested at multiple levels:
1. **Runtime Detection** - Verify Java 26+ support
2. **Key Generation** - Create ML-DSA key pairs
3. **Signature Operations** - Test signing and verification
4. **Integration** - Test with actual audit logs
5. **Fallback** - Verify RSA fallback on older Java

All tests should pass on Java 26+ with ML-DSA support enabled.

Made with Bob