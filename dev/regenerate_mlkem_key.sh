#!/bin/bash

# Script to regenerate ML-KEM-768 encryption key for audit

JAVA_26=/Library/Java/JavaVirtualMachines/ibm-semeru-certified-25.jdk/Contents/Home/bin/java
OUTPUT_FILE=build.image/wlp/usr/servers/defaultServer/resources/security/auditencryptionkey.pem

# Backup the old file
if [ -f "$OUTPUT_FILE" ]; then
    echo "Backing up existing file to ${OUTPUT_FILE}.bak"
    cp "$OUTPUT_FILE" "${OUTPUT_FILE}.bak"
fi

# Generate new ML-KEM-768 key pair using Java code
cat > /tmp/GenerateMLKEM.java << 'EOF'
import java.security.*;
import java.nio.file.*;
import java.util.Base64;

public class GenerateMLKEM {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: java GenerateMLKEM <output-file>");
            System.exit(1);
        }
        
        String outputFile = args[0];
        
        // Generate ML-KEM-768 key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768");
        KeyPair keyPair = kpg.generateKeyPair();
        
        // Encode keys to PEM format
        StringBuilder pem = new StringBuilder();
        
        // Private key
        pem.append("-----BEGIN PRIVATE KEY-----\n");
        String privKeyB64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded());
        pem.append(privKeyB64);
        if (!privKeyB64.endsWith("\n")) pem.append("\n");
        pem.append("-----END PRIVATE KEY-----\n");
        
        // Public key
        pem.append("-----BEGIN PUBLIC KEY-----\n");
        String pubKeyB64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPublic().getEncoded());
        pem.append(pubKeyB64);
        if (!pubKeyB64.endsWith("\n")) pem.append("\n");
        pem.append("-----END PUBLIC KEY-----\n");
        
        // Write to file
        Files.writeString(Paths.get(outputFile), pem.toString());
        
        System.out.println("Successfully generated ML-KEM-768 key pair");
        System.out.println("Private key algorithm: " + keyPair.getPrivate().getAlgorithm());
        System.out.println("Public key algorithm: " + keyPair.getPublic().getAlgorithm());
        System.out.println("Output file: " + outputFile);
    }
}
EOF

# Compile and run
echo "Generating ML-KEM-768 key pair..."
$JAVA_26 /tmp/GenerateMLKEM.java "$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "Successfully regenerated encryption key"
    echo "File: $OUTPUT_FILE"
    ls -lh "$OUTPUT_FILE"
else
    echo "Failed to generate key"
    exit 1
fi

# Clean up
rm -f /tmp/GenerateMLKEM.java

echo ""
echo "Next steps:"
echo "1. Stop the Liberty server if running"
echo "2. Delete the old audit log: rm build.image/wlp/usr/servers/defaultServer/logs/audit.log"
echo "3. Start the Liberty server to generate a new audit log with the new encryption key"
echo "4. Test the audit reader"

# Made with Bob
