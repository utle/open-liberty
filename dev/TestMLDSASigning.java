import java.security.*;
import java.security.spec.*;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.Base64;

public class TestMLDSASigning {
    public static void main(String[] args) throws Exception {
        System.out.println("=== ML-DSA Signing Test ===\n");
        
        // Load key pair from PEM file
        String keyFile = "test-keys/audit_signing.pem";
        System.out.println("1. Loading ML-DSA key pair from: " + keyFile);
        KeyPair keyPair = loadKeyPair(keyFile);
        System.out.println("   Keys loaded successfully");
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
        System.out.println("   Signature created");
        System.out.println("   Signature length: " + signature.length + " bytes");
        
        // Verify the signature
        System.out.println("\n4. Verifying signature...");
        Signature verifier = Signature.getInstance("ML-DSA-65");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(dataBytes);
        boolean valid = verifier.verify(signature);
        
        if (valid) {
            System.out.println("   Signature verification: PASSED");
        } else {
            System.out.println("   Signature verification: FAILED");
            System.exit(1);
        }
        
        // Test with tampered data
        System.out.println("\n5. Testing with tampered data...");
        byte[] tamperedData = "This is TAMPERED audit log entry".getBytes(StandardCharsets.UTF_8);
        verifier = Signature.getInstance("ML-DSA-65");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(tamperedData);
        boolean tamperedValid = verifier.verify(signature);
        
        if (!tamperedValid) {
            System.out.println("   Tampered data rejected: PASSED");
        } else {
            System.out.println("   Tampered data accepted: FAILED");
            System.exit(1);
        }
        
        System.out.println("\n=== All Tests PASSED ===");
    }
    
    private static KeyPair loadKeyPair(String pemFile) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(pemFile));
        StringBuilder privKeyPem = new StringBuilder();
        StringBuilder pubKeyPem = new StringBuilder();
        String line;
        boolean inPrivKey = false;
        boolean inPubKey = false;
        
        while ((line = reader.readLine()) != null) {
            if (line.contains("BEGIN PRIVATE KEY")) {
                inPrivKey = true;
            } else if (line.contains("END PRIVATE KEY")) {
                inPrivKey = false;
            } else if (line.contains("BEGIN PUBLIC KEY")) {
                inPubKey = true;
            } else if (line.contains("END PUBLIC KEY")) {
                inPubKey = false;
            } else if (inPrivKey) {
                privKeyPem.append(line);
            } else if (inPubKey) {
                pubKeyPem.append(line);
            }
        }
        reader.close();
        
        // Decode keys
        byte[] privKeyBytes = Base64.getDecoder().decode(privKeyPem.toString());
        byte[] pubKeyBytes = Base64.getDecoder().decode(pubKeyPem.toString());
        
        // Create key objects
        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privKeyBytes));
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyBytes));
        
        return new KeyPair(publicKey, privateKey);
    }
}

// Made with Bob
