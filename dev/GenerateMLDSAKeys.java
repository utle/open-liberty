import java.security.*;
import java.security.spec.*;
import java.io.*;
import java.util.Base64;

public class GenerateMLDSAKeys {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: java GenerateMLDSAKeys <output-pem-file>");
            System.exit(1);
        }
        
        String outputFile = args[0];
        System.out.println("Generating ML-DSA-65 key pair...");
        
        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair keyPair = keyGen.generateKeyPair();
        
        System.out.println("Key pair generated");
        System.out.println("  Private key size: " + keyPair.getPrivate().getEncoded().length + " bytes");
        System.out.println("  Public key size: " + keyPair.getPublic().getEncoded().length + " bytes");
        
        // Write to PEM file
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
            // Write private key
            writer.println("-----BEGIN PRIVATE KEY-----");
            String privKeyB64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(
                keyPair.getPrivate().getEncoded());
            writer.println(privKeyB64);
            writer.println("-----END PRIVATE KEY-----");
            
            // Write public key
            writer.println("-----BEGIN PUBLIC KEY-----");
            String pubKeyB64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(
                keyPair.getPublic().getEncoded());
            writer.println(pubKeyB64);
            writer.println("-----END PUBLIC KEY-----");
        }
        
        System.out.println("Keys saved to: " + outputFile);
    }
}

// Made with Bob
