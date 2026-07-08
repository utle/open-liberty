import com.ibm.ws.security.audit.crypto.AuditPQCKeyLoader;

public class GenerateMLKEMKey {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java GenerateMLKEMKey <output-pem-file>");
            System.exit(1);
        }
        
        String outputFile = args[0];
        
        try {
            System.out.println("Generating ML-KEM-768 key pair...");
            AuditPQCKeyLoader.generateAndSave(outputFile);
            System.out.println("Successfully generated ML-KEM-768 key pair and saved to: " + outputFile);
        } catch (Exception e) {
            System.err.println("Failed to generate ML-KEM key pair: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}

// Made with Bob
