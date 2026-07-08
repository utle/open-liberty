import com.ibm.ws.security.audit.crypto.AuditPQCKeyLoader;

public class GenerateMLDSAKey {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java GenerateMLDSAKey <output-pem-file>");
            System.exit(1);
        }
        
        String outputFile = args[0];
        System.out.println("Generating ML-DSA-65 key pair and saving to: " + outputFile);
        
        try {
            AuditPQCKeyLoader.generateAndSaveMLDSA(outputFile);
            System.out.println("Successfully generated and saved ML-DSA-65 key pair");
        } catch (Exception e) {
            System.err.println("Error generating ML-DSA key: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}

// Made with Bob
