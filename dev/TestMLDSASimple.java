import java.security.*;

/**
 * Simple test to verify ML-DSA-65 support in Java 26+
 * This test doesn't require any Liberty classes.
 */
public class TestMLDSASimple {
    public static void main(String[] args) {
        System.out.println("=== ML-DSA Support Test ===\n");
        
        // Check Java version
        String javaVersion = System.getProperty("java.version");
        System.out.println("Java Version: " + javaVersion);
        
        // Parse major version
        int majorVersion = getMajorVersion(javaVersion);
        System.out.println("Major Version: " + majorVersion);
        
        if (majorVersion >= 26) {
            System.out.println("✅ Java 26+ detected - ML-DSA should be available\n");
        } else {
            System.out.println("❌ Java " + majorVersion + " detected - ML-DSA requires Java 26+\n");
        }
        
        // Test ML-DSA-65 availability
        System.out.println("Testing ML-DSA-65 Signature Algorithm:");
        try {
            Signature sig = Signature.getInstance("ML-DSA-65");
            System.out.println("✅ ML-DSA-65 is AVAILABLE");
            System.out.println("   Provider: " + sig.getProvider().getName());
            System.out.println("   Provider Version: " + sig.getProvider().getVersion());
            
            // List all available signature algorithms
            System.out.println("\nAvailable ML-DSA variants:");
            testAlgorithm("ML-DSA");
            testAlgorithm("ML-DSA-44");
            testAlgorithm("ML-DSA-65");
            testAlgorithm("ML-DSA-87");
            
        } catch (NoSuchAlgorithmException e) {
            System.out.println("❌ ML-DSA-65 is NOT AVAILABLE");
            System.out.println("   Reason: " + e.getMessage());
            System.out.println("\nThis is expected on Java versions before 26.");
            System.out.println("The audit signing will automatically fall back to SHA512withRSA.");
        }
        
        System.out.println("\n=== Test Complete ===");
    }
    
    private static void testAlgorithm(String algorithm) {
        try {
            Signature.getInstance(algorithm);
            System.out.println("  ✅ " + algorithm);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("  ❌ " + algorithm + " (not available)");
        }
    }
    
    private static int getMajorVersion(String version) {
        try {
            // Handle versions like "26.0.1", "17.0.12", "1.8.0_292"
            String[] parts = version.split("\\.");
            int first = Integer.parseInt(parts[0]);
            
            // Java 8 and earlier use "1.8" format
            if (first == 1 && parts.length > 1) {
                return Integer.parseInt(parts[1]);
            }
            
            // Java 9+ uses "9", "17", "26" format
            return first;
        } catch (Exception e) {
            return 0;
        }
    }
}

// Made with Bob
