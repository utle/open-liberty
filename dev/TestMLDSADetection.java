import com.ibm.ws.security.audit.pqc.AuditPQCRuntimeSupport;
public class TestMLDSADetection {
    public static void main(String[] args) {
        System.out.println("Java: " + System.getProperty("java.version"));
        System.out.println("PQC Supported: " + AuditPQCRuntimeSupport.isPQCSupported());
        try {
            java.security.Signature.getInstance("ML-DSA-65");
            System.out.println("✅ ML-DSA-65: Available");
        } catch (Exception e) {
            System.out.println("❌ ML-DSA-65: Not Available - " + e.getMessage());
        }
    }
}
