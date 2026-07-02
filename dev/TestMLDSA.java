import java.security.KeyPairGenerator;

public class TestMLDSA {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA");
        System.out.println("ML-DSA supported: " + kpg.getAlgorithm());
        System.out.println("Provider: " + kpg.getProvider());
    }
}