import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

public class KeyPair {
    PrivateKey privateKey;
    PublicKey publicKey;

    /**
     * Generates private and public key via Elliptic curve
     * Uses 256-bit prime field random Weierstrass curve.
     */
    public void KeyGen(){
        try {
            ECGenParameterSpec param = new ECGenParameterSpec("secp256r1");
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(param, new SecureRandom());
            java.security.KeyPair keypair = generator.generateKeyPair();
            privateKey = keypair.getPrivate();
            publicKey = keypair.getPublic();
        }
        catch(Exception e) {
            System.out.println(e);
        }
    }
    @Override
    public String toString(){
        return "Private key: " + privateKey + "\nPublic key: " + publicKey;
    }
    KeyPair(){
        KeyGen();
    }
}
