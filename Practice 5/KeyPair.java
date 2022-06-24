import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyPair {
    PrivateKey privateKey;
    PublicKey publicKey;
    public static java.security.KeyPair KeyGen(){
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
            return keyPairGen.generateKeyPair();
        }
        catch(Exception e){
            System.out.println(e);
        }
        return null;
    }
    public void printKeyPair(){
        System.out.println("Private key: " + privateKey);
        System.out.println("Public key: " + publicKey);
    }
    @Override
    public String toString(){
        return new String("Private key: " + privateKey + "\nPublic key: " + publicKey);
    }
}
