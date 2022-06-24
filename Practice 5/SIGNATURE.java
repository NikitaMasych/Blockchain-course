import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SIGNATURE{
    public static byte[] signData(PrivateKey prk, String message){
        try {
            Signature signature = Signature.getInstance("SHA3-256withDSA");
            signature.initSign(prk);
            signature.update(message.getBytes(StandardCharsets.UTF_8));
            return signature.sign();
        }
        catch (Exception e){
            System.out.println(e);
        }
        return message.getBytes(StandardCharsets.UTF_8);
    }
    public static boolean verifySignature(byte[] signedMessage, String message, PublicKey pbk){
        try {
            Signature signature = Signature.getInstance("SHA3-256withDSA");
            signature.initVerify(pbk);
            signature.update(message.getBytes(StandardCharsets.UTF_8));
            return signature.verify(signedMessage);
        }
        catch (Exception e){
            System.out.println(e);
        }
        return false;
    }
}
