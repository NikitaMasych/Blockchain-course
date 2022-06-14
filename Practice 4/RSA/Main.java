import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Map;
import java.util.Scanner;

public class Main {
    public static void outputCiphertext(byte[] ciphertext){
        StringBuilder sb = new StringBuilder("Ciphertext: ");
        for (byte b : ciphertext){
            sb.append(String.format("%02X ", b));
        }
        System.out.println(sb);
    }
    public static void main(String[] args){
        try {
            RSA rsa = new RSA();
            // WARNING: INSECURE STORAGE. MADE IN EDUCATIONAL PURPOSES:
            Map<Character, BigInteger> keys = rsa.generateKeys();

            System.out.println("Enter message to be encrypted: ");
            Scanner scanner = new Scanner(System.in);
            String message = scanner.nextLine();

            Charset charset = StandardCharsets.UTF_8;
            byte[] ciphertext;
            byte[] decryptedMessage;

            // RSAES-PSCS1-V1_5:
            ciphertext = rsa.RSAES_PKCS1_V1_5_ENCRYPT(keys.get('e'), keys.get('n'), message);
            outputCiphertext(ciphertext);
            decryptedMessage = rsa.RSAES_PKCS1_V1_5_DECRYPT(keys.get('d'), keys.get('n'), ciphertext);
            System.out.println(new String(decryptedMessage, charset));

            // NO LABEL TEST:
            ciphertext = rsa.RSAES_OAEP_ENCRYPT(keys.get('e'), keys.get('n'), message);
            outputCiphertext(ciphertext);
            decryptedMessage = rsa.RSAES_OAEP_DECRYPT(keys.get('d'), keys.get('n'), ciphertext);
            System.out.println(new String(decryptedMessage, charset));

            // CORRESPONDING LABELS TEST:
            ciphertext = rsa.RSAES_OAEP_ENCRYPT(keys.get('e'), keys.get('n'), message, "Average label fun");
            outputCiphertext(ciphertext);
            decryptedMessage = rsa.RSAES_OAEP_DECRYPT(keys.get('d'), keys.get('n'), ciphertext, "Average label fun");
            System.out.println(new String(decryptedMessage, charset));

            //DIVERGENT LABELS TEST:
            ciphertext = rsa.RSAES_OAEP_ENCRYPT(keys.get('e'), keys.get('n'), message, "Average label fun");
            outputCiphertext(ciphertext);
            decryptedMessage = rsa.RSAES_OAEP_DECRYPT(keys.get('d'), keys.get('n'), ciphertext, "Average label enjoyer");
            System.out.println(new String(decryptedMessage, charset));

        }
        catch (NoSuchAlgorithmException ex){
            System.out.println( "Exception thrown for incorrect algorithm: " + ex) ;
        }
        catch (RuntimeException ex){
            System.out.println("Problem occurred: " + ex);
        }
    }
}
