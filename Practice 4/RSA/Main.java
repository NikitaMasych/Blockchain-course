import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Map;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        RSA rsa = new RSA();
        Map<Character, BigInteger> keys = rsa.generateKeys();

        System.out.println("Enter message to be encrypted: ");
        Scanner scanner = new Scanner(System.in);
        String message = scanner.nextLine();

        byte[] ciphertext = rsa.RSAES_OAEP_ENCRYPT(keys.get('e'), keys.get('n'), message, null);
        byte[] decryptedMessage = rsa.RSAES_OAEP_DECRYPT(keys.get('d'), keys.get('n'), ciphertext, null);

        Charset charset = StandardCharsets.UTF_8;
        String result = new String(decryptedMessage, charset);

        System.out.println(result);
    }
}
