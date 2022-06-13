import java.math.BigInteger;
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

        String ciphertext = rsa.RSAES_OAEP_ENCRYPT(keys.get('e'), keys.get('n'), message, null);
        System.out.println(ciphertext);
        String decryptedMessage = rsa.RSAES_OAEP_DECRYPT(keys.get('d'), keys.get('n'), ciphertext, null);
        System.out.println(decryptedMessage);
    }
}
