import java.util.Scanner;


public class Main {
    public static void main(String[] args){
        KeyPair keyPair = new KeyPair();
        System.out.println(keyPair);
        Scanner scanner = new Scanner(System.in);
        String message = scanner.nextLine();
        byte[] digest = SIGNATURE.signData(keyPair.privateKey, message);
        boolean authentic = SIGNATURE.verifySignature(digest,  message, keyPair.publicKey);
        if (authentic) System.out.println("Authentic");
        else System.out.println("Not authentic");
    }
}
