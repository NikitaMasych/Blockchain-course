import javax.management.InvalidAttributeValueException;
import java.math.BigInteger;
import java.security.*;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class RSA {
    private String hashAlgorithm; // Type of the hash algorithm
    private int k; // Length in octets of the modulus n
    private int hLen; // Length in octets of the specified hash algorithm

    /**
     * Generates private (d) and public (e) exponents and modulus (n)
     * @return BigInteger map of 3 values with d, e and n accordingly as char keys
     */
    Map<Character, BigInteger> generateKeys() throws NoSuchAlgorithmException {
        BigInteger d, e, n;
        Map<Character, BigInteger> kS = new HashMap<Character, BigInteger>();

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(k * 8); // in bits
        KeyPair pair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        kS.put('d', ((RSAPrivateKey) privateKey).getPrivateExponent());
        kS.put('e', ((RSAPublicKey) publicKey).getPublicExponent());
        kS.put('n', ((RSAPrivateKey) privateKey).getModulus());

        return kS;
    }

    /**
     * Requests key length in bits via console;
     * Sets length in octets of the modulus n
     * @param scanner represents object for input
     */
    void enterKeyLength(Scanner scanner) {
        System.out.println("Enter key length in bits: ");
        int keyLength = scanner.nextInt();
        if (keyLength % 512 != 0){
            System.out.println("Invalid key length!");
            enterKeyLength(scanner);
        }
        else k = keyLength / 8;
        scanner.nextLine();
    }

    /**
     * Requests hashing algorithm type via console
     * until it is not valid
     * Sets hash length in octets for specified algorithm
     * @param scanner
     */
    void enterHashAlgorithm(Scanner scanner){

        System.out.println("Enter hashing algorithm: ");
        String hAlg = scanner.nextLine();
        try{
            MessageDigest md = MessageDigest.getInstance(hAlg);
            hashAlgorithm = hAlg;
            String str = "";
            hLen = md.digest(str.getBytes(StandardCharsets.UTF_8)).length;
        }
        catch (NoSuchAlgorithmException e){
            System.out.println("Invalid hashing algorithm" + e);
            enterHashAlgorithm(scanner);
        }
    }

    /**
     * Constructor for the RSA class;
     * calls enterKeyLength() and enterHashAlgorithm() functions
     */
    RSA(){
        Scanner scanner = new Scanner(System.in);
        enterKeyLength(scanner);
        enterHashAlgorithm(scanner);
    }
    /**
     * Encryption function primitive
     * @param e public exponent
     * @param n public modulus
     * @param m message representative, an integer between 0 and n - 1
     * @return ciphertext representative, an integer between 0 and n - 1
     */
    public BigInteger RSAEP(BigInteger e, BigInteger n, BigInteger m){
        if ((m.compareTo(BigInteger.ZERO) == -1) || (m.compareTo(n.subtract(BigInteger.ONE)) == 1)){
            throw new RuntimeException("Message representative out of range!");
        }
        return m.modPow(e, n);
    };
    /**
     * Decryption function primitive
     * @param d private exponent
     * @param n public modulus
     * @param c ciphertext representative, an integer between 0 and n - 1
     * @return message representative, an integer between 0 and n - 1
     */
    public BigInteger RSADP(BigInteger d, BigInteger n, BigInteger c){
        if ((c.compareTo(BigInteger.ZERO) == -1) || (c.compareTo(n.subtract(BigInteger.ONE)) == 1)){
            throw new RuntimeException("Ciphertext representative out of range!");
        }
        return c.modPow(d, n);
    };
    /**
     * Digital signature function primitive
     * @param d private exponent
     * @param n public modulus
     * @param m message representative, an integer between 0 and n - 1
     * @return signature representative, an integer between 0 and n - 1
     */
    public BigInteger RSASP1(BigInteger d, BigInteger n, BigInteger m){
        if ((m.compareTo(BigInteger.ZERO) == -1) || (m.compareTo(n.subtract(BigInteger.ONE)) == 1)){
            throw new RuntimeException("Message representative out of range!");
        }
        return m.modPow(d, n);
    }
    /**
     * Verification signature function primitive
     * @param e public exponent
     * @param n public modulus
     * @param s signature representative, an integer between 0 and n - 1
     * @return message representative, an integer between 0 and n - 1
     */
    public BigInteger RSAVP1(BigInteger e, BigInteger n, BigInteger s){
        if ((s.compareTo(BigInteger.ZERO) == -1) || (s.compareTo(n.subtract(BigInteger.ONE)) > 0)){
            throw new RuntimeException("Signature representative out of range!");
        }
        return s.modPow(e, n);
    }
    /**
     * I2OSP converts a nonnegative integer to an octet string of a specified length.
     * @params x nonnegative integer to be converted
     * @params xLen intended length of the resulting octet string
     * @return octet string of lenght xLen
     */
    public String I2OSP(BigInteger x, int xLen){
        if (x.compareTo(BigInteger.valueOf(256).pow(xLen)) != -1)
            throw new RuntimeException("Integer too large!");

        StringBuilder res = new StringBuilder();
        while (!x.equals(BigInteger.ZERO)){
            res.append(x.mod(BigInteger.valueOf(256)));
            x = x.divide(BigInteger.valueOf(256));
        }
        res.append("0".repeat(Math.max(0, xLen - res.length())));

        return res.reverse().toString();
    }

    /**
     * OS2IP converts an octet string to a nonnegative integer.
     * @params x octet string to be converted
     * @return corresponding nonnegative integer
     */
    public BigInteger OS2IP(String x){
        x = new StringBuilder(x).reverse().toString();
        BigInteger res = BigInteger.ZERO;
        for (int i = 0; i != x.length(); ++i){
            BigInteger c = new BigInteger(String.valueOf(x.charAt(i)));
            res = res.add(c.multiply(BigInteger.valueOf(256).pow(i)));
        }
        return res;
    }

    /**
     * Hashing function
     * @param str input message
     * @return message digest as octet string
     */
    public String SHA(String str) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
        return Arrays.toString(md.digest(str.getBytes(StandardCharsets.UTF_8)));
    }
    /**
     * Mask generation function
     * @param Z seed from which mask is generated, an octet string
     * @param l intended length in octets of the mask
     * @return mask of l octets length
     */
    String MGF1(String Z, int l) throws NoSuchAlgorithmException {

        if (l > Math.pow(2,hLen)) throw new RuntimeException("Mask too long!");
        StringBuilder T = new StringBuilder();
        for (long counter = 0; counter != Math.ceilDiv(l,hLen) - 1; ++ counter){
            String C = I2OSP(BigInteger.valueOf(counter), 4);
            T.append(SHA(Z + C));
        }
        return T.substring(0,l);
    }

    /**
     * Generates random octet string
     * @param len intended length in octets of the seed
     * @return seed string size of len
     */
    public String seedRandom(int len){
        StringBuilder res = new StringBuilder();
        Random rand = new Random();
        for (int i = 0; i != len; ++i){
            res.append((char) rand.nextInt(256));
        }
        return res.toString();
    }
    /**
     * Applies xor operation to the corresponding characters of string a and b
     * @param a denotes first term
     * @param b denotes second term
     * @return string of xor result
     */
    String XORStrings(String a, String b){
        if (a.length() != b.length())
            throw new RuntimeException("Lengths of strings diverges!");
        StringBuilder res = new StringBuilder();
        for (int i = 0; i != a.length(); ++i){
            res.append((int) a.charAt(i) ^ (int)b.charAt(i));
        }
        return res.toString();
    }
    /**
     * Encryption operation
     * Using specified hashing algorithm
     * @param e public exponent
     * @param n public modulus
     * @param message message to be encrypted, an octet string of length mLen
     * @param L optional label to be associated with the message, by default, empty string
     * @return ciphertext, an octet string of length k
     */
    public String RSAES_OAEP_ENCRYPT(BigInteger e, BigInteger n, String message, String L){
        int mLen = message.length();
        if (mLen > k - 2*hLen - 2) throw new RuntimeException("Message too long!");
        // EME-OAEP Encoding:
        if (L == null) L = "";
        try {
            String lHash = SHA(L);
            StringBuilder tmp = new StringBuilder();
            String PS = String.valueOf(tmp.append("0".repeat((k - mLen - 2*hLen - 2))));
            String DB = lHash + PS + 0x01 + message;
            String seed = seedRandom(hLen);
            String dbMask = MGF1(seed, k - hLen - 1);
            String maskedDB = XORStrings(DB, dbMask);
            String seedMask = MGF1(maskedDB, hLen);
            String maskedSeed = XORStrings(seed, seedMask);
            String EM =  0x00 + maskedSeed + maskedDB;
            BigInteger m = OS2IP(EM);
            BigInteger c = RSAEP(e, n, m);
            return I2OSP (c, k);
        }
        catch (NoSuchAlgorithmException ex){
            System.out.println( "Exception thrown for incorrect algorithm: " + e ) ;
        }
        catch (RuntimeException ex){
            System.out.println(e);
        }
        return "";
    }
    /**
     * Decryption operation
     * Using SHA3-256
     * @param d private exponent
     * @param n public modulus
     * @param ciphertext ciphertext to be decrypted, an octet string of length k
     * @param L optional label whose association with the message
     * @return message, an octet string of length mLen, where mLen <= k - 2hLen - 2
     */
    public String  RSAES_OAEP_DECRYPT(BigInteger d, BigInteger n, String ciphertext, String L){
        System.out.println(ciphertext.length());
        if (ciphertext.length() != k || k < (2*hLen + 2))
            throw new RuntimeException("Decryption error!");
        try {
            BigInteger c = OS2IP(ciphertext);
            BigInteger m = RSADP(d, n, c);
            String EM = I2OSP(m, hLen);
            if (L == null) L = "";
            String lHash = SHA(L);
            char Y = EM.charAt(0);
            String maskedSeed = EM.substring(1, hLen);
            String maskedDB = EM.substring(hLen, k);
            String seedMask = MGF1(maskedDB, hLen);
            String seed = XORStrings(maskedSeed, seedMask);
            String dbMask = MGF1(seed, k - hLen - 1);
            String DB = XORStrings(maskedDB, dbMask);
            String lHash1 = DB.substring(0,hLen);
            int index = hLen;
            while(DB.charAt(index) == 0x00 ) index ++;
            String M = DB.substring(index+1);
            if(DB.charAt(index) != 0x01 || !Objects.equals(lHash, lHash1) || Y != 0)
                throw new RuntimeException();
            return M;
        }
        catch (RuntimeException ex){
            System.out.println("Decryption error: " + ex);
        }
        catch (NoSuchAlgorithmException ex) {
            System.out.println( "Exception thrown for incorrect algorithm: " + ex) ;
        }

        return "";
    }

}
