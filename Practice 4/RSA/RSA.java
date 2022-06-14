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
     * Generates private (d), public (e) exponents and modulus (n).
     * @return BigInteger map of 3 values with d, e and n accordingly as char keys.
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
     * Requests key length in bits via console.
     * Sets length in octets of the modulus n.
     * @param scanner represents Scanner object for input.
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
     * Calculates message digest length for a specified hashing algorithm.
     * @param hashAlgorithm intended hashing algorithm.
     * @return hash length.
     * @throws NoSuchAlgorithmException
     */
    private static int calculateHashLength(String hashAlgorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
        return md.digest("".getBytes(StandardCharsets.UTF_8)).length;
    }
    /**
     * Requests hashing algorithm type via console until it is not valid.
     * Sets hash length in octets for specified algorithm.
     * @param scanner represents Scanner object for input.
     */
    void enterHashAlgorithm(Scanner scanner){
        System.out.println("Enter hashing algorithm: ");
        String hAlg = scanner.nextLine();
        try{
            hLen = calculateHashLength(hAlg);
            hashAlgorithm = hAlg;
        }
        catch (NoSuchAlgorithmException e){
            System.out.println("Invalid hashing algorithm" + e);
            enterHashAlgorithm(scanner);
        }
    }
    /**
     * Constructor for the RSA class.
     * Generates Scanner object with console input and
     * calls enterKeyLength() and enterHashAlgorithm() functions.
     */
    RSA(){
        Scanner scanner = new Scanner(System.in);
        enterKeyLength(scanner);
        enterHashAlgorithm(scanner);
    }
    /**
     * Encryption primitive.
     * @param e public exponent.
     * @param n public modulus.
     * @param m message representative, an integer between 0 and n - 1.
     * @return ciphertext representative, an integer between 0 and n - 1.
     */
    private static BigInteger RSAEP(BigInteger e, BigInteger n, BigInteger m){
        if ((m.compareTo(BigInteger.ZERO) < 0) || (m.compareTo(n.subtract(BigInteger.ONE)) > 0)){
            throw new RuntimeException("Message representative out of range!");
        }
        return m.modPow(e, n);
    };
    /**
     * Decryption primitive.
     * @param d private exponent.
     * @param n public modulus.
     * @param c ciphertext representative, an integer between 0 and n - 1.
     * @return message representative, an integer between 0 and n - 1.
     */
    private static BigInteger RSADP(BigInteger d, BigInteger n, BigInteger c){
        if ((c.compareTo(BigInteger.ZERO) < 0) || (c.compareTo(n.subtract(BigInteger.ONE)) > -1)){
            throw new RuntimeException("Ciphertext representative out of range!");
        }
        return c.modPow(d, n);
    };
    /**
     * Digital signature primitive.
     * @param d private exponent.
     * @param n public modulus.
     * @param m message representative, an integer between 0 and n - 1.
     * @return signature representative, an integer between 0 and n - 1.
     */
    private static BigInteger RSASP1(BigInteger d, BigInteger n, BigInteger m){
        if ((m.compareTo(BigInteger.ZERO) < 0) || (m.compareTo(n.subtract(BigInteger.ONE)) > 0)){
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
    private static BigInteger RSAVP1(BigInteger e, BigInteger n, BigInteger s){
        if ((s.compareTo(BigInteger.ZERO) < 0) || (s.compareTo(n.subtract(BigInteger.ONE)) > 0)){
            throw new RuntimeException("Signature representative out of range!");
        }
        return s.modPow(e, n);
    }
    /**
     * I2OSP converts a nonnegative integer into an octet string of a specified length.
     * @params x nonnegative integer to be converted.
     * @params xLen intended length of the resulting octet string.
     * @return octet string of length xLen.
     */
    private static byte[] I2OSP(BigInteger x, int xLen){
        if (x.compareTo(BigInteger.valueOf(256).pow(xLen)) > -1)
            throw new RuntimeException("Integer too large!");

        byte[] res = new byte[xLen];
        for(int i = 0; i != xLen; ++i){
            res[i] = (x.divide(BigInteger.valueOf(256).pow(xLen - i - 1)).byteValue());
        }
        return res;
    }
    /**
     * OS2IP converts an octet string into a nonnegative integer.
     * @params x octet string to be converted.
     * @return corresponding nonnegative integer.
     */
    private static BigInteger OS2IP(byte[] x){
        BigInteger res = BigInteger.ZERO;
        for (int i = 0; i != x.length; ++i){
            res = res.add(BigInteger.valueOf(x[i] & 0xFF).multiply(BigInteger.valueOf(256).pow(x.length - i - 1)));
        }
        return res;
    }
    /**
     * Hashing function.
     * @param str input message as an octet string.
     * @param hashAlgorithm intended type of the hash algorithm.
     * @return message digest as an octet string.
     */
    private static byte[] hashString(byte[] str, String hashAlgorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
        return md.digest(str);
    }
    /**
     * Mask generation function.
     * @param Z seed from which mask is generated, an octet string.
     * @param l intended length in octets of the mask.
     * @param hashAlgorithm intended type of the hash algorithm.
     * @return mask of l octets length.
     */
    private static byte[] MGF1(byte[] Z, int l, String hashAlgorithm) throws NoSuchAlgorithmException {

        int hLen = calculateHashLength(hashAlgorithm);
        if (l > Math.pow(2,hLen)) throw new RuntimeException("Mask too long!");
        byte[] T = new byte[l];

        byte[] tmp = new byte[Z.length + 4];
        System.arraycopy(Z, 0, tmp, 0, Z.length);
        int i = 0;
        for (int counter = 0; counter != Math.ceilDiv(l,hLen) - 1; ++ counter){
            byte[] C = I2OSP(BigInteger.valueOf(counter), 4);
            System.arraycopy(C, 0, tmp, Z.length, 4);
            byte[] tmp2 = hashString(tmp, hashAlgorithm);
            int k = 0;
            while(i < l && k < hLen) {
                T[i] = tmp2[k];
                k++; i++;
            }
        }
        return T;
    }
    /**
     * Generates random octet string.
     * @param len intended length in octets of the seed.
     * @return seed string of size len.
     */
    private static byte[] seedRandom(int len) throws NoSuchAlgorithmException {
        byte[] res = new byte[len];
        SecureRandom.getInstanceStrong().nextBytes(res);
        return res;
    }
    /**
     * Applies xor operation to the corresponding characters of string a and b.
     * @param a denotes first term.
     * @param b denotes second term.
     * @return string of \xor result.
     */
    private static byte[] XORStrings(byte[] a, byte[] b){
        if (a.length != b.length)
            throw new RuntimeException("Lengths of strings diverges!");
        byte[] res = new byte[a.length];
        for (int i = 0; i != a.length; ++i){
            res[i] = (byte) (a[i] ^ b[i]);
        }
        return res;
    }
    /**
     * Encryption operation.
     * Using specified hashing algorithm.
     * @param e public exponent.
     * @param n public modulus.
     * @param msg message to be encrypted, an octet string of length mLen.
     * @param l optional label to be associated with the message, by default, empty string.
     * @return ciphertext, an octet string of length k.
     */
    public byte[] RSAES_OAEP_ENCRYPT(BigInteger e, BigInteger n, String msg, String l){
        // EME-OAEP Encoding:
        try {
            int mLen = msg.length();
            if (mLen > k - 2*hLen - 2) throw new RuntimeException("Message too long!");

            byte[] message = msg.getBytes(StandardCharsets.UTF_8);
            byte[] L = l.getBytes(StandardCharsets.UTF_8);

            byte[] lHash = hashString(L, hashAlgorithm);

            byte[] DB = new byte[k - hLen - 1];
            System.arraycopy(lHash, 0, DB, 0, hLen);
            for (int i = hLen; i != DB.length - 1 - mLen; ++i){
                DB[i] = 0x00;
            }
            DB[DB.length-1-mLen] = 0x01;
            System.arraycopy(message, 0, DB, DB.length - mLen, mLen);

            byte[] seed = seedRandom(hLen);
            byte[] dbMask = MGF1(seed, k - hLen - 1, hashAlgorithm);
            byte[] maskedDB = XORStrings(DB, dbMask);
            byte[] seedMask = MGF1(maskedDB, hLen, hashAlgorithm);
            byte[] maskedSeed = XORStrings(seed, seedMask);

            byte[] EM = new byte[k];
            EM[0] = 0x00;
            System.arraycopy(maskedSeed, 0, EM, 1, hLen);
            System.arraycopy(maskedDB, 0, EM, hLen + 1, k - hLen - 1);

            //RSA encryption:
            BigInteger m = OS2IP(EM);
            BigInteger c = RSAEP(e, n, m);
            return I2OSP(c, k);
        }
        catch (NoSuchAlgorithmException ex){
            System.out.println( "Exception thrown for incorrect algorithm: " + e ) ;
        }
        catch (RuntimeException ex){
            System.out.println(e);
        }

        return msg.getBytes(StandardCharsets.UTF_8);
    }
    // piece of overloading to achieve default associated label L
    public byte[] RSAES_OAEP_ENCRYPT(BigInteger e, BigInteger n, String msg){
            return RSAES_OAEP_ENCRYPT(e ,n, msg,"");
    }
    /**
     * Decryption operation.
     * Using specified hashing algorithm.
     * @param d private exponent.
     * @param n public modulus.
     * @param ciphertext ciphertext to be decrypted, an octet string of length k.
     * @param l optional label associated with the message.
     * @return message, an octet string of length mLen, where mLen <= k - 2hLen - 2.
     */
    public byte[] RSAES_OAEP_DECRYPT(BigInteger d, BigInteger n, byte[] ciphertext, String l){
        try {
            if (ciphertext.length != k || k < (2*hLen + 2))
                throw new RuntimeException("Decryption error!");
            //RSA Decryption:
            BigInteger c = OS2IP(ciphertext);
            BigInteger m = RSADP(d, n, c);
            byte[] EM = I2OSP(m, k);

            // EME-OAEP Decoding:
            if (l == null) l = "";
            byte[] lHash = hashString(l.getBytes(StandardCharsets.UTF_8), hashAlgorithm);
            byte Y = EM[0];

            byte[] maskedSeed = Arrays.copyOfRange(EM, 1, hLen+1);
            byte[] maskedDB = Arrays.copyOfRange(EM, hLen+1, k);
            byte[] seedMask = MGF1(maskedDB, hLen, hashAlgorithm);
            byte[] seed = XORStrings(maskedSeed, seedMask);
            byte[] dbMask = MGF1(seed, k - hLen - 1, hashAlgorithm);
            byte[] DB = XORStrings(maskedDB, dbMask);
            byte[] lHash1 = Arrays.copyOfRange(DB, 0, hLen);

            int index = hLen;
            while(index < DB.length && DB[index] != 0x01 ){
                index++;
            }
            byte[] M = Arrays.copyOfRange(DB,index+1, DB.length);
            if(DB[index] != 0x01 || !Arrays.equals(lHash, lHash1) || Y != 0)
                throw new RuntimeException();
            return M;
        }
        catch (RuntimeException ex){
            System.out.println("Decryption error: " + ex);
        }
        catch (NoSuchAlgorithmException ex) {
            System.out.println( "Exception thrown for incorrect algorithm: " + ex) ;
        }

        return ciphertext;
    }
    //overloading to achieve default empty associated label
    public byte[] RSAES_OAEP_DECRYPT(BigInteger d, BigInteger n, byte[] ciphertext){
        return RSAES_OAEP_DECRYPT(d,n,ciphertext, "");
    }
    /**
     * Encryption operation.
     * @param e public exponent.
     * @param n public modulus.
     * @param msg message to be encrypted, an octet string of length mLen.
     * @return ciphertext, an octet string of length k.
     */
    public byte[] RSAES_PKCS1_V1_5_ENCRYPT(BigInteger e, BigInteger n, String msg){
        try {
            int mLen = msg.length();
            if (mLen > k - 11) throw new RuntimeException("Message too long!");
            byte[] message = msg.getBytes(StandardCharsets.UTF_8);

            // EME-PKCS1-v1_5 encoding:
            byte[] PS = seedRandom(k-mLen-3);

            byte[] EM = new byte[k];
            EM[0] = 0x00; EM[1] = 0x02;
            System.arraycopy(PS, 0, EM, 2, PS.length);
            EM[PS.length+2] = 0x00;
            System.arraycopy(message, 0, EM, PS.length+3, mLen);

            //RSA encryption:
            BigInteger m = OS2IP(EM);
            BigInteger c = RSAEP(e, n, m);
            return I2OSP(c, k);
        }
        catch (NoSuchAlgorithmException ex){
            System.out.println( "Exception thrown for incorrect algorithm: " + e ) ;
        }
        catch (RuntimeException ex){
            System.out.println(e);
        }

        return msg.getBytes(StandardCharsets.UTF_8);
    }
    /**
     * Decryption operation.
     * @param d private exponent.
     * @param n public modulus.
     * @param ciphertext ciphertext to be decrypted, an octet string of length k.
     * @return message, an octet string of length mLen, where mLen <= k - 2hLen - 2.
     */
    public byte[] RSAES_PKCS1_V1_5_DECRYPT(BigInteger d, BigInteger n, byte[] ciphertext){
        try {
            if (ciphertext.length != k || k < 11)
                throw new RuntimeException("Decryption error!");
            //RSA Decryption:
            BigInteger c = OS2IP(ciphertext);
            BigInteger m = RSADP(d, n, c);
            byte[] EM = I2OSP(m, k);

            // EME-PKCS1-v1_5 decoding:

            int index = EM.length-1;
            while(index > 2 && EM[index] != 0x00 ){
                index--;
            }
            if(EM[0] != 0x00 || EM[1] != 0x02 || EM[index] != 0x00 || index-2 < 8)
                throw new RuntimeException();

            byte[] M = new byte[EM.length - index - 1];
            System.arraycopy(EM, index+1, M, 0, EM.length-index-1);

            return M;
        }
        catch (RuntimeException ex){
            System.out.println("Decryption error: " + ex);
        }

        return ciphertext;
    }
}
