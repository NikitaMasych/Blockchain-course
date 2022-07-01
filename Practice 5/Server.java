import java.security.PublicKey;
import java.util.HashMap;

public class Server {
    public static final Server INSTANCE = new Server(); // Server is singleton
    private final HashMap<byte[], KeyPair> voters = new HashMap<>();
    private Server(){
        // do something
    }
    /**
     * Checks whether passportID is valid and user is allowed to vote.
     * @param passportID denotes string containing passport ID.
     * @return true if user is allowed to vote, otherwise - false.
     */
    private static boolean verify(String passportID){
        // do some work
        return true;
    }
    /**
     * Function intends to interact with external device to get passportID.
     * @return string as an passportID.
     */
    private static String scanPassportID(){
        String passportID = "some id"; // do some work;
        return passportID;
    }
    /**
     * Scans and verifies passportID.
     * @return correct passportID in string format.
     * @throws RuntimeException if user is not eligible to vote / passportID invalid.
     */
    public static String getPassportID() throws RuntimeException{
        String passportID = scanPassportID();
        if (!verify(passportID))
            throw new RuntimeException("Not eligible to vote!");
        return passportID;
    }
    /**
     * Adds user to the database.
     * Generates RSA key pair, which will be used for encryption and decryption of the choice.
     * @param address intended user account address.
     */
    public void addUser(byte[] address) throws Exception {
        KeyPair keyPair = KeyPair.genKeyPairRSA();
        voters.put(address, keyPair);
    }
    /**
     * Gets public key for specified user.
     * @param address intended account address.
     * @return public key, necessary for the encryption of desired choice.
     */
    public PublicKey provideEncryptionKey(byte[] address) {
        return voters.get(address).publicKey;
    }
}
