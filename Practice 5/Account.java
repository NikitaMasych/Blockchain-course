import java.util.ArrayList;

public class Account {
    private final String accountID;
    public byte[] openAccountID;
    public ArrayList<KeyPair> keyPairs;
    boolean voted;
    /**
     * Generates unique user's identifier and KeyPair
     * @param govElect is either true if election is being held
     *                 on government scale or false otherwise
     */
    Account(boolean govElect){
        keyPairs = new ArrayList<KeyPair>();
        keyPairs.add(new KeyPair());
        if (govElect) accountID = passportID();
        else accountID = keyPairs.get(0).publicKey.toString();
        openAccountID = Hash.calculateHash(accountID, "SHA-256");
        voted = false;
    }
    /**
     * Adds key pair to wallet
     * @param keyPair intended key pair
     */
    public void addKeyPair(KeyPair keyPair){
        keyPairs.add(keyPair);
    }
    /**
     * Signs message with specified keyPair of user
     * @param message intended message
     * @param keyIndex stands for keyPair index of the wallet
     * @return signed message as an octet string
     */
    public byte[] signData(String message, int keyIndex){
        return SIGNATURE.signData(keyPairs.get(keyIndex).privateKey, message);
    }
    /**
     * User scans passport and government's database returns his passport ID
     * @return passport ID as a string
     */
    private String passportID(){
        return "some id";
    }
}
