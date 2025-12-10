import java.io.Serializable;

public class User implements Serializable {
    String pubKeyB64;
    byte[] pwHash;
    byte[] salt;
    Map<String, String> attributes;

    public User(String pubKeyB64, byte[] pwHash, byte[] salt) {
        this.pubKeyB64 = pubKeyB64;
        this.pwHash = pwHash;
        this.salt = salt;
        this.attributes = attributes;
    }
}
