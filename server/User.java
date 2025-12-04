import java.io.*;
import java.util.*;

class User {
    String pubKeyB64;
    byte[] pwHash;
    byte[] salt;
    Map<String, String> attributes;

    User(String pubKeyB64, byte[] pwHash, byte[] salt, Map<String, String> attributes) {
        this.pubKeyB64 = pubKeyB64;
        this.pwHash = pwHash;
        this.salt = salt;
        this.attributes = attributes;
    }
}
