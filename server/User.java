class User {
    String pubKeyB64;
    byte[] pwHash;
    byte[] salt;

    User(String pubKeyB64, byte[] pwHash, byte[] salt) {
        this.pubKeyB64 = pubKeyB64;
        this.pwHash = pwHash;
        this.salt = salt;
    }
}
