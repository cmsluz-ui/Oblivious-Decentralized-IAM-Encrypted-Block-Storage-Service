package sessionKeys;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class ECCKeyManager {

    private static String DIR;
    private static String PUB;
    private static String PRIV;

    public static void init(String baseDir) {
        DIR = baseDir + "client_keys/";
        PUB = DIR + "public.key";
        PRIV = DIR + "private.key";
        new File(DIR).mkdirs();
    }

    public static KeyPair loadKeyPair() throws Exception {
        File pub = new File(PUB);
        File priv = new File(PRIV);

        if (pub.exists() && priv.exists()) {
            return loadExistingKeyPair();
        }

        return storeKeyPair();
    }

    private static KeyPair storeKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();

        try (FileOutputStream fos = new FileOutputStream(PUB)) {
            fos.write(keyPair.getPublic().getEncoded());
        }
        try (FileOutputStream fos = new FileOutputStream(PRIV)) {
            fos.write(keyPair.getPrivate().getEncoded());
        }

        return keyPair;
    }

    private static KeyPair loadExistingKeyPair() throws Exception {
        byte[] pub = readAll(PUB);
        byte[] priv = readAll(PRIV);

        KeyFactory factory = KeyFactory.getInstance("EC");

        PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(pub));
        PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(priv));

        return new KeyPair(publicKey, privateKey);
    }

    private static byte[] readAll(String path) throws Exception {
        return java.nio.file.Files.readAllBytes(new File(path).toPath());
    }

    public static String getPublicKeyBase64(KeyPair key) {
        return Base64.getEncoder().encodeToString(key.getPublic().getEncoded());
    }

    public static byte[] sign(PrivateKey privateKey, byte[] msg) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(msg);
        return signature.sign();
    }
    
}
