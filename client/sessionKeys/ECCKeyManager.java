package sessionKeys;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.nio.file.*;

public class ECCKeyManager {

    private static final String DIR = "client_keys";
    private static final String PUB = DIR + "/public.key";
    private static final String PRIV = DIR + "/private.key";

    public static KeyPair loadKeyPair() throws Exception {
        File dir = new File(DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        File pub = new File(PUB);
        File priv = new File(PRIV);

        if (!pub.exists() || !priv.exists()) {
            return storeKeyPair();
        }

        return loadExistingKeyPair();
    }

    private static KeyPair storeKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();

        Files.write(Paths.get(PUB), keyPair.getPublic().getEncoded());
        Files.write(Paths.get(PRIV), keyPair.getPrivate().getEncoded());

        return keyPair;
    }

    private static KeyPair loadExistingKeyPair() throws Exception {
        byte[] pub = Files.readAllBytes(Paths.get(PUB));
        byte[] priv = Files.readAllBytes(Paths.get(PRIV));

        KeyFactory factory = KeyFactory.getInstance("EC");

        PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(pub));
        PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(priv));

        return new KeyPair(publicKey, privateKey);
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
