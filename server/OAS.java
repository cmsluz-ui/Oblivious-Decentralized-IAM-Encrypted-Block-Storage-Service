import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;

public class OAS {

    private static final int PORT = 6000;
    private static Map<String, User> users = new HashMap<>();
    private static Map<String, String> pendingNonces = new ConcurrentHashMap<>();
    private static final Path OAS_KEYS_DIR = Paths.get("oaskeys");
    private static final Path OAS_PRIV_FILE = OAS_KEYS_DIR.resolve("oas_private.pkcs8");
    private static final Path OAS_PUB_FILE  = OAS_KEYS_DIR.resolve("oas_public.x509");
    private static PrivateKey oasPrivateKey = null;
    private static PublicKey oasPublicKey = null;
    
    public static void main(String[] args) throws IOException {

        try {
            loadOrCreateOASKeypair();
        } catch (Exception e) {
            System.err.println("Failed to load or create OAS keypair: " + e.getMessage());
            e.printStackTrace();
            return;
        }
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("OAS running on port " + PORT);

        ExecutorService pool = Executors.newCachedThreadPool();
        loadUsers();
        while (true) {
            Socket client = serverSocket.accept();
            pool.submit(() -> handleClient(client));
        }
    }

    private static void handleClient(Socket socket) {
        try (
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
            while (true) {
                String cmd = in.readUTF();

                switch (cmd) {
                    case "CREATE_REG":
                        CreateRegistration(in, out);
                        break;

                    case "MODIFY_REG":
                        ModifyRegistration(in, out);
                        break;

                    case "AUTH_START":
                        AuthStart(in, out);
                        break;

                    case "AUTH_RESP":
                        AuthResponse(in, out);
                        break;

                    case "GET_USER_PUBKEY":
                        GetUserPubKey(in, out);
                        break;

                    case "EXIT":
                        return;

                    default:
                        out.writeUTF("ERROR: Unknown OAS command");
                        out.flush();
                }
            }

        } catch (Exception e) {
            System.out.println("OAS client disconnected.");
        }
    }

    private static void CreateRegistration(DataInputStream in, DataOutputStream out) throws IOException {
    try {
        
        String plaintext = in.readUTF();        // "pubKey|salt|pwHash"
        byte[] receivedHash = Base64.getDecoder().decode(in.readUTF());
        byte[] signature = Base64.getDecoder().decode(in.readUTF());

        int attrCount = in.readInt();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] computedHash = digest.digest(plaintext.getBytes());

        if (!MessageDigest.isEqual(receivedHash, computedHash)) {
            out.writeUTF("ERROR_BAD_HASH");
            out.flush();
            return;
        }

        String[] parts = plaintext.split("\\|");
        if (parts.length != 3) {
            out.writeUTF("ERROR_BAD_FORMAT");
            out.flush();
            return;
        }

        String pubKeyB64 = parts[0];
        byte[] salt = Base64.getDecoder().decode(parts[1]);
        byte[] pwHash = Base64.getDecoder().decode(parts[2]);

        PublicKey clientPubKey = loadECPublicKey(pubKeyB64);

        boolean ok = verifySignature(clientPubKey, receivedHash, signature);
        if (!ok) {
            out.writeUTF("ERROR_BAD_SIGNATURE");
            out.flush();
            return;
        }

        
        //Load attributes
        Map<String, String> attrs = new HashMap<>();
        for (int i = 0; i < attrCount; i++) {
            String key = in.readUTF();
            String value = in.readUTF();
            attrs.put(key, value);
        }   
        String anonId = convertId(pubKeyB64);
        User u = new User(pubKeyB64, pwHash, salt, attrs);
        users.put(anonId, u);
        saveUsers();
        out.writeUTF("OK_CREATE_REG");
        out.flush();

    } catch (Exception e) {
        out.writeUTF("ERROR_CREATE_REG");
        out.flush();
    }
}


    private static void ModifyRegistration(DataInputStream in, DataOutputStream out) throws IOException {
        // Allows users to modify attributes previously registered by the respective
        // user
        out.writeUTF("OK_MODIFY_REG");
        out.flush();
    }

    private static void AuthStart(DataInputStream in, DataOutputStream out) throws IOException {
        String pubKeyB64 = in.readUTF();
        String anonId = convertId(pubKeyB64);

        if (!users.containsKey(anonId)) {
            out.writeUTF("ERROR_NO_SUCH_USER");
            return;
        }

        String nonce = UUID.randomUUID().toString();
        long timeStamp = System.currentTimeMillis();

        pendingNonces.put(nonce, anonId + "|" + timeStamp);

        out.writeUTF(nonce);
        out.writeLong(timeStamp);
        out.flush();
    }

    private static void AuthResponse(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String pubKeyB64 = in.readUTF();
            String nonce = in.readUTF();
            long timeStamp = in.readLong();
            String signatureB64 = in.readUTF();
            String pwHash = in.readUTF();

            String anonId = convertId(pubKeyB64);

            User u = users.get(anonId);
            if (u == null) {
                out.writeUTF("ERROR_NO_SUCH_USER");
                pendingNonces.remove(nonce);

                return;
            }

            String storedNonce = pendingNonces.get(nonce);
            // check if nonce exists
            if (!pendingNonces.containsKey(nonce)) {
                out.writeUTF("ERROR_NONCE_DOES_NOT_EXIST");
                pendingNonces.remove(nonce);
                return;
            }

            String[] attributes = storedNonce.split("\\|");
            String storedAnonId = attributes[0];
            long storedTimeStamp = Long.parseLong(attributes[1]);

            // check if correct nonce
            if (!storedAnonId.equals(anonId)) {
                out.writeUTF("ERROR_BAD_NONCE");
                pendingNonces.remove(nonce);
                return;
            }

            // check if correct timestamp
            if (storedTimeStamp != timeStamp) {
                out.writeUTF("ERROR_BAD_TIMESTAMP");
                pendingNonces.remove(nonce);
                return;
            }

            // check pass hash
            if (!Base64.getEncoder().encodeToString(u.pwHash).equals(pwHash)) {
                out.writeUTF("ERROR_BAD_PASSWORD");
                pendingNonces.remove(nonce);
                return;
            }

            // verify signature
            PublicKey pubKey = loadECPublicKey(pubKeyB64);
            String msg = nonce + "|" + timeStamp + "|" + pubKeyB64 + "|" + pwHash;
            boolean check = verifySignature(pubKey, msg.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(signatureB64));
            if (!check) {
                out.writeUTF("ERROR_BAD_SIGNATURE");
                pendingNonces.remove(nonce);
                return;
            }

            String token = generateToken(anonId);
            out.writeUTF("OK_AUTH");
            out.writeUTF(token);
            out.flush();

            pendingNonces.remove(nonce);
        } catch (Exception e) {
            out.writeUTF("ERROR_AUTH_EXCEPTION");
            out.flush();
        }
    }

    private static PublicKey loadECPublicKey(String b64) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(b64);
        KeyFactory factory = KeyFactory.getInstance("EC");
        return factory.generatePublic(new X509EncodedKeySpec(bytes));
    }

    private static boolean verifySignature(PublicKey key, byte[] msg, byte[] signature) {
        try {
            Signature sign = Signature.getInstance("SHA256withECDSA");
            sign.initVerify(key);
            sign.update(msg);
            return sign.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    private static String generateToken(String anonId) {
    try {
        long ts = System.currentTimeMillis();
        String payload = anonId + "|" + ts;
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(oasPrivateKey);
        signer.update(payload.getBytes(StandardCharsets.UTF_8));
        byte[] signature = signer.sign();
        String sigB64 = Base64.getEncoder().encodeToString(signature);
        String tokenPlain = payload + "|" + sigB64; // anonId|ts|sigB64
        return Base64.getEncoder().encodeToString(tokenPlain.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
        throw new RuntimeException("Failed to generate signed token: " + e.getMessage(), e);
    }
}
private static void loadOrCreateOASKeypair() throws Exception {
    if (!Files.exists(OAS_KEYS_DIR)) {
        Files.createDirectories(OAS_KEYS_DIR);
    }

    if (Files.exists(OAS_PRIV_FILE) && Files.exists(OAS_PUB_FILE)) {
        // load keys
        byte[] privBytes = Files.readAllBytes(OAS_PRIV_FILE);
        byte[] pubBytes  = Files.readAllBytes(OAS_PUB_FILE);

        KeyFactory kf = KeyFactory.getInstance("EC");
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privBytes);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubBytes);

        oasPrivateKey = kf.generatePrivate(privSpec);
        oasPublicKey  = kf.generatePublic(pubSpec);
        System.out.println("Loaded existing OAS ECDSA keypair.");
    } else {
        // generate new keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256); // secp256r1
        KeyPair kp = kpg.generateKeyPair();

        oasPrivateKey = kp.getPrivate();
        oasPublicKey  = kp.getPublic();

        // write keys to files (DER encoding)
        Files.write(OAS_PRIV_FILE, oasPrivateKey.getEncoded());
        Files.write(OAS_PUB_FILE, oasPublicKey.getEncoded());
        System.out.println("Generated and saved new OAS ECDSA keypair to " + OAS_KEYS_DIR.toString());
    }
}
    private static byte[] getOASPublicKeyBytes() {
    return oasPublicKey.getEncoded();
}

    private static void GetUserPubKey(DataInputStream in, DataOutputStream out) throws IOException {
        String anonId = in.readUTF();
        User u = users.get(anonId);
        if (u == null) {
            out.writeUTF("ERROR_NO_SUCH_USER");
            return;
        }
        out.writeUTF(u.pubKeyB64);
        out.flush();
    }

    private static String convertId(String id) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(id.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void loadUsers() {
    File f = new File("users.ser");
    if (f.exists()) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            users = (Map<String, User>) ois.readObject();
        } catch (Exception e) {
            users = new HashMap<>();
        }
    }
}
private static void saveUsers() {
    try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("users.ser"))) {
        oos.writeObject(users);
    } catch (Exception e) {
        e.printStackTrace();
    }
}
}
