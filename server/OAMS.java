import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

import Token.TokenInfo;

import java.util.Base64;

public class OAMS {

    private static final int PORT = 7000;
    private static final String OAS_HOST = "localhost";
    private static final int OAS_PORT = 6000;

    private static final Map<String, String> blockToFile = new ConcurrentHashMap<>();
    private static final Map<String, String> pubKeys = new HashMap<>();

    private static final ConcurrentMap<String, ShareRecord> shares = new ConcurrentHashMap<>();

    private static final long TOKEN_VALIDITY_MS = 5 * 60 * 1000; // 5 minutes

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("OAMS running on port " + PORT);
        try {
            loadOASPublicKey();
        } catch (Exception e) {
            System.err.println("Failed to load OAS public key: " + e.getMessage());
            e.printStackTrace();
            return;
        }
        ExecutorService pool = Executors.newCachedThreadPool();

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
                String cmd;

                try {
                    cmd = in.readUTF();
                } catch (Exception e) {
                    break;
                }
                switch (cmd) {
                    case "REGISTER_OWNER":
                        registerOwner(in, out);
                        break;
                    case "CREATE_SHARE":
                        createShare(in, out);
                        break;
                    case "VALIDATE_TOKEN":
                        validateTokenRPC(in, out);
                        break;
                    case "DELETE_SHARE":
                        deleteShare(in, out);
                        break;
                    case "CHECK_ACCESS":
                        checkAccess(in, out);
                        break;
                    case "LIST_SHARED":
                        listShared(in, out);
                        break;
                    case "EXIT":
                        return;
                    default:
                        out.writeUTF("ERROR_UNKNOWN_CMD");
                        out.flush();
                }
            }
        } catch (Exception e) {
            e.getStackTrace();
            System.out.println("OAMS client disconnected or error: " + e.getMessage());
        }
    }

    private static void registerOwner(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String token = in.readUTF();
            String fileAnonId = in.readUTF();

            TokenInfo info = validateToken(token);
            if (!info.valid) {
                out.writeUTF("ERROR_INVALID_TOKEN: " + info.reason);
                out.flush();
                return;
            }

            String ownerAnonId = info.anonId;

            shares.compute(fileAnonId, (k, rec) -> {
                if (rec == null)
                    return new ShareRecord(ownerAnonId);
                else
                    return rec;
            });

            out.writeUTF("OK_REGISTER_OWNER");
            out.flush();
        } catch (Exception e) {
            out.writeUTF("ERROR_REGISTER_OWNER_EXCEPTION");
            out.flush();
        }
    }

    private static void validateTokenRPC(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String token = in.readUTF();
            TokenInfo info = validateToken(token);
            if (!info.valid) {
                out.writeUTF("ERROR_INVALID_TOKEN: " + info.reason);
                out.flush();
                return;
            }
            out.writeUTF("OK_VALIDATE");
            out.writeUTF(info.anonId);
            out.flush();
        } catch (Exception e) {
            out.writeUTF("ERROR_VALIDATE_TOKEN_EXCEPTION");
            out.flush();
        }
    }

    private static void createShare(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String token = in.readUTF();
            String fileAnonId = in.readUTF();
            String recipientPubKey = in.readUTF();
            String recipientName = in.readUTF();
            String permissions = in.readUTF();

            TokenInfo tokenInfo = validateToken(token);
            if (!tokenInfo.valid) {
                out.writeUTF("ERROR_INVALID_TOKEN: " + tokenInfo.reason);
                out.flush();
                return;
            }

            String ownerAnonId = tokenInfo.anonId;
            String recipientAnonId = sha256Base64(recipientPubKey);
            pubKeys.put(recipientName, recipientAnonId);

            shares.compute(fileAnonId, (k, rec) -> {
                if (rec == null) {
                    rec = new ShareRecord(ownerAnonId);
                }

                if (!rec.id.equals(ownerAnonId)) {
                    return rec;
                }
                rec.authorized.add(recipientAnonId);
                rec.permissions.put(recipientAnonId, permissions);
                return rec;
            });

            ShareRecord finalRec = shares.get(fileAnonId);
            if (!finalRec.id.equals(ownerAnonId)) {
                out.writeUTF("ERROR_NOT_OWNER");
                out.flush();
                return;
            }
            out.writeUTF("OK_CREATE_SHARE");
            out.flush();
        } catch (Exception e) {
            out.writeUTF("ERROR_CREATE_SHARE_EXCEPTION");
            out.flush();
        }
    }

    private static void deleteShare(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String token = in.readUTF();
            String fileAnonId = in.readUTF();
            String recipientPublicKey = in.readUTF();

            TokenInfo tokenInfo = validateToken(token);
            if (!tokenInfo.valid) {
                out.writeUTF("ERROR_INVALID_TOKEN: " + tokenInfo.reason);
                out.flush();
                return;
            }

            String ownerAnonId = tokenInfo.anonId;
            String recipientAnonId = sha256Base64(recipientPublicKey);

            ShareRecord record = shares.get(fileAnonId);
            if (record == null) {
                out.writeUTF("ERROR_NO_SUCH_SHARE");
                out.flush();
                return;
            }

            if (!record.id.equals(ownerAnonId)) {
                out.writeUTF("ERROR_NOT_OWNER");
                out.flush();
                return;
            }

            record.authorized.remove(recipientAnonId);
            record.permissions.remove(recipientAnonId);

            out.writeUTF("OK_DELETE_SHARE");
            out.flush();
        } catch (Exception e) {
            out.writeUTF("ERROR_DELETE_SHARE_EXCEPTION");
            out.flush();
        }

    }

    private static void checkAccess(DataInputStream in, DataOutputStream out) throws IOException {
        String token = in.readUTF();
        String fileAnonId = in.readUTF();
        String recipientUsername = in.readUTF();

        TokenInfo tokenInfo = validateToken(token);
        if (!tokenInfo.valid) {
            out.writeUTF("NOK_ACCESS");
            out.flush();
            System.out.println("nao e valida, " + tokenInfo.reason);
            return;
        }

        String subject = tokenInfo.anonId;
        ShareRecord record = shares.get(fileAnonId);
        if (record == null) {
            out.writeUTF("NOK_ACCESS");
            System.out.println("o record e null" + tokenInfo.reason);
            out.flush();
            return;
        }

        if (record.id.equals(subject) || record.authorized.contains(pubKeys.get(recipientUsername))) {
            out.writeUTF("OK_ACCESS");
        } else {
            out.writeUTF("NOK_ACCESS");
            System.out.println("geral" + tokenInfo.reason);
        }
        out.flush();
    }

    private static void listShared(DataInputStream in, DataOutputStream out) throws IOException {
        try {
            String token = in.readUTF();
            TokenInfo tokenInfo = validateToken(token);
            if (!tokenInfo.valid) {
                out.writeUTF("ERROR_INVALID_TOKEN: " + tokenInfo.reason);
                out.flush();
                return;
            }
            String subject = tokenInfo.anonId;

            List<String> owned = new ArrayList<>();
            List<String> sharedWithMe = new ArrayList<>();

            for (Map.Entry<String, ShareRecord> e : shares.entrySet()) {
                String file = e.getKey();
                ShareRecord record = e.getValue();
                if (record.id.equals(subject))
                    owned.add(file);
                if (record.authorized.contains(subject))
                    sharedWithMe.add(file);
            }

            out.writeUTF("OK_LIST_SHARED");
            out.writeInt(owned.size());
            for (String f : owned)
                out.writeUTF(f);
            out.writeInt(sharedWithMe.size());
            for (String f : sharedWithMe)
                out.writeUTF(f);
            out.flush();
        } catch (Exception e) {
            out.writeUTF("ERROR_LIST_EXCEPTION");
            out.flush();
        }
    }

    private static TokenInfo validateToken(String token) {
        TokenInfo tokenInfo = new TokenInfo();
        try {
            if (token == null || token.isEmpty()) {
                tokenInfo.valid = false;
                tokenInfo.reason = "NO_TOKEN";
                return tokenInfo;
            }
            byte[] raw = Base64.getDecoder().decode(token);
            String s = new String(raw, StandardCharsets.UTF_8);
            int p1 = s.indexOf('|');
            int p2 = s.indexOf('|', p1 + 1);
            if (p1 < 0 || p2 < 0) {
                tokenInfo.valid = false;
                tokenInfo.reason = "BAD_FORMAT";
                return tokenInfo;
            }
            String anonId = s.substring(0, p1);
            long timeStamp = Long.parseLong(s.substring(p1 + 1, p2));
            String sigB64 = s.substring(p2 + 1);
            byte[] sigBytes = Base64.getDecoder().decode(sigB64);

            long now = System.currentTimeMillis();
            if (timeStamp <= 0 || Math.abs(now - timeStamp) > TOKEN_VALIDITY_MS) {
                tokenInfo.valid = false;
                tokenInfo.reason = "TOKEN_EXPIRED";
                return tokenInfo;
            }

            try {
                Signature verifier = Signature.getInstance("SHA256withECDSA");
                verifier.initVerify(oasPubKey);
                String payload = anonId + "|" + timeStamp;
                verifier.update(payload.getBytes(StandardCharsets.UTF_8));
                boolean ok = verifier.verify(sigBytes);
                if (!ok) {
                    tokenInfo.valid = false;
                    tokenInfo.reason = "BAD_SIGNATURE";
                    return tokenInfo;
                }
            } catch (Exception e) {
                tokenInfo.valid = false;
                tokenInfo.reason = "SIG_VERIFY_ERROR";
                return tokenInfo;
            }

            boolean exists = checkAnonIdExistsWithAOS(anonId);
            if (!exists) {
                tokenInfo.valid = false;
                tokenInfo.reason = "UNKNOWN_SUBJECT";
                return tokenInfo;
            }

            tokenInfo.valid = true;
            tokenInfo.anonId = anonId;
            tokenInfo.issuedAt = timeStamp;
            return tokenInfo;
        } catch (Exception e) {
            tokenInfo.valid = false;
            tokenInfo.reason = "PARSE_ERROR";
            return tokenInfo;
        }
    }

    private static boolean checkAnonIdExistsWithAOS(String anonId) {
        try (Socket socket = new Socket(OAS_HOST, OAS_PORT);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())) {

            out.writeUTF("GET_USER_PUBKEY");
            out.writeUTF(anonId);
            out.flush();

            String answer = in.readUTF();
            if (answer.startsWith("ERROR"))
                return false;
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static void loadOASPublicKey() throws Exception {
        if (!Files.exists(OAS_PUB_PATH)) {
            throw new IOException("OAS public key not found at " + OAS_PUB_PATH.toString());
        }
        byte[] pubBytes = Files.readAllBytes(OAS_PUB_PATH);
        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubBytes);
        oasPubKey = kf.generatePublic(pubSpec);
        System.out.println("Loaded OAS public key from " + OAS_PUB_PATH.toString());
    }

    private static String sha256Base64(String input) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
