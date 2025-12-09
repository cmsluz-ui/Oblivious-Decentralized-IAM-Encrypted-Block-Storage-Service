
import encryption.FileDecryption;
import encryption.FileEncryption;
import encryption.KeywordSecurity;
import sessionKeys.ECCKeyManager;

import static encryption.KeywordSecurity.bytesToHex;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.*;

import javax.crypto.SecretKey;
import streamciphers.PBKDF2;

public class BlockStorageClient {

    private static final String CLIENT_ID = System.getProperty("client", "default");
    private static final String BASE_DIR = "clients/" + CLIENT_ID + "/";
    private static final String AUTH_DIR = BASE_DIR + "client_auth/";

    private static final int OBSS_PORT = 5000;
    private static final int OAS_PORT = 6000;
    private static final int BLOCK_SIZE = 4096;

    private static final String INDEX_FILE = BASE_DIR + "client_index.ser";
    private static final String SALT_FILE = AUTH_DIR + "salt.bin";
    private static final String CRYPTO_CONFIG = BASE_DIR + "cryptoconfig.txt";

    private static Map<String, List<String>> fileIndex = new HashMap<>();

    private static FileEncryption encryptor = null;
    private static FileDecryption decryptor = null;
    private static KeywordSecurity kwSec;

    private static KeyPair keyPair;
    private static String authToken = null;

    private static String clientPassword = null;

    public static void main(String[] args) throws Exception {
        System.out.println("=== CLIENT ID: " + CLIENT_ID + " ===");

        new File(BASE_DIR).mkdirs();
        new File(AUTH_DIR).mkdirs();

        ECCKeyManager.init(BASE_DIR);
        keyPair = ECCKeyManager.loadKeyPair();

        loadIndex();

        Socket socket = new Socket("localhost", OBSS_PORT);
        kwSec = new KeywordSecurity();

        try (
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                Scanner scanner = new Scanner(System.in);) {
            while (true) {
                System.out.print("Command (REGISTER/AUTH/PUT/GET/LIST/SEARCH/SHARE/EXIT): ");
                String cmd = scanner.nextLine().trim().toUpperCase();

                switch (cmd) {
                    case "REGISTER":
                        System.out.print("Create password: ");
                        String sessionPassword = scanner.nextLine().trim();
                        if (sessionPassword.isEmpty()) {
                            System.out.println("The system requires a password.");
                            break;
                        }

                        String result = registerClient(sessionPassword);
                        System.out.println("OAS replied with " + result);
                        if (result != null && result.startsWith("OK")) {
                            clientPassword = sessionPassword;
                        }
                        break;
                    case "AUTH":
                        System.out.print("Enter your password: ");
                        String userPassword = scanner.nextLine().trim();
                        if (userPassword.isEmpty()) {
                            System.out.println("The system requires a password.");
                            break;
                        }

                        String answer = authClient(userPassword);
                        System.out.println(answer);
                        break;
                    case "PUT":
                        if (clientPassword == null || authToken == null) {
                            System.out.println("You have to REGISTER and AUTH first.");
                            break;
                        }
                        System.out.print("Enter local file path: ");
                        String path = scanner.nextLine();
                        File file = new File(path);
                        if (!file.exists()) {
                            System.out.println("File does not exist.");
                            continue;
                        }
                        System.out.print("Enter keywords (comma-separated): ");
                        String kwLine = scanner.nextLine();
                        String[] input = readCryptoConfig();
                        if (input == null) {
                            System.out.println("Crypto config file is null.");
                            break;
                        }

                        String ciphersuite = input[0].contains(":") ? input[0].split(":", 2)[1].trim() : input[0].trim();
                        if (encryptor == null || !encryptor.getCypherSuite().equals(ciphersuite)) {
                            encryptor = new FileEncryption(ciphersuite, clientPassword.toCharArray());
                        }

                        List<String> keywords = new ArrayList<>();
                        if (!kwLine.trim().isEmpty()) {
                            for (String kw : kwLine.split(","))
                                keywords.add(kw.trim().toLowerCase());
                        }
                        putFile(file, keywords, clientPassword, out, in);
                        saveIndex();
                        break;

                    case "GET":
                        if (clientPassword == null || authToken == null) {
                            System.out.println("You have to REGISTER and AUTH first.");
                            break;
                        }
                        System.out.print("Enter filename to retrieve: ");
                        String filename = scanner.nextLine();

                        String[] configInput = readCryptoConfig();
                        if (configInput == null) {
                            System.out.println("Crypto config file is null.");
                            break;
                        }
                        String ciphersuiteInput = configInput[0].contains(":") ? configInput[0].split(":", 2)[1].trim() : configInput[0].trim();
                        if (encryptor == null || !encryptor.getCypherSuite().equals(ciphersuiteInput)) {
                            encryptor = new FileEncryption(ciphersuiteInput, clientPassword.toCharArray());
                        }
                        decryptor = new FileDecryption(encryptor.getCypherSuite());
                        getFile(filename, clientPassword, out, in);
                        break;

                    case "LIST":
                        System.out.print("Stored files:");
                        for (String f : fileIndex.keySet())
                            System.out.println(" - " + f);
                        break;

                    case "SEARCH":
                        System.out.print("Enter keyword to search: ");
                        String keyword = scanner.nextLine();
                        searchFiles(keyword, out, in);
                        break;

                    case "SHARE":
                        if (authToken == null) {
                            System.out.println("You must AUTH before sharing.");
                            break;
                        }
                        System.out.print("Enter the file you want to share: ");
                        String shareName = scanner.nextLine();

                        List<String> blocks = fileIndex.get(shareName);
                        if (blocks == null) {
                            System.out.println("That file is not in the index");
                            break;
                        }

                        System.out.print("Enter the public key of the recipient: ");
                        String recipientPublicKey = scanner.nextLine();

                        for (String blockId : blocks) {
                            String encryptedBlockId = bytesToHex(kwSec.encryptKeyword(blockId));
                            shareBlock(encryptedBlockId, recipientPublicKey);
                        }

                        System.out.println("File successfully shared");
                        break;
                    case "EXIT":
                        out.writeUTF("EXIT");
                        out.flush();
                        saveIndex();
                        return;

                    default:
                        System.out.println("Unknown command.");
                        break;
                }
            }
        } finally {
            socket.close();
        }
    }

    private static String registerClient(String password) {
        try (Socket socket = new Socket("localhost", OAS_PORT);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())) {

            byte[] salt = new byte[16];
            new java.security.SecureRandom().nextBytes(salt);

            saveSalt(salt);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] passwordHash = digest.digest((password + Base64.getEncoder().encodeToString(salt)).getBytes());

            String publicKey = ECCKeyManager.getPublicKeyBase64(keyPair);

            out.writeUTF("CREATE_REG");
            out.writeUTF(publicKey);
            out.writeUTF(Base64.getEncoder().encodeToString(salt));
            out.writeUTF(Base64.getEncoder().encodeToString(passwordHash));

            out.writeInt(0); // TODO: write attributes
            out.flush();

            return in.readUTF();
        } catch (Exception e) {
            e.printStackTrace();
            return "ERROR_EXCEPTION: " + e.getMessage();
        }
    }

    private static String authClient(String password) {
        try (Socket socket = new Socket("localhost", OAS_PORT);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())) {

            String publicKey = ECCKeyManager.getPublicKeyBase64(keyPair);

            out.writeUTF("AUTH_START");
            out.writeUTF(publicKey);
            out.flush();

            String nonce = in.readUTF();
            long timeStamp = in.readLong();

            String msg = nonce + "|" + timeStamp;
            byte[] signature = ECCKeyManager.sign(keyPair.getPrivate(), msg.getBytes());

            byte[] salt = loadSalt();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] passwordHash = digest.digest((password + Base64.getEncoder().encodeToString(salt)).getBytes());

            out.writeUTF("AUTH_RESP");
            out.writeUTF(publicKey);
            out.writeUTF(nonce);
            out.writeLong(timeStamp);
            out.writeUTF(Base64.getEncoder().encodeToString(signature));
            out.writeUTF(Base64.getEncoder().encodeToString(passwordHash));
            out.flush();

            String result = in.readUTF();
            if (result.equals("OK_AUTH")) {
                authToken = in.readUTF();
                clientPassword = password;
                return "You were authenticated. Your token is the following: " + authToken;
            } else {
                return "You were not authenticated: " + result;
            }
        } catch (FileNotFoundException fE) {
            return "Salt not found. If you haven't, please REGISTER first.";
        } catch (Exception e) {
            e.printStackTrace();
            return "ERROR_EXCEPTION: " + e.getMessage();
        }
    }

    private static void saveSalt(byte[] salt) throws IOException {
        new File("client_auth").mkdirs();
        try (FileOutputStream fos = new FileOutputStream(SALT_FILE)) {
            fos.write(salt);
        }
    }

    private static byte[] loadSalt() throws IOException {
        return java.nio.file.Files.readAllBytes(new File(SALT_FILE).toPath());
    }

    private static void putFile(File file, List<String> keywords, String password, DataOutputStream out,
            DataInputStream in)
            throws IOException {
        List<String> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[BLOCK_SIZE];
            int bytesRead;
            int blockNum = 0;
            PBKDF2 pbkdf2 = new PBKDF2(password.toCharArray());
            SecretKey passwordKey = pbkdf2.deriveKey(file.getName(), encryptor.getCypherSuite());

            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] blockData = Arrays.copyOf(buffer, bytesRead);
                blockData = encryptor.encrypt(blockData, passwordKey);
                String blockId = file.getName() + "_block_" + blockNum++;
                String encryptedBlockId = bytesToHex(kwSec.encryptKeyword(blockId));

                out.writeUTF("STORE_BLOCK");
                out.writeUTF(authToken == null ? "" : authToken);
                out.writeUTF(encryptedBlockId);
                out.writeInt(blockData.length);
                out.write(blockData);

                // Send keywords for first block only
                if (blockNum == 1) {
                    out.writeInt(keywords.size());
                    for (String kw : keywords) {
                        String encryptedKw = bytesToHex(kwSec.encryptKeyword(kw));
                        out.writeUTF(encryptedKw);
                    }
                    System.out.println("ciphersuite used: " + encryptor.getCypherSuite());
                    System.out.println("/nSent keywords./n"); // Just for debug
                } else {
                    out.writeInt(0); // no keywords for other blocks
                }

                out.flush();
                String response = in.readUTF();
                if (!response.equals("OK")) {
                    System.out.println("Error storing block: " + blockId + " -> " + response);
                    return;
                }
                blocks.add(blockId);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
        fileIndex.put(file.getName(), blocks);
        System.out.println();
        System.out.println("File stored with " + blocks.size() + " blocks.");
    }

    private static void getFile(String filename, String password, DataOutputStream out, DataInputStream in)
            throws IOException {
        List<String> blocks = fileIndex.get(filename);
        if (blocks == null) {
            System.out.println();
            System.out.println("File not found in local index.");
            return;
        }
        try (FileOutputStream fos = new FileOutputStream("retrieved_" + filename)) {
            for (String blockId : blocks) {
                String encryptedBlockId = bytesToHex(kwSec.encryptKeyword(blockId));
                out.writeUTF("GET_BLOCK");
                out.writeUTF(authToken == null ? "" : authToken);
                out.writeUTF(encryptedBlockId);
                out.flush();
                int length = in.readInt();
                if (length == -1) {
                    System.out.println("Block not found: " + blockId);
                    return;
                }
                byte[] data = new byte[length];
                in.readFully(data);
                byte[] decryptedBlock = null;
                try {
                    decryptedBlock = decryptor.decrypt(data, filename);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                System.out.print(".");
                fos.write(decryptedBlock);
            }
        } catch (Exception e) {
            System.out.println("The file has been tampered. Aborting command...");
            return;
        }
        System.out.println();
        System.out.println("File reconstructed: retrieved_" + filename);
    }

    private static void searchFiles(String keyword, DataOutputStream out, DataInputStream in) throws IOException {
        try {
            out.writeUTF("SEARCH");
            String encryptedKw = bytesToHex(kwSec.encryptKeyword(keyword));
            out.writeUTF(encryptedKw);
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
        int count = in.readInt();
        System.out.println();
        System.out.println("Search results:");
        for (int i = 0; i < count; i++) {
            System.out.println(" - " + in.readUTF());
        }
    }

    private static void shareBlock(String encryptedBlockId, String recipientPublicKey) {
        try (Socket socket = new Socket("localhost", 7000);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream())) {
            out.writeUTF("CREATE_SHARE");
            out.writeUTF(authToken == null ? "" : authToken);
            out.writeUTF(encryptedBlockId);
            out.writeUTF(recipientPublicKey);
            out.writeUTF("GET");
            out.flush();

            String answer = in.readUTF();
            System.out.println("Share block answer: " + answer);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String[] readCryptoConfig() {
        File configFile = new File("client/cryptoconfig.txt");
        try (BufferedReader reader = new BufferedReader(new FileReader(configFile))) {
            List<String> lines = new ArrayList<>();
            reader.lines().forEach(lines::add);
            String ciphersuite = null;
            String user = null;
            for (String line : lines) {
                if (line.toLowerCase().startsWith("ciphersuite:")) {
                    ciphersuite = line.split(":", 2)[1].trim();
                } else if (line.toLowerCase().startsWith("user:")) {
                    user = line.split(":", 2)[1].trim();
                }
            }
            if (ciphersuite == null)
                return null;
            return new String[] { ciphersuite, user };
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void saveIndex() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(INDEX_FILE))) {
            oos.writeObject(fileIndex);
        } catch (IOException e) {
            System.err.println("Failed to save index: " + e.getMessage());
        }
    }

    private static void loadIndex() {
        File f = new File(INDEX_FILE);
        if (!f.exists())
            return;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            fileIndex = (Map<String, List<String>>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Failed to load index: " + e.getMessage());
        }
    }
}
