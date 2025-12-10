
import encryption.FileDecryption;
import encryption.FileEncryption;
import encryption.KeywordSecurity;
import static encryption.KeywordSecurity.bytesToHex;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.UnrecoverableKeyException;
import java.util.*;

import javax.crypto.SecretKey;
import streamciphers.PBKDF2;

public class BlockStorageClient {
    private static final int PORT = 5000;
    private static final int BLOCK_SIZE = 4096;
    private static final String INDEX_FILE = "client_index.ser";

    private static Map<String, List<String>> fileIndex = new HashMap<>();
    private static Map<String, String> passwordIndex = new HashMap<>();

    private static FileEncryption encryptor;
    private static FileDecryption decryptor;
    private static KeywordSecurity kwSec;

    public static void main(String[] args) throws IOException, ClassNotFoundException, Exception {
        loadIndex();

        Socket socket = new Socket("localhost", PORT);
        kwSec = new KeywordSecurity();

        try (
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                Scanner scanner = new Scanner(System.in);) {
            String password = null;
            while (true) {
                System.out.print("Command (PUT/GET/LIST/SEARCH/EXIT): ");
                String cmd = scanner.nextLine().toUpperCase();

                switch (cmd) {
                    case "PUT":
                        System.out.print("Enter local file path: ");
                        String path = scanner.nextLine();
                        File file = new File(path);
                        if (!file.exists()) {
                            System.out.println("File does not exist.");
                            continue;
                        }
                        System.out.print("Enter keywords (comma-separated): ");
                        String kwLine = scanner.nextLine();
                        String[] input = new String[3];
                        input = readCryptoConfig();
                        String ciphersuite = input[0].split(" ")[1];
                        String user = input[1].split(" ")[1];
                        password = input[2].split(" ")[1];

                        encryptor = new FileEncryption(ciphersuite, password.toCharArray());
                        List<String> keywords = new ArrayList<>();
                        if (!kwLine.trim().isEmpty()) {
                            for (String kw : kwLine.split(","))
                                keywords.add(kw.trim().toLowerCase());
                        }
                        putFile(file, keywords, password, out, in);
                        saveIndex();
                        break;

                    case "GET":
                        System.out.print("Enter filename to retrieve: ");
                        String filename = scanner.nextLine();
                        decryptor = new FileDecryption(encryptor.ciphersuite);
                        getFile(filename, password, out, in);
                        break;

                    case "LIST":
                        System.out.println("Stored files:");
                        for (String f : fileIndex.keySet())
                            System.out.println(" - " + f);
                        break;

                    case "SEARCH":
                        System.out.print("Enter keyword to search: ");
                        String keyword = scanner.nextLine();
                        searchFiles(keyword, out, in);
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

    private static void putFile(File file, List<String> keywords, String password, DataOutputStream out,
            DataInputStream in)
            throws IOException {
        List<String> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[BLOCK_SIZE];
            int bytesRead;
            int blockNum = 0;
            PBKDF2 pbkdf2 = new PBKDF2(password.toCharArray());
            SecretKey passwordKey = pbkdf2.deriveKey(file.getName(), encryptor.ciphersuite);

            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] blockData = Arrays.copyOf(buffer, bytesRead);
                blockData = encryptor.encrypt(blockData, passwordKey);
                String blockId = file.getName() + "_block_" + blockNum++;
                String encryptedBlockId = bytesToHex(kwSec.encryptKeyword(blockId));

                out.writeUTF("STORE_BLOCK");
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
                    System.out.println("Error storing block: " + blockId);
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
                } catch (UnrecoverableKeyException e) {
                    System.out.println("Cannot decrypt: you do not have permission for this file.");
                    return;
                } catch (Exception e) {
                    e.printStackTrace();
                    return;
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

    private static String[] readCryptoConfig() {
        File configFile = new File("client/cryptoconfig.txt");
        try (BufferedReader reader = new BufferedReader(new FileReader(configFile))) {
            return reader.lines().toArray(String[]::new);
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
