// Ref. Iniial code for a Java Implentation of a Block-Storage Server
// This is a naive and insecure implementation as initial reference for
// Project assignment

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class OBSS {
    private static final int PORT = 5000;
    private static final String BLOCK_DIR = "server/blockstorage";
    private static final String META_FILE = "metadata.ser";

    private static final Map<String, String> owners = new ConcurrentHashMap<>();
    private static final String OWNERS_FILE = "owners.ser";
    // Map filename -> list of keywords
    private static Map<String, List<String>> metadata = new HashMap<>();

    public static void main(String[] args) throws IOException {
        File dir = new File(BLOCK_DIR);
        if (!dir.exists())
            dir.mkdirs();
        loadMetadata();

        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("BlockStorageServer running on port " + PORT);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            new Thread(() -> handleClient(clientSocket)).start();
        }
    }

    private static void handleClient(Socket socket) {
        try (
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());) {
            String command;
            while ((command = in.readUTF()) != null) {
                switch (command) {
                    case "STORE_BLOCK":
                        storeBlock(in, out);
                        break;
                    case "GET_BLOCK":
                        getBlock(in, out);
                        break;
                    case "LIST_BLOCKS":
                        listBlocks(out);
                        break;
                    case "SEARCH":
                        searchBlocks(in, out);
                        break;
                    case "EXIT":
                        return;
                    default:
                        out.writeUTF("ERROR: Unknown command");
                        out.flush();
                        break;
                }
            }
        } catch (IOException e) {
            System.err.println("Client disconnected.");
        }
    }

    private static void storeBlock(DataInputStream in, DataOutputStream out) throws IOException {
    String token = in.readUTF();
    String encryptedBlockId = in.readUTF();
    int length = in.readInt();
    byte[] data = new byte[length];
    in.readFully(data);

    // Validate token with OAMS to get owner anonId
    String ownerAnonId = null;
    try (Socket oams = new Socket("localhost", 7000);
         DataOutputStream outO = new DataOutputStream(oams.getOutputStream());
         DataInputStream inO = new DataInputStream(oams.getInputStream())) {

        outO.writeUTF("VALIDATE_TOKEN");
        outO.writeUTF(token == null ? "" : token);
        outO.flush();

        String response = inO.readUTF();
        if ("OK_VALIDATE".equals(response)) {
            ownerAnonId = inO.readUTF();
        } else {
            // token invalid - reject storing
            out.writeUTF("ERROR_INVALID_TOKEN");
            out.flush();
            return;
        }
    } catch (Exception e) {
        // couldn't reach OAMS; reject the store (fail closed)
        out.writeUTF("ERROR_OAMS_UNAVAILABLE");
        out.flush();
        return;
    }

    // Write block to disk
    File blockFile = new File(BLOCK_DIR, encryptedBlockId);
    try (FileOutputStream fos = new FileOutputStream(blockFile)) {
        fos.write(data);
    }

    // record owner mapping
    owners.put(encryptedBlockId, ownerAnonId);
    saveOwners();

    // Read optional metadata (keywords)
    int keywordCount = in.readInt();
    if (keywordCount > 0) {
        List<String> keywords = new ArrayList<>();
        for (int i = 0; i < keywordCount; i++) {
            keywords.add(in.readUTF().toLowerCase());
        }
        metadata.put(encryptedBlockId, keywords);
        saveMetadata();
    }

    // Inform OAMS about owner (optional - creates OAMS shareRecord owner if necessary)
    notifyOwnerToOAMS(token, encryptedBlockId);

    out.writeUTF("OK");
    out.flush();
}

    private static void getBlock(DataInputStream in, DataOutputStream out) throws IOException {
    String token = in.readUTF();
    String encryptedBlockId = in.readUTF();

    boolean allowed = false;

    // Primary check: ask OAMS for permission (OAMS now verifies signature)
    try (Socket oams = new Socket("localhost", 7000);
         DataOutputStream outO = new DataOutputStream(oams.getOutputStream());
         DataInputStream inO = new DataInputStream(oams.getInputStream())) {

        outO.writeUTF("CHECK_ACCESS");
        outO.writeUTF(token == null ? "" : token);
        outO.writeUTF(encryptedBlockId); // pass file/block anonId
        outO.flush();

        String response = inO.readUTF();
        allowed = "OK_ACCESS".equals(response);
    } catch (Exception e) {
        allowed = false;
    }

    // Secondary / defence-in-depth: check local owner mapping if OAMS was unreachable
    if (!allowed) {
        if (token != null && !token.isEmpty()) {
            // extract anonId from token only if it's valid format and signature — attempt to validate with OAMS
            // We already tried to validate with OAMS above. If OAMS was unreachable, we should not grant access.
            // So do NOT permit access here.
        }
        out.writeInt(-1); // deny access
        out.flush();
        return;
    }

    File blockFile = new File(BLOCK_DIR, encryptedBlockId);
    if (!blockFile.exists()) {
        out.writeInt(-1);
        out.flush();
        return;
    }
    byte[] data = java.nio.file.Files.readAllBytes(blockFile.toPath());
    out.writeInt(data.length);
    out.write(data);
    out.flush();
}

    private static void listBlocks(DataOutputStream out) throws IOException {
        String[] files = new File(BLOCK_DIR).list();
        if (files == null)
            files = new String[0];
        out.writeInt(files.length);
        for (String f : files)
            out.writeUTF(f);
        out.flush();
    }

    private static void searchBlocks(DataInputStream in, DataOutputStream out) throws IOException {
        String keyword = in.readUTF().toLowerCase();
        List<String> results = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : metadata.entrySet()) {
            if (entry.getValue().contains(keyword)) {
                results.add(entry.getKey());
            }
        }
        out.writeInt(results.size());
        for (String f : results)
            out.writeUTF(f);
        out.flush();
    }

    private static void notifyOwnerToOAMS(String token, String encryptedBlockId) {
        try (Socket socket = new Socket("localhost", 7000);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
            out.writeUTF("REGISTER_OWNER");
            out.writeUTF(token);
            out.writeUTF(encryptedBlockId);
            out.flush();
        } catch (Exception e) {
            System.out.println("Could not notify OAMS about owner for block " + encryptedBlockId);
        }
    }

    private static void saveMetadata() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(META_FILE))) {
            oos.writeObject(metadata);
        } catch (IOException e) {
            System.err.println("Error saving metadata: " + e.getMessage());
        }
    }

    private static void loadMetadata() {
        File f = new File(META_FILE);
        if (!f.exists())
            return;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            metadata = (Map<String, List<String>>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Error loading metadata: " + e.getMessage());
        }
    }
    private static void loadOwners() {
    File f = new File(OWNERS_FILE);
    if (!f.exists())
        return;
    try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
        Map<String, String> m = (Map<String, String>) ois.readObject();
        owners.putAll(m);
    } catch (Exception e) {
        System.err.println("Error loading owners: " + e.getMessage());
    }
}

private static void saveOwners() {
    try {
       
        Path tmp = Files.createTempFile("owners", ".ser");
        try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(tmp))) {
            oos.writeObject(new HashMap<>(owners));
        }
        Files.move(tmp, Paths.get(OWNERS_FILE), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    } catch (Exception e) {
        System.err.println("Error saving owners: " + e.getMessage());
    }
}
}