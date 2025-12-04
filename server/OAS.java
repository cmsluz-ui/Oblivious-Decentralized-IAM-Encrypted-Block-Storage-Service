import java.io.*;
import java.net.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

public class OAS {

    private static final int PORT = 6000;
    private static Map<String, User> users = new HashMap<>();

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("OAS running on port " + PORT);

        ExecutorService pool = Executors.newCachedThreadPool();

        while (true) {
            Socket client = serverSocket.accept();
            pool.submit(() -> handleClient(client));
        }
    }

    private static void handleClient(Socket socket) {
        try (
                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream())
        ) {
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
        //read pubkey, salt, password hash, metadata
        try {
        String pubKeyB64 = in.readUTF();
        byte[] salt = Base64.getDecoder().decode(in.readUTF());
        byte[] pwHash = Base64.getDecoder().decode(in.readUTF());

        int attrCount = in.readInt();
        Map<String, String> attrs = new HashMap<>();
        for (int i = 0; i < attrCount; i++) {
            String key = in.readUTF();
            String value = in.readUTF();
            attrs.put(key, value);
        }

        User u = new User(pubKeyB64, pwHash, salt, attrs);
        users.put(pubKeyB64, u);

        out.writeUTF("OK_CREATE_REG");
        out.flush();
    } catch (Exception e) {
        out.writeUTF("ERROR_CREATE_REG");
        out.flush();
    }
    }

    private static void ModifyRegistration(DataInputStream in, DataOutputStream out) throws IOException {
        //Allows users to modify attributes previously registered by the respective user
        out.writeUTF("OK_MODIFY_REG");
        out.flush();
    }

    private static void AuthStart(DataInputStream in, DataOutputStream out) throws IOException {
        // TODO: read username, send nonce
        out.writeUTF("NONCE_PLACEHOLDER");
        out.writeLong(System.currentTimeMillis());
        out.flush();
    }

    private static void AuthResponse(DataInputStream in, DataOutputStream out) throws IOException {
        // TODO: verificar assinatura
        out.writeUTF("TOKEN");
        out.writeUTF("FAKE_TOKEN_VALUE");
        out.flush();
    }

    private static void GetUserPubKey(DataInputStream in, DataOutputStream out) throws IOException {
        // TODO: retornar pub key do user
        out.writeUTF("PUBKEY_PLACEHOLDER");
        out.flush();
    }
}
