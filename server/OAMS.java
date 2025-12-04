import java.io.*;
import java.net.*;
import java.util.concurrent.*;

public class OAMS {

    private static final int PORT = 6001;

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("OAMS running on port " + PORT);

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
                    case "CREATE_SHARE":
                        CreateShare(in, out);
                        break;

                    case "UPDATE_SHARE":
                        UpdateShare(in, out);
                        break;

                    case "GET_SHARE":
                        GetShare(in, out);
                        break;

                    case "EXIT":
                        return;

                    default:
                        out.writeUTF("ERROR: Unknown OAMS command");
                        out.flush();
                }
            }

        } catch (Exception e) {
            System.out.println("OAMS client disconnected.");
        }
    }

    private static void CreateShare(DataInputStream in, DataOutputStream out) throws IOException {
        // TODO: ler token, fileId, permissao etc
        out.writeUTF("OK_CREATE_SHARE");
        out.flush();
    }

    private static void UpdateShare(DataInputStream in, DataOutputStream out) throws IOException {
        // TODO : ler token, fileId, nova permissao etc
        out.writeUTF("OK_UPDATE_SHARE");
        out.flush();
    }

    private static void GetShare(DataInputStream in, DataOutputStream out) throws IOException {
        // TODO: ler token, fileId etc
        out.writeInt(0); 
        out.flush();
    }
}
