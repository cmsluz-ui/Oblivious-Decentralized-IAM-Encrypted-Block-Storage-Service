package encryption;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeywordSecurity {

    private static final byte[] KEY_BYTES = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    private static final int NONCE_SIZE = 12;
    private static final int COUNTER = 1;

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    public KeywordSecurity() {
    }

    public byte[] encryptKeyword(String keyword) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256"); //vai buscar hash function
        byte[] fullHash = sha.digest(keyword.getBytes(StandardCharsets.UTF_8)); //da hash da keyword
        byte[] nonce = Arrays.copyOf(fullHash, NONCE_SIZE); //usa a keyword como nonce

        SecretKeySpec spec = new SecretKeySpec(KEY_BYTES, "ChaCha20");
        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, COUNTER);

        Cipher cipher = Cipher.getInstance("ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, spec, param);

        return cipher.doFinal(keyword.getBytes());
    }

    public byte[] decryptKeyword(byte[] ciphertext, String keyword) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] fullHash = sha.digest(keyword.getBytes());
        byte[] nonce = Arrays.copyOf(fullHash, NONCE_SIZE);       
        
        SecretKeySpec spec = new SecretKeySpec(KEY_BYTES, "ChaCha20");
        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(nonce, COUNTER);

        Cipher cipher = Cipher.getInstance("ChaCha20");
        cipher.init(Cipher.DECRYPT_MODE, spec, param);

        return cipher.doFinal(ciphertext);
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hex[j * 2] = HEX_ARRAY[v >>> 4];
            hex[j * 2 + 1] = HEX_ARRAY[v & 0x0F]; 
        }
        return new String(hex);
    }
}
