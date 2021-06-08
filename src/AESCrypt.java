import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

public class AESCrypt {

    private static final String ALGORITHM = "AES";
    private static final Charset CHARSET = StandardCharsets.UTF_8;

    public static String encrypt(String valueToEnc, String password) throws Exception {
        Key key = generateKey(password);
        Cipher c = Cipher.getInstance(ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encValue = c.doFinal(valueToEnc.getBytes());
        return new String(Base64.getEncoder().encode(encValue));
    }

    public static String decrypt(String encryptedValue, String password) throws Exception {
        Key key = generateKey(password);
        Cipher c = Cipher.getInstance(ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decordedValue = Base64.getDecoder().decode(encryptedValue);
        byte[] decValue = c.doFinal(decordedValue);
        return new String(decValue);
    }

    private static Key generateKey(String password) {
        return new SecretKeySpec(password.getBytes(CHARSET), ALGORITHM);
    }
}
