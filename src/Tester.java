import org.junit.Test;

public class Tester {

    public static final String INPUT = "oliver.meimberg";
    public static final String ENC_INPUT = "tzVZTKv/il4mh8cBvGghHg==";
    public static final String PASSWORD = "Oliedvf..o345ru9";

    @Test
    public void testShorthand() throws Exception {
        String encryptedInput = AESCrypt.encrypt(INPUT, PASSWORD);
        String decryptedInput = AESCrypt.decrypt(encryptedInput, PASSWORD);
        assert INPUT.equals(decryptedInput);
    }

    @Test
    public void testRecover() throws Exception {
        String decryptedInput = AESCrypt.decrypt(ENC_INPUT, PASSWORD);
        assert INPUT.equals(decryptedInput);
    }

}
