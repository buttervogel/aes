import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Tester {

    @Test
    public void givenString_whenEncrypt_thenSuccess() throws Exception {
        String input = "my.very.secret";
        SecretKey key = AESCrypt.getKeyFromPassword("dfvinjmo","pepper");
        IvParameterSpec ivParameterSpec = AESCrypt.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";
        String cipherText = AESCrypt.encrypt(algorithm, input, key, ivParameterSpec);
        String plainText = AESCrypt.decrypt(algorithm, cipherText, key, ivParameterSpec);
        assert input.equals(plainText);
    }

    @Test
    public void testShorthand() throws  Exception {
        String input = "my.very.secret2";
        String password = "pups";


        String encryptedInput = AESCrypt.encrypt(input,password);
        String decryptedInput = AESCrypt.decrypt(encryptedInput,password);

        assert input.equals(decryptedInput);



    }

}
