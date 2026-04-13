import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class AesTest {

    @BeforeAll
    static void setup() {
        // Додаємо провайдера Bouncy Castle [cite: 13]
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testAesCorrectness() throws Exception {
        // Тестовий вектор NIST (Варіант 12)
        byte[] keyBytes = new byte[16]; // 128-бітний нульовий ключ для прикладу
        byte[] input = new byte[16];    // Нульовий блок даних

        // Очікуваний результат для AES-128 ECB (нульовий ключ/вхід)
        byte[] expected = hexStringToByteArray("66e94bd4ef8a2c3b884cfa59ca342b2e");

        // 1. Тест через вбудовану бібліотеку (SunJCE)
        Cipher cipherDefault = Cipher.getInstance("AES/ECB/NoPadding", "SunJCE");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        cipherDefault.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] resultDefault = cipherDefault.doFinal(input);

        // 2. Тест через Bouncy Castle [cite: 13]
        Cipher cipherBC = Cipher.getInstance("AES/ECB/NoPadding", "BC");
        cipherBC.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] resultBC = cipherBC.doFinal(input);

        // Перевірка коректності [cite: 15]
        assertArrayEquals(expected, resultDefault, "SunJCE failed NIST vector");
        assertArrayEquals(expected, resultBC, "Bouncy Castle failed NIST vector");
        System.out.println("Коректність підтверджено для обох бібліотек.");
    }

    @Test
    void testPerformance() throws Exception {
        byte[] data = new byte[1024 * 1024]; // 1 МБ даних [cite: 17]
        Arrays.fill(data, (byte) 1);
        SecretKeySpec keySpec = new SecretKeySpec(new byte[16], "AES");

        // Вимірювання SunJCE [cite: 17]
        Cipher c1 = Cipher.getInstance("AES/ECB/NoPadding", "SunJCE");
        c1.init(Cipher.ENCRYPT_MODE, keySpec);
        long start = System.nanoTime();
        c1.doFinal(data);
        long end = System.nanoTime();
        System.out.println("SunJCE time: " + (end - start) / 1_000_000.0 + " ms");

        // Вимірювання Bouncy Castle [cite: 17]
        Cipher c2 = Cipher.getInstance("AES/ECB/NoPadding", "BC");
        c2.init(Cipher.ENCRYPT_MODE, keySpec);
        start = System.nanoTime();
        c2.doFinal(data);
        end = System.nanoTime();
        System.out.println("Bouncy Castle time: " + (end - start) / 1_000_000.0 + " ms");
    }

    // Допоміжний метод для перетворення HEX у byte[]
    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}

