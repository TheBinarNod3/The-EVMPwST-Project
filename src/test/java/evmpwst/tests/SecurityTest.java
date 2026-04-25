package evmpwst.tests;
import evmpwst.core.CryptoEngine;
import evmpwst.core.Decoder;
import evmpwst.core.Encoder;
import evmpwst.core.KeyExchange;
import evmpwst.protocol.PatternType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.awt.image.BufferedImage;
import java.security.KeyPair;
import static org.junit.jupiter.api.Assertions.*;
public class SecurityTest {
    private CryptoEngine senderEngine;
    private CryptoEngine receiverEngine;
    private CryptoEngine wrongEngine;
    @BeforeEach
    public void setup() {
        KeyPair kp1 = KeyExchange.generateKeyPair();
        KeyPair kp2 = KeyExchange.generateKeyPair();
        KeyPair kp3 = KeyExchange.generateKeyPair();
        byte[] sessionKey = KeyExchange.deriveSessionKey(kp1.getPrivate(), kp2.getPublic());
        senderEngine = new CryptoEngine(sessionKey);
        receiverEngine = new CryptoEngine(sessionKey);
        byte[] wrongKey = KeyExchange.deriveSessionKey(kp3.getPrivate(), kp2.getPublic());
        wrongEngine = new CryptoEngine(wrongKey);
    }
    @Test
    public void testTamperingDetection_Crc32() {
        BufferedImage img = Encoder.encode("Wiadomosc Testowa".getBytes(), PatternType.TEXT_MESSAGE, senderEngine);
        int color = img.getRGB(150, 150);
        img.setRGB(150, 150, color == 0xFF000000 ? 0xFFFFFFFF : 0xFF000000);
        SecurityException thrown = assertThrows(SecurityException.class, () -> Decoder.decode(img, receiverEngine));
        assertTrue(thrown.getMessage().contains("ERR_CRC32_MISMATCH"));
    }
    @Test
    public void testReplayAttack() {
        BufferedImage img = Encoder.encode("Rozkaz wystrzału z działa głównego!".getBytes(), PatternType.COMMAND_PACKET, senderEngine);
        Decoder.decode(img, receiverEngine);
        SecurityException thrown = assertThrows(SecurityException.class, () -> Decoder.decode(img, receiverEngine));
        assertTrue(thrown.getMessage().contains("ERR_NONCE_REUSE"));
    }
    @Test
    public void testWrongKeyException() {
        BufferedImage img = Encoder.encode("Dane ukryte przed kradzieżą".getBytes(), PatternType.TEXT_MESSAGE, senderEngine);
        SecurityException thrown = assertThrows(SecurityException.class, () -> Decoder.decode(img, wrongEngine));
        assertTrue(thrown.getMessage().contains("ERR_AUTH_TAG_INVALID") || thrown.getMessage().contains("ERR_DECRYPTION_FAILED"));
    }
}
