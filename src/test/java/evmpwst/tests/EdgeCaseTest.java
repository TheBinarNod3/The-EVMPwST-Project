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
public class EdgeCaseTest {
    private CryptoEngine engine;
    @BeforeEach
    public void setup() {
        KeyPair kp1 = KeyExchange.generateKeyPair();
        KeyPair kp2 = KeyExchange.generateKeyPair();
        engine = new CryptoEngine(KeyExchange.deriveSessionKey(kp1.getPrivate(), kp2.getPublic()));
    }
    @Test
    public void testWrongDimensions() {
        BufferedImage badImg = new BufferedImage(300, 300, BufferedImage.TYPE_BYTE_BINARY);
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> Decoder.decode(badImg, engine));
        assertTrue(thrown.getMessage().contains("ERR_IMAGE_DIMENSIONS"));
    }
    @Test
    public void testMaxPayloadRefusal() {
        byte[] tooLarge = new byte[Encoder.MAX_CIPHERTEXT_SIZE + 1];
        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> Encoder.encode(tooLarge, PatternType.FILE_PAYLOAD, engine));
        assertTrue(thrown.getMessage().contains("mność ram"));
    }
    @Test
    public void testEmptyPayload() {
        BufferedImage img = Encoder.encode(new byte[0], PatternType.TEXT_MESSAGE, engine);
        Decoder.DecodedPayload payload = Decoder.decode(img, engine);
        assertEquals(0, payload.plaintext.length);
    }
}
