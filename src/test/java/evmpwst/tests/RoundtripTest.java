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
import java.util.Random;
import static org.junit.jupiter.api.Assertions.*;
public class RoundtripTest {
    private CryptoEngine engine;
    @BeforeEach
    public void setup() {
        KeyPair kp1 = KeyExchange.generateKeyPair();
        KeyPair kp2 = KeyExchange.generateKeyPair();
        byte[] sessionKey = KeyExchange.deriveSessionKey(kp1.getPrivate(), kp2.getPublic());
        engine = new CryptoEngine(sessionKey);
    }
    @Test
    public void testSmallPayload() {
        byte[] message = "Hello EVMPwST - tajna transmisja 0101".getBytes();
        long startEncode = System.currentTimeMillis();
        BufferedImage img = Encoder.encode(message, PatternType.TEXT_MESSAGE, engine);
        long encodeTime = System.currentTimeMillis() - startEncode;
        System.out.println("Encode time: " + encodeTime + "ms");
        assertTrue(encodeTime < 100, "Encoding target failed (" + encodeTime + "ms)");
        long startDecode = System.currentTimeMillis();
        Decoder.DecodedPayload payload = Decoder.decode(img, engine);
        long decodeTime = System.currentTimeMillis() - startDecode;
        System.out.println("Decode time: " + decodeTime + "ms");
        assertTrue(decodeTime < 150, "Decoding target failed (" + decodeTime + "ms)");
        assertEquals(new String(message), new String(payload.plaintext));
        assertEquals(PatternType.TEXT_MESSAGE, payload.pattern);
    }
    @Test
    public void testMaxPayloadAndCompression() {
        byte[] largeData = new byte[15000];
        new Random().nextBytes(largeData);
        BufferedImage img = Encoder.encode(largeData, PatternType.COMPRESSED_BLOCK, engine);
        Decoder.DecodedPayload payload = Decoder.decode(img, engine);
        assertArrayEquals(largeData, payload.plaintext);
        assertEquals(PatternType.COMPRESSED_BLOCK, payload.pattern);
    }
}
