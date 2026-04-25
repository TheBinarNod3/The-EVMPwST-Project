package evmpwst.tests;
import evmpwst.core.kwl.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;
public class KwlSecurityTest {
    private KeyPair rsaSender;
    private KeyPair rsaReceiver;
    private byte[] x25519Pub;
    @BeforeEach
    public void setup() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaSender = kpg.generateKeyPair();
        rsaReceiver = kpg.generateKeyPair();
        x25519Pub = new byte[32];
        new SecureRandom().nextBytes(x25519Pub);
    }
    @Test
    public void testRsaOaepTampering() {
        KeyWrapper senderWrapper = KeyWrapperFactory.getRsaWrapper(rsaReceiver.getPublic(), rsaSender.getPrivate());
        KeyPacket packet = senderWrapper.wrap(x25519Pub);
        packet.getCiphertext()[50] ^= 1;
        KeyWrapper receiverWrapper = KeyWrapperFactory.getRsaWrapper(rsaSender.getPublic(), rsaReceiver.getPrivate());
        SecurityException thrown = assertThrows(SecurityException.class, () -> receiverWrapper.unwrap(packet));
        assertTrue(thrown.getMessage().contains("ERR_DECRYPTION_FAILED"));
    }
    @Test
    public void testAesGcmReplayAndTampering() {
        byte[] bootstrap = new byte[32];
        new SecureRandom().nextBytes(bootstrap);
        NonceManager nm = new NonceManager();
        KeyWrapper wrapper = KeyWrapperFactory.getAesGcmWrapper(bootstrap, nm);
        KeyPacket packet = wrapper.wrap(x25519Pub);
        assertArrayEquals(x25519Pub, wrapper.unwrap(packet));
        SecurityException thrown = assertThrows(SecurityException.class, () -> wrapper.unwrap(packet));
        assertTrue(thrown.getMessage().contains("ERR_NONCE_REUSE"));
    }
}
