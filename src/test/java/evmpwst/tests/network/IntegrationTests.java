package evmpwst.tests.network;
import evmpwst.core.Encoder;
import evmpwst.core.Decoder;
import evmpwst.core.CryptoEngine;
import evmpwst.network.*;
import evmpwst.protocol.PatternType;
import org.junit.jupiter.api.*;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;
@DisplayName("Integration Tests — Full EVMPwST Pipeline")
class IntegrationTests {
    @Test
    @DisplayName("MANUAL MODE: encrypt text → EVMPwST image → decrypt with token")
    void manual_fullRoundTrip_text() throws Exception {
        KeyManager km = new KeyManager();
        SenderService sender   = new SenderService(km);
        ReceiverService receiver = new ReceiverService(km);
        String original = "This is a secure test message for EVMPwST.";
        SenderService.OfflineResult result = sender.encryptOffline(
            original.getBytes(StandardCharsets.UTF_8));
        ReceiverService.DecryptResult decrypted = receiver.decryptOffline(
            result.pngBytes(), result.tokenBase64());
        assertEquals(original, decrypted.asString());
    }
    @Test
    @DisplayName("MANUAL MODE: SenderService.encryptOffline → ReceiverService.decryptOffline")
    void manual_senderReceiverServices_offline() throws Exception {
        KeyManager senderKm   = new KeyManager();
        KeyManager receiverKm = new KeyManager();
        SenderService sender     = new SenderService(senderKm);
        ReceiverService receiver = new ReceiverService(receiverKm);
        String message = "EVMPwST offline integration test";
        SenderService.OfflineResult result = sender.encryptOffline(
            message.getBytes(StandardCharsets.UTF_8));
        assertNotNull(result.pngBytes());
        assertNotNull(result.tokenBase64());
        assertFalse(result.tokenBase64().isEmpty());
        ReceiverService.DecryptResult decrypted = receiver.decryptOffline(
            result.pngBytes(), result.tokenBase64());
        assertEquals(message, decrypted.asString());
    }
    @Test
    @DisplayName("MANUAL MODE: Wrong token produces SecurityException, no plaintext")
    void manual_wrongToken_noPlaintext() throws Exception {
        KeyManager km = new KeyManager();
        SenderService sender = new SenderService(km);
        ReceiverService receiver = new ReceiverService(km);
        SenderService.OfflineResult result = sender.encryptOffline("top secret".getBytes());
        TokenManager tm = new TokenManager();
        byte[] wrongToken = tm.generateToken();
        String wrongTokenB64 = tm.exportToken(wrongToken, TokenManager.ExportFormat.BASE64);
        assertThrows(SecurityException.class,
            () -> receiver.decryptOffline(result.pngBytes(), wrongTokenB64));
    }
    @Test
    @DisplayName("AUTO MODE: X25519 + HKDF → image encode → decode round-trip")
    void auto_fullRoundTrip() throws Exception {
        KeyManager alice = new KeyManager();
        KeyManager bob   = new KeyManager();
        SenderService sender = new SenderService(alice);
        byte[] sharedSecret = alice.computeSharedSecret(bob.getPublicKeyBase64());
        byte[] frame = buildAutoFrame(alice, sharedSecret, "X25519+HKDF integration test message");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] imgKey = HKDFService.derive(sharedSecret, null, "evmpwst-img-v1", 32);
        CryptoEngine imgEngine = new CryptoEngine(imgKey);
        BufferedImage img = Encoder.encode(frame, PatternType.TEXT_MESSAGE, imgEngine);
        ImageIO.write(img, "png", baos);
        ReceiverService bobReceiver = new ReceiverService(bob);
        ReceiverService.DecryptResult result = bobReceiver.decryptOfflineAuto(
            baos.toByteArray(), alice.getPublicKeyBase64());
        assertEquals("X25519+HKDF integration test message", result.asString());
    }
    private byte[] buildAutoFrame(KeyManager sender, byte[] sharedSecret, String message) {
        byte[] encKey = HKDFService.derive(sharedSecret, null, HKDFService.INFO_ENCRYPTION, 32);
        CryptoEngine engine = new CryptoEngine(encKey);
        byte[] nonce = engine.generateNonce();
        byte[][] parts = engine.encrypt(message.getBytes(StandardCharsets.UTF_8), nonce);
        return SenderService.packFrame(nonce, parts[1], parts[0]);
    }
    @Test
    @DisplayName("AUTO MODE: Wrong sender key causes SecurityException")
    void auto_wrongSenderKey_SecurityException() throws Exception {
        KeyManager alice    = new KeyManager();
        KeyManager bob      = new KeyManager();
        KeyManager impostor = new KeyManager();
        byte[] sharedSecret = alice.computeSharedSecret(bob.getPublicKeyBase64());
        byte[] encKey = HKDFService.derive(sharedSecret, null, HKDFService.INFO_ENCRYPTION, 32);
        CryptoEngine engine = new CryptoEngine(encKey);
        BufferedImage img = Encoder.encode("secret".getBytes(), PatternType.TEXT_MESSAGE, engine);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(img, "png", baos);
        ReceiverService bobReceiver = new ReceiverService(bob);
        assertThrows(SecurityException.class,
            () -> bobReceiver.decryptOfflineAuto(baos.toByteArray(), impostor.getPublicKeyBase64()));
    }
    @Test
    @DisplayName("MessagePacket: JSON serialize/deserialize preserves all fields")
    void messagePacket_jsonRoundTrip() {
        byte[] nonce = new byte[12];
        byte[] ct    = new byte[32];
        byte[] tag   = new byte[16];
        new java.security.SecureRandom().nextBytes(nonce);
        new java.security.SecureRandom().nextBytes(ct);
        new java.security.SecureRandom().nextBytes(tag);
        MessagePacket packet = new MessagePacket.Builder()
            .mode(MessagePacket.EncryptionMode.MANUAL_TOKEN)
            .nonce(nonce)
            .ciphertext(ct)
            .authTag(tag)
            .build();
        String json = packet.toJson();
        assertFalse(json.isEmpty());
        MessagePacket restored = MessagePacket.fromJson(json);
        assertArrayEquals(nonce, restored.getNonceBytes());
        assertArrayEquals(ct,    restored.getCiphertextBytes());
        assertArrayEquals(tag,   restored.getAuthTagBytes());
        assertEquals(MessagePacket.EncryptionMode.MANUAL_TOKEN, restored.getEncryptionMode());
        assertEquals(MessagePacket.PROTOCOL_VERSION, restored.getPacketVersion());
        assertNotNull(restored.getReplayProtectionId());
    }
    @Test
    @DisplayName("CryptoService: two-party symmetric channel consistency")
    void cryptoService_twoPartyChannel() {
        byte[] sharedKey = new byte[32];
        new java.security.SecureRandom().nextBytes(sharedKey);
        CryptoService party1 = new CryptoService(sharedKey, null);
        CryptoService party2 = new CryptoService(sharedKey, null);
        byte[] msg = "Bidirectional channel test".getBytes(StandardCharsets.UTF_8);
        CryptoService.EncryptedPayload ep = party1.encrypt(msg);
        byte[] decrypted = party2.decrypt(ep);
        assertArrayEquals(msg, decrypted);
    }
    @Test
    @DisplayName("EVMPwST image: PNG encoding preserves pixel-level data integrity")
    void evmpwst_imageIntegrity() throws Exception {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        CryptoEngine engine1 = new CryptoEngine(key);
        CryptoEngine engine2 = new CryptoEngine(key);
        String msg = "Steganography integrity test";
        BufferedImage img = Encoder.encode(msg.getBytes(StandardCharsets.UTF_8),
            PatternType.TEXT_MESSAGE, engine1);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(img, "png", baos);
        BufferedImage decoded = ImageIO.read(new ByteArrayInputStream(baos.toByteArray()));
        Decoder.DecodedPayload payload = Decoder.decode(decoded, engine2);
        assertEquals(msg, new String(payload.plaintext, StandardCharsets.UTF_8));
    }
}
