package evmpwst.tests.network;
import evmpwst.core.Encoder;
import evmpwst.core.CryptoEngine;
import evmpwst.network.*;
import evmpwst.protocol.PatternType;
import org.junit.jupiter.api.*;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;
@DisplayName("Failure Tests — Security Edge Cases and Rejection Scenarios")
class FailureTests {
    private final SecureRandom rng = new SecureRandom();
    @Test
    @DisplayName("FAIL: Modified auth tag (1 bit flip) → SecurityException, zero plaintext")
    void fail_modifiedAuthTag() {
        byte[] key = randomBytes(32);
        CryptoService crypto = new CryptoService(key, null);
        CryptoService.EncryptedPayload ep = crypto.encrypt("sensitive".getBytes());
        byte[] badTag = Arrays.copyOf(ep.authTag, ep.authTag.length);
        badTag[0] ^= 0x01;
        CryptoService.EncryptedPayload tampered = new CryptoService.EncryptedPayload(
            ep.nonce, ep.ciphertext, badTag);
        SecurityException ex = assertThrows(SecurityException.class,
            () -> crypto.decrypt(tampered));
        assertFalse(ex.getMessage().toLowerCase().contains("sensitive"));
    }
    @Test
    @DisplayName("FAIL: All-zeros auth tag → SecurityException")
    void fail_zeroAuthTag() {
        byte[] key = randomBytes(32);
        CryptoService crypto = new CryptoService(key, null);
        CryptoService.EncryptedPayload ep = crypto.encrypt("data".getBytes());
        CryptoService.EncryptedPayload tampered = new CryptoService.EncryptedPayload(
            ep.nonce, ep.ciphertext, new byte[16]);
        assertThrows(SecurityException.class, () -> crypto.decrypt(tampered));
    }
    @Test
    @DisplayName("FAIL: Auth tag wrong length → SecurityException before decrypt")
    void fail_authTagWrongLength() {
        byte[] key = randomBytes(32);
        CryptoService crypto = new CryptoService(key, null);
        CryptoService.EncryptedPayload ep = crypto.encrypt("data".getBytes());
        CryptoService.EncryptedPayload tampered = new CryptoService.EncryptedPayload(
            ep.nonce, ep.ciphertext, new byte[8]);
        assertThrows(SecurityException.class, () -> crypto.decrypt(tampered));
    }
    @Test
    @DisplayName("FAIL: Nonce wrong length (8 bytes) → SecurityException")
    void fail_nonceWrongLength() {
        byte[] key = randomBytes(32);
        CryptoService crypto = new CryptoService(key, null);
        CryptoService.EncryptedPayload ep = crypto.encrypt("data".getBytes());
        CryptoService.EncryptedPayload tampered = new CryptoService.EncryptedPayload(
            new byte[8], ep.ciphertext, ep.authTag);
        assertThrows(SecurityException.class, () -> crypto.decrypt(tampered));
    }
    @Test
    @DisplayName("FAIL: Null nonce → SecurityException")
    void fail_nullNonce() {
        byte[] key = randomBytes(32);
        CryptoService crypto = new CryptoService(key, null);
        CryptoService.EncryptedPayload ep = crypto.encrypt("data".getBytes());
        CryptoService.EncryptedPayload tampered = new CryptoService.EncryptedPayload(
            null, ep.ciphertext, ep.authTag);
        assertThrows(SecurityException.class, () -> crypto.decrypt(tampered));
    }
    @Test
    @DisplayName("FAIL: Single bit flip in ciphertext → SecurityException")
    void fail_ciphertextBitFlip() {
        byte[] key = randomBytes(32);
        CryptoService crypto = new CryptoService(key, null);
        CryptoService.EncryptedPayload ep = crypto.encrypt("payload".getBytes());
        byte[] badCt = Arrays.copyOf(ep.ciphertext, ep.ciphertext.length);
        badCt[badCt.length / 2] ^= 0x80;
        CryptoService.EncryptedPayload tampered = new CryptoService.EncryptedPayload(
            ep.nonce, badCt, ep.authTag);
        assertThrows(SecurityException.class, () -> crypto.decrypt(tampered));
    }
    @Test
    @DisplayName("FAIL: Empty ciphertext → SecurityException")
    void fail_emptyCiphertext() {
        byte[] key = randomBytes(32);
        CryptoService crypto = new CryptoService(key, null);
        CryptoService.EncryptedPayload ep = crypto.encrypt("data".getBytes());
        CryptoService.EncryptedPayload tampered = new CryptoService.EncryptedPayload(
            ep.nonce, new byte[0], ep.authTag);
        assertThrows(SecurityException.class, () -> crypto.decrypt(tampered));
    }
    @Test
    @DisplayName("FAIL: Token reuse → SecurityException on second use")
    void fail_tokenReuse() {
        TokenManager tm = new TokenManager();
        byte[] token = tm.generateToken();
        tm.markUsed(token);
        assertThrows(SecurityException.class, () -> tm.markUsed(token));
    }
    @Test
    @DisplayName("FAIL: Tampered token (1 byte changed) → wrong derived key → decrypt SecurityException")
    void fail_tamperedTokenDecrypt() throws Exception {
        KeyManager km = new KeyManager();
        SenderService sender = new SenderService(km);
        ReceiverService receiver = new ReceiverService(km);
        SenderService.OfflineResult result = sender.encryptOffline("secret".getBytes());
        String origToken = result.tokenBase64();
        byte[] origBytes = Base64.getDecoder().decode(origToken);
        origBytes[0] ^= 0xFF;
        String tamperedToken = Base64.getEncoder().encodeToString(origBytes);
        assertThrows(SecurityException.class,
            () -> receiver.decryptOffline(result.pngBytes(), tamperedToken));
    }
    @Test
    @DisplayName("FAIL: Partial token (too short) → SecurityException before decrypt")
    void fail_partialToken() throws Exception {
        KeyManager km = new KeyManager();
        SenderService sender = new SenderService(km);
        ReceiverService receiver = new ReceiverService(km);
        SenderService.OfflineResult result = sender.encryptOffline("data".getBytes());
        String partial = result.tokenBase64().substring(0, 8);
        assertThrows(SecurityException.class,
            () -> receiver.decryptOffline(result.pngBytes(), partial));
    }
    @Test
    @DisplayName("FAIL: Wrong token format (malformed string) → SecurityException")
    void fail_malformedToken() throws Exception {
        KeyManager km = new KeyManager();
        SenderService sender = new SenderService(km);
        ReceiverService receiver = new ReceiverService(km);
        SenderService.OfflineResult result = sender.encryptOffline("data".getBytes());
        assertThrows(SecurityException.class,
            () -> receiver.decryptOffline(result.pngBytes(), "not!valid@base64#"));
    }
    @Test
    @DisplayName("FAIL: Duplicate replay protection ID → SecurityException")
    void fail_replayDetected() {
        byte[] nonce = randomBytes(12);
        byte[] ct    = randomBytes(32);
        byte[] tag   = randomBytes(16);
        MessagePacket packet = new MessagePacket.Builder()
            .mode(MessagePacket.EncryptionMode.MANUAL_TOKEN)
            .nonce(nonce).ciphertext(ct).authTag(tag)
            .build();
        assertDoesNotThrow(() -> SecurityValidator.validatePacket(packet));
        assertThrows(SecurityException.class, () -> SecurityValidator.validatePacket(packet));
    }
    @Test
    @DisplayName("FAIL: Null packet → SecurityException")
    void fail_nullPacket() {
        assertThrows(SecurityException.class, () -> SecurityValidator.validatePacket(null));
    }
    @Test
    @DisplayName("FAIL: AUTO mode packet without senderPublicKey → SecurityException from SecurityValidator")
    void fail_autoMode_missingSenderKey() {
        MessagePacket manualPacket = new MessagePacket.Builder()
            .mode(MessagePacket.EncryptionMode.MANUAL_TOKEN)
            .nonce(randomBytes(12))
            .ciphertext(randomBytes(32))
            .authTag(randomBytes(16))
            .build();
        String tamperedJson = manualPacket.toJson().replace("MANUAL_TOKEN", "AUTO_X25519");
        MessagePacket malformedPacket = MessagePacket.fromJson(tamperedJson);
        assertThrows(SecurityException.class,
            () -> SecurityValidator.validatePacket(malformedPacket));
    }
    @Test
    @DisplayName("FAIL: Broken (corrupted) PNG → SecurityException on decode")
    void fail_corruptedPng() {
        KeyManager km = new KeyManager();
        ReceiverService receiver = new ReceiverService(km);
        TokenManager tm = new TokenManager();
        byte[] token = tm.generateToken();
        String tokenB64 = tm.exportToken(token, TokenManager.ExportFormat.BASE64);
        byte[] corruptedPng = "not-a-png-at-all".getBytes();
        assertThrows(Exception.class,
            () -> receiver.decryptOffline(corruptedPng, tokenB64));
    }
    @Test
    @DisplayName("FAIL: Tampered image (pixel-level modification) → SecurityException")
    void fail_tamperedImage() throws Exception {
        KeyManager km = new KeyManager();
        SenderService sender = new SenderService(km);
        ReceiverService receiver = new ReceiverService(km);
        SenderService.OfflineResult result = sender.encryptOffline("confidential".getBytes());
        byte[] tampered = result.pngBytes().clone();
        int mid = tampered.length / 2;
        for (int i = mid; i < mid + 50 && i < tampered.length; i++) {
            tampered[i] ^= 0xFF;
        }
        assertThrows(Exception.class,
            () -> receiver.decryptOffline(tampered, result.tokenBase64()));
    }
    @Test
    @DisplayName("FAIL: Valid token but mismatched image → SecurityException")
    void fail_tokenImageMismatch() throws Exception {
        KeyManager km = new KeyManager();
        SenderService sender = new SenderService(km);
        ReceiverService receiver = new ReceiverService(km);
        SenderService.OfflineResult result1 = sender.encryptOffline("message 1".getBytes());
        SenderService.OfflineResult result2 = sender.encryptOffline("message 2".getBytes());
        assertThrows(SecurityException.class,
            () -> receiver.decryptOffline(result2.pngBytes(), result1.tokenBase64()));
    }
    @Test
    @DisplayName("FAIL: Plaintext encrypt attempt blocked (empty message)")
    void fail_emptyPlaintext() {
        byte[] key = randomBytes(32);
        CryptoService crypto = new CryptoService(key, null);
        assertThrows(IllegalArgumentException.class,
            () -> crypto.encrypt(new byte[0]));
        assertThrows(IllegalArgumentException.class,
            () -> crypto.encrypt(null));
    }
    @Test
    @DisplayName("FAIL: Invalid public key base64 for X25519 → SecurityException")
    void fail_invalidX25519Key() {
        KeyManager km = new KeyManager();
        assertThrows(SecurityException.class,
            () -> km.computeSharedSecret("not-a-valid-x25519-key=="));
    }
    @Test
    @DisplayName("FAIL: RSA key passed to X25519 slot → SecurityException")
    void fail_rsaKeyInX25519Slot() throws Exception {
        KeyManager km = new KeyManager();
        java.security.KeyPairGenerator rsaKPG = java.security.KeyPairGenerator.getInstance("RSA");
        rsaKPG.initialize(2048);
        String rsaPubBase64 = Base64.getEncoder().encodeToString(
            rsaKPG.generateKeyPair().getPublic().getEncoded());
        assertThrows(SecurityException.class,
            () -> km.computeSharedSecret(rsaPubBase64));
    }
    @Test
    @DisplayName("FailureHandler: always throws, never returns")
    void failureHandler_alwaysThrows() {
        assertThrows(SecurityException.class,
            () -> FailureHandler.handleSecurityFailure("TEST_CODE"));
        assertThrows(SecurityException.class,
            () -> FailureHandler.handleSecurityFailure("TEST_CODE", new RuntimeException("cause")));
        assertThrows(RuntimeException.class,
            () -> FailureHandler.handleOperationalFailure("op failure", new Exception("cause")));
    }
    @Test
    @DisplayName("FailureHandler.require: false condition throws SecurityException")
    void failureHandler_require() {
        assertThrows(SecurityException.class,
            () -> FailureHandler.require(false, "ERR_CONDITION"));
        assertDoesNotThrow(
            () -> FailureHandler.require(true, "ERR_CONDITION"));
    }
    private byte[] randomBytes(int length) {
        byte[] b = new byte[length];
        rng.nextBytes(b);
        return b;
    }
}
