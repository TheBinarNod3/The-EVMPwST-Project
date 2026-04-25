package evmpwst.network;
import evmpwst.core.CryptoEngine;
import evmpwst.core.Encoder;
import evmpwst.protocol.PatternType;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
public final class SenderService {
    private final KeyManager keyManager;
    private final TokenManager tokenManager;
    public SenderService(KeyManager keyManager) {
        this.keyManager   = keyManager;
        this.tokenManager = new TokenManager();
    }
    public void sendAuto(byte[] plaintext, String recipientPublicKeyBase64,
                         TorTransportClient transport) throws IOException {
        byte[] sharedSecret = keyManager.computeSharedSecret(recipientPublicKeyBase64);
        byte[] wirePayload  = buildEncryptedPacketJson(plaintext, sharedSecret,
            MessagePacket.EncryptionMode.AUTO_X25519, keyManager.getPublicKeyBase64());
        transport.send(wirePayload);
    }
    public String sendManual(byte[] plaintext, TorTransportClient transport) throws IOException {
        byte[] token = tokenManager.generateToken();
        byte[] wirePayload = buildEncryptedPacketJson(plaintext, token,
            MessagePacket.EncryptionMode.MANUAL_TOKEN, null);
        transport.send(wirePayload);
        return tokenManager.exportToken(token, TokenManager.ExportFormat.BASE64);
    }
    public OfflineResult encryptOffline(byte[] plaintext) {
        byte[] token  = tokenManager.generateToken();
        byte[] encKey = HKDFService.derive(token, null, HKDFService.INFO_ENCRYPTION, 32);
        CryptoEngine engine = new CryptoEngine(encKey);
        byte[] nonce   = engine.generateNonce();
        byte[][] parts = engine.encrypt(plaintext, nonce);
        byte[] ciphertext = parts[0];
        byte[] authTag    = parts[1];
        byte[] frame = packFrame(nonce, authTag, ciphertext);
        try {
            byte[] imgKey = HKDFService.derive(token, null, "evmpwst-img-v1", 32);
            CryptoEngine imgEngine = new CryptoEngine(imgKey);
            BufferedImage img = Encoder.encode(frame, PatternType.TEXT_MESSAGE, imgEngine);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(img, "png", baos);
            byte[] pngBytes  = baos.toByteArray();
            String tokenB64  = tokenManager.exportToken(token, TokenManager.ExportFormat.BASE64);
            return new OfflineResult(pngBytes, tokenB64);
        } catch (IOException e) {
            FailureHandler.handleOperationalFailure("EVMPwST image encoding failed", e);
            throw new RuntimeException("unreachable");
        }
    }
    private byte[] buildEncryptedPacketJson(byte[] plaintext, byte[] ikm,
                                             MessagePacket.EncryptionMode mode,
                                             String senderPubKey) {
        byte[] encKey = HKDFService.derive(ikm, null, HKDFService.INFO_ENCRYPTION, 32);
        CryptoEngine engine = new CryptoEngine(encKey);
        byte[] nonce  = engine.generateNonce();
        byte[][] parts = engine.encrypt(plaintext, nonce);
        MessagePacket.Builder builder = new MessagePacket.Builder()
            .mode(mode)
            .nonce(nonce)
            .ciphertext(parts[0])
            .authTag(parts[1]);
        if (senderPubKey != null) builder.senderPublicKey(senderPubKey);
        return builder.build().toJson().getBytes(StandardCharsets.UTF_8);
    }
    public static byte[] packFrame(byte[] nonce, byte[] authTag, byte[] ciphertext) {
        byte[] frame = new byte[12 + 16 + ciphertext.length];
        System.arraycopy(nonce,      0, frame, 0,  12);
        System.arraycopy(authTag,    0, frame, 12, 16);
        System.arraycopy(ciphertext, 0, frame, 28, ciphertext.length);
        return frame;
    }
    public record OfflineResult(byte[] pngBytes, String tokenBase64) {}
}
