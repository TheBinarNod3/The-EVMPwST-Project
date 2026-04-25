package evmpwst.network;
import evmpwst.core.CryptoEngine;
import evmpwst.core.Decoder;
import evmpwst.protocol.PatternType;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
public final class ReceiverService {
    private final KeyManager keyManager;
    private final TokenManager tokenManager;
    public ReceiverService(KeyManager keyManager) {
        this.keyManager   = keyManager;
        this.tokenManager = new TokenManager();
    }
    public byte[] receiveAuto(TorTransportClient transport) throws IOException {
        byte[] wireData = transport.receive();
        MessagePacket packet = MessagePacket.fromJson(new String(wireData, StandardCharsets.UTF_8));
        SecurityValidator.validatePacket(packet);
        if (packet.getEncryptionMode() != MessagePacket.EncryptionMode.AUTO_X25519) {
            FailureHandler.handleSecurityFailure("ERR_MODE_MISMATCH");
        }
        byte[] sharedSecret = keyManager.computeSharedSecret(packet.getSenderPublicKey());
        byte[] encKey = HKDFService.derive(sharedSecret, null, HKDFService.INFO_ENCRYPTION, 32);
        CryptoEngine engine = new CryptoEngine(encKey);
        return engine.decrypt(packet.getCiphertextBytes(), packet.getAuthTagBytes(), packet.getNonceBytes());
    }
    public byte[] receiveManual(TorTransportClient transport, String tokenString) throws IOException {
        byte[] wireData = transport.receive();
        MessagePacket packet = MessagePacket.fromJson(new String(wireData, StandardCharsets.UTF_8));
        SecurityValidator.validatePacket(packet);
        if (packet.getEncryptionMode() != MessagePacket.EncryptionMode.MANUAL_TOKEN) {
            FailureHandler.handleSecurityFailure("ERR_MODE_MISMATCH");
        }
        byte[] token = tokenManager.importToken(tokenString);
        tokenManager.markUsed(token);
        byte[] encKey = HKDFService.derive(token, null, HKDFService.INFO_ENCRYPTION, 32);
        CryptoEngine engine = new CryptoEngine(encKey);
        return engine.decrypt(packet.getCiphertextBytes(), packet.getAuthTagBytes(), packet.getNonceBytes());
    }
    public DecryptResult decryptOffline(byte[] pngBytes, String tokenString) throws IOException {
        byte[] token = tokenManager.importToken(tokenString);
        tokenManager.markUsed(token);
        BufferedImage img = ImageIO.read(new ByteArrayInputStream(pngBytes));
        if (img == null) {
            FailureHandler.handleSecurityFailure("ERR_INVALID_PNG");
        }
        byte[] imgKey = HKDFService.derive(token, null, "evmpwst-img-v1", 32);
        CryptoEngine imgEngine = new CryptoEngine(imgKey);
        Decoder.DecodedPayload decoded = Decoder.decode(img, imgEngine);
        byte[] frame = decoded.plaintext;
        if (frame.length < 28) {
            FailureHandler.handleSecurityFailure("ERR_FRAME_TOO_SHORT");
        }
        byte[] nonce      = Arrays.copyOfRange(frame, 0,  12);
        byte[] authTag    = Arrays.copyOfRange(frame, 12, 28);
        byte[] ciphertext = Arrays.copyOfRange(frame, 28, frame.length);
        byte[] encKey = HKDFService.derive(token, null, HKDFService.INFO_ENCRYPTION, 32);
        CryptoEngine cryptoEngine = new CryptoEngine(encKey);
        byte[] plaintext = cryptoEngine.decrypt(ciphertext, authTag, nonce);
        return new DecryptResult(plaintext, decoded.pattern.name());
    }
    public DecryptResult decryptOfflineAuto(byte[] pngBytes, String senderPublicKeyBase64) throws IOException {
        byte[] sharedSecret = keyManager.computeSharedSecret(senderPublicKeyBase64);
        BufferedImage img = ImageIO.read(new ByteArrayInputStream(pngBytes));
        if (img == null) {
            FailureHandler.handleSecurityFailure("ERR_INVALID_PNG");
        }
        byte[] imgKey = HKDFService.derive(sharedSecret, null, "evmpwst-img-v1", 32);
        CryptoEngine imgEngine = new CryptoEngine(imgKey);
        Decoder.DecodedPayload decoded = Decoder.decode(img, imgEngine);
        byte[] frame = decoded.plaintext;
        if (frame.length < 28) {
            FailureHandler.handleSecurityFailure("ERR_FRAME_TOO_SHORT");
        }
        byte[] nonce      = Arrays.copyOfRange(frame, 0,  12);
        byte[] authTag    = Arrays.copyOfRange(frame, 12, 28);
        byte[] ciphertext = Arrays.copyOfRange(frame, 28, frame.length);
        byte[] encKey = HKDFService.derive(sharedSecret, null, HKDFService.INFO_ENCRYPTION, 32);
        CryptoEngine cryptoEngine = new CryptoEngine(encKey);
        byte[] plaintext = cryptoEngine.decrypt(ciphertext, authTag, nonce);
        return new DecryptResult(plaintext, decoded.pattern.name());
    }
    public record DecryptResult(byte[] plaintext, String patternName) {
        public String asString() { return new String(plaintext, StandardCharsets.UTF_8); }
    }
}
