package evmpwst.network;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
public final class SecurityValidator {
    private static final long MAX_PACKET_AGE_MS = 10 * 60 * 1000L;
    private static final Map<String, Long> SEEN_REPLAY_IDS = new ConcurrentHashMap<>();
    private SecurityValidator() {}
    public static void validatePacket(MessagePacket packet) {
        validateStructure(packet);
        validateTimestamp(packet.getTimestamp());
        validateReplayId(packet.getReplayProtectionId());
    }
    public static void validateEncryptedPayload(CryptoService.EncryptedPayload payload) {
        if (payload == null) {
            throw new SecurityException("ERR_NULL_PAYLOAD: Encrypted payload is null");
        }
        if (payload.nonce == null || payload.nonce.length != 12) {
            throw new SecurityException("ERR_NONCE_LENGTH: Nonce must be exactly 12 bytes");
        }
        if (payload.ciphertext == null || payload.ciphertext.length == 0) {
            throw new SecurityException("ERR_EMPTY_CIPHERTEXT: Ciphertext must not be empty");
        }
        if (payload.authTag == null || payload.authTag.length != 16) {
            throw new SecurityException("ERR_AUTH_TAG_LENGTH: Auth tag must be exactly 16 bytes (Poly1305)");
        }
    }
    private static void validateStructure(MessagePacket p) {
        if (p == null) {
            throw new SecurityException("ERR_NULL_PACKET");
        }
        if (p.getPacketVersion() != MessagePacket.PROTOCOL_VERSION) {
            throw new SecurityException(
                "ERR_VERSION_MISMATCH: Expected v" + MessagePacket.PROTOCOL_VERSION
                + ", got v" + p.getPacketVersion()
            );
        }
        if (p.getEncryptionMode() == null) {
            throw new SecurityException("ERR_NO_ENCRYPTION_MODE");
        }
        if (p.getNonceBytes().length != 12) {
            throw new SecurityException("ERR_NONCE_LENGTH");
        }
        if (p.getAuthTagBytes().length != 16) {
            throw new SecurityException("ERR_AUTH_TAG_LENGTH");
        }
        if (p.getCiphertextBytes().length == 0) {
            throw new SecurityException("ERR_EMPTY_CIPHERTEXT");
        }
        if (p.getReplayProtectionId() == null || p.getReplayProtectionId().isBlank()) {
            throw new SecurityException("ERR_MISSING_REPLAY_ID");
        }
        if (p.getEncryptionMode() == MessagePacket.EncryptionMode.AUTO_X25519
                && (p.getSenderPublicKey() == null || p.getSenderPublicKey().isBlank())) {
            throw new SecurityException("ERR_MISSING_SENDER_KEY: AUTO mode requires senderPublicKey");
        }
    }
    private static void validateTimestamp(long packetTimestamp) {
        long now = Instant.now().toEpochMilli();
        long age = now - packetTimestamp;
        if (age < 0 || age > MAX_PACKET_AGE_MS) {
            throw new SecurityException(
                "ERR_PACKET_EXPIRED: Packet age " + age + "ms exceeds allowed window of " + MAX_PACKET_AGE_MS + "ms"
            );
        }
    }
    private static void validateReplayId(String replayId) {
        long now = Instant.now().toEpochMilli();
        SEEN_REPLAY_IDS.entrySet().removeIf(e -> (now - e.getValue()) > MAX_PACKET_AGE_MS);
        Long existing = SEEN_REPLAY_IDS.putIfAbsent(replayId, now);
        if (existing != null) {
            throw new SecurityException("ERR_REPLAY_DETECTED: Duplicate packet ID rejected: " + replayId);
        }
    }
}
