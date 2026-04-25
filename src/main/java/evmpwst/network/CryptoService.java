package evmpwst.network;
import evmpwst.core.CryptoEngine;
import java.security.SecureRandom;
import java.util.Arrays;
public final class CryptoService {
    public enum Mode { AUTO_X25519, MANUAL_TOKEN }
    private final CryptoEngine engine;
    private final HKDFService.DerivedKeys derivedKeys;
    private final SecureRandom rng = new SecureRandom();
    public CryptoService(byte[] ikm, byte[] salt) {
        if (ikm == null || ikm.length < 16) {
            throw new SecurityException("IKM must be at least 128 bits");
        }
        this.derivedKeys = HKDFService.deriveAll(ikm, salt);
        this.engine = new CryptoEngine(derivedKeys.encryptionKey);
    }
    public EncryptedPayload encrypt(byte[] plaintext) {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("Plaintext must not be empty");
        }
        byte[] randomPart = new byte[12];
        rng.nextBytes(randomPart);
        byte[] nonce = xor(randomPart, derivedKeys.nonceSeed);
        byte[][] result = engine.encrypt(plaintext, nonce);
        return new EncryptedPayload(nonce, result[0], result[1]);
    }
    public byte[] decrypt(EncryptedPayload payload) {
        SecurityValidator.validateEncryptedPayload(payload);
        return engine.decrypt(payload.ciphertext, payload.authTag, payload.nonce);
    }
    public byte[] getEncryptionKey() {
        return Arrays.copyOf(derivedKeys.encryptionKey, derivedKeys.encryptionKey.length);
    }
    private static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }
    public static final class EncryptedPayload {
        public final byte[] nonce;
        public final byte[] ciphertext;
        public final byte[] authTag;
        public EncryptedPayload(byte[] nonce, byte[] ciphertext, byte[] authTag) {
            this.nonce = nonce;
            this.ciphertext = ciphertext;
            this.authTag = authTag;
        }
    }
}
