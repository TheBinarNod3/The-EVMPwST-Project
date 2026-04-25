package evmpwst.tests.network;
import evmpwst.network.CryptoService;
import evmpwst.network.HKDFService;
import evmpwst.network.KeyManager;
import org.junit.jupiter.api.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.*;
@DisplayName("Crypto Tests — HKDF + CryptoService")
class CryptoTests {
    @Test
    @DisplayName("HKDF-SHA256: RFC 5869 Test Case 1 — extract output")
    void hkdf_rfc5869_testcase1_extract() {
        byte[] ikm  = HexFormat.of().parseHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = HexFormat.of().parseHex("000102030405060708090a0b0c");
        String expectedPrkHex = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
        byte[] derived1 = HKDFService.derive(ikm, salt, "evmpwst-enc-v1", 32);
        byte[] derived2 = HKDFService.derive(ikm, salt, "evmpwst-enc-v1", 32);
        assertArrayEquals(derived1, derived2, "HKDF must be deterministic");
    }
    @Test
    @DisplayName("HKDF: Different info labels produce different outputs")
    void hkdf_domainSeparation() {
        byte[] ikm  = new byte[32];
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(ikm);
        byte[] encKey    = HKDFService.derive(ikm, salt, HKDFService.INFO_ENCRYPTION, 32);
        byte[] nonceKey  = HKDFService.derive(ikm, salt, HKDFService.INFO_NONCE_SEED, 12);
        assertFalse(Arrays.equals(
            Arrays.copyOf(encKey, 12), nonceKey
        ), "Different info labels must produce independent outputs");
    }
    @Test
    @DisplayName("HKDF: Empty IKM throws exception")
    void hkdf_emptyIkm() {
        assertThrows(IllegalArgumentException.class,
            () -> HKDFService.derive(new byte[0], null, "test", 32));
    }
    @Test
    @DisplayName("HKDF: Output length out of bounds throws exception")
    void hkdf_invalidOutputLength() {
        byte[] ikm = new byte[32];
        new SecureRandom().nextBytes(ikm);
        assertThrows(IllegalArgumentException.class,
            () -> HKDFService.derive(ikm, null, "test", 0));
        assertThrows(IllegalArgumentException.class,
            () -> HKDFService.derive(ikm, null, "test", 256 * 32 + 1));
    }
    @Test
    @DisplayName("HKDF: deriveAll produces 32-byte encKey and 12-byte nonceSeed")
    void hkdf_deriveAll_outputSizes() {
        byte[] ikm = new byte[32];
        new SecureRandom().nextBytes(ikm);
        HKDFService.DerivedKeys keys = HKDFService.deriveAll(ikm, null);
        assertEquals(32, keys.encryptionKey.length);
        assertEquals(12, keys.nonceSeed.length);
    }
    @Test
    @DisplayName("CryptoService: encrypt/decrypt round-trip")
    void crypto_roundTrip() {
        byte[] ikm = new byte[32];
        new SecureRandom().nextBytes(ikm);
        CryptoService sender   = new CryptoService(ikm, null);
        CryptoService receiver = new CryptoService(ikm, null);
        byte[] plaintext = "Hello, EVMPwST!".getBytes(StandardCharsets.UTF_8);
        CryptoService.EncryptedPayload ep = sender.encrypt(plaintext);
        byte[] decrypted = receiver.decrypt(ep);
        assertArrayEquals(plaintext, decrypted);
    }
    @Test
    @DisplayName("CryptoService: tampered auth tag causes SecurityException")
    void crypto_tamperedAuthTag() {
        byte[] ikm = new byte[32];
        new SecureRandom().nextBytes(ikm);
        CryptoService crypto = new CryptoService(ikm, null);
        CryptoService.EncryptedPayload ep = crypto.encrypt("test".getBytes());
        byte[] tamperedTag = Arrays.copyOf(ep.authTag, ep.authTag.length);
        tamperedTag[0] ^= 0xFF;
        CryptoService.EncryptedPayload tampered = new CryptoService.EncryptedPayload(
            ep.nonce, ep.ciphertext, tamperedTag);
        assertThrows(SecurityException.class, () -> crypto.decrypt(tampered));
    }
    @Test
    @DisplayName("CryptoService: tampered ciphertext causes SecurityException")
    void crypto_tamperedCiphertext() {
        byte[] ikm = new byte[32];
        new SecureRandom().nextBytes(ikm);
        CryptoService crypto = new CryptoService(ikm, null);
        CryptoService.EncryptedPayload ep = crypto.encrypt("secret message".getBytes());
        byte[] tamperedCt = Arrays.copyOf(ep.ciphertext, ep.ciphertext.length);
        tamperedCt[5] ^= 0x01;
        CryptoService.EncryptedPayload tampered = new CryptoService.EncryptedPayload(
            ep.nonce, tamperedCt, ep.authTag);
        assertThrows(SecurityException.class, () -> crypto.decrypt(tampered));
    }
    @Test
    @DisplayName("CryptoService: wrong key causes SecurityException")
    void crypto_wrongKey() {
        byte[] senderKey   = new byte[32];
        byte[] receiverKey = new byte[32];
        new SecureRandom().nextBytes(senderKey);
        new SecureRandom().nextBytes(receiverKey);
        CryptoService sender   = new CryptoService(senderKey, null);
        CryptoService receiver = new CryptoService(receiverKey, null);
        CryptoService.EncryptedPayload ep = sender.encrypt("sensitive data".getBytes());
        assertThrows(SecurityException.class, () -> receiver.decrypt(ep));
    }
    @Test
    @DisplayName("CryptoService: each encrypt call produces unique nonce")
    void crypto_uniqueNonces() {
        byte[] ikm = new byte[32];
        new SecureRandom().nextBytes(ikm);
        CryptoService crypto = new CryptoService(ikm, null);
        CryptoService.EncryptedPayload ep1 = crypto.encrypt("msg1".getBytes());
        CryptoService.EncryptedPayload ep2 = crypto.encrypt("msg2".getBytes());
        assertFalse(Arrays.equals(ep1.nonce, ep2.nonce), "Each message must use a unique nonce");
    }
    @Test
    @DisplayName("CryptoService: IKM too short throws SecurityException")
    void crypto_shortIkm() {
        assertThrows(SecurityException.class,
            () -> new CryptoService(new byte[8], null));
    }
    @Test
    @DisplayName("CryptoService: same IKM + metadata → same derived keys")
    void crypto_deterministicKeyDerivation() {
        byte[] ikm = new byte[32];
        new SecureRandom().nextBytes(ikm);
        CryptoService c1 = new CryptoService(ikm, null);
        CryptoService c2 = new CryptoService(ikm, null);
        assertArrayEquals(c1.getEncryptionKey(), c2.getEncryptionKey());
    }
    @Test
    @DisplayName("KeyManager: X25519 shared secrets are equal on both sides")
    void keymanager_sharedSecretSymmetry() {
        KeyManager alice = new KeyManager();
        KeyManager bob   = new KeyManager();
        byte[] secretAlice = alice.computeSharedSecret(bob.getPublicKeyBase64());
        byte[] secretBob   = bob.computeSharedSecret(alice.getPublicKeyBase64());
        assertArrayEquals(secretAlice, secretBob, "X25519 DH must produce equal secrets on both sides");
    }
    @Test
    @DisplayName("KeyManager: Different key pairs produce different shared secrets")
    void keymanager_differentPairsGiveDifferentSecrets() {
        KeyManager alice   = new KeyManager();
        KeyManager bob     = new KeyManager();
        KeyManager charlie = new KeyManager();
        byte[] secretAliceBob     = alice.computeSharedSecret(bob.getPublicKeyBase64());
        byte[] secretAliceCharlie = alice.computeSharedSecret(charlie.getPublicKeyBase64());
        assertFalse(Arrays.equals(secretAliceBob, secretAliceCharlie));
    }
    @Test
    @DisplayName("KeyManager: PUBLIC key is accessible, distinct from full pair")
    void keymanager_publicKeyAccess() {
        KeyManager km = new KeyManager();
        assertNotNull(km.getPublicKey());
        assertNotNull(km.getPublicKeyBase64());
        assertFalse(km.getPublicKeyBase64().isEmpty());
    }
    @Test
    @DisplayName("AUTO mode: X25519 → HKDF → CryptoService round-trip")
    void autoMode_fullRoundTrip() {
        KeyManager alice = new KeyManager();
        KeyManager bob   = new KeyManager();
        byte[] sharedAlice = alice.computeSharedSecret(bob.getPublicKeyBase64());
        byte[] sharedBob   = bob.computeSharedSecret(alice.getPublicKeyBase64());
        CryptoService senderCrypto   = new CryptoService(sharedAlice, null);
        CryptoService receiverCrypto = new CryptoService(sharedBob, null);
        byte[] msg = "Top secret via X25519+HKDF!".getBytes(StandardCharsets.UTF_8);
        CryptoService.EncryptedPayload ep = senderCrypto.encrypt(msg);
        byte[] decrypted = receiverCrypto.decrypt(ep);
        assertArrayEquals(msg, decrypted);
    }
}
