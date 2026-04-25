package evmpwst.tests.network;
import evmpwst.network.HKDFService;
import evmpwst.network.TokenManager;
import org.junit.jupiter.api.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;
@DisplayName("Token Mode Tests — TokenManager + HKDF Token Derivation")
class TokenModeTests {
    private TokenManager tokenManager;
    @BeforeEach
    void setUp() {
        tokenManager = new TokenManager();
    }
    @Test
    @DisplayName("Token: generated token is 32 bytes")
    void token_length() {
        byte[] token = tokenManager.generateToken();
        assertEquals(32, token.length);
    }
    @Test
    @DisplayName("Token: each generated token is unique")
    void token_uniqueness() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            byte[] token = tokenManager.generateToken();
            String encoded = Base64.getEncoder().encodeToString(token);
            assertTrue(seen.add(encoded), "Duplicate token generated at iteration " + i);
        }
    }
    @Test
    @DisplayName("Token: exported Base64 round-trips through import")
    void token_base64RoundTrip() {
        byte[] original = tokenManager.generateToken();
        String exported = tokenManager.exportToken(original, TokenManager.ExportFormat.BASE64);
        byte[] imported = tokenManager.importToken(exported);
        assertArrayEquals(original, imported);
    }
    @Test
    @DisplayName("Token: exported Hex produces correct length and decodes losslessly")
    void token_hexRoundTrip() {
        byte[] original = tokenManager.generateToken();
        String exported = tokenManager.exportToken(original, TokenManager.ExportFormat.HEX);
        assertEquals(64, exported.length(), "Hex of 32 bytes must be 64 chars");
        byte[] imported = HexFormat.of().parseHex(exported);
        assertArrayEquals(original, imported, "Hex encode/decode must be lossless");
    }
    @Test
    @DisplayName("Token: reuse detection throws SecurityException")
    void token_reuseRejected() {
        byte[] token = tokenManager.generateToken();
        tokenManager.markUsed(token);
        assertThrows(SecurityException.class, () -> tokenManager.markUsed(token));
    }
    @Test
    @DisplayName("Token: isUsed returns false before markUsed")
    void token_isUsed_beforeMark() {
        byte[] token = tokenManager.generateToken();
        assertFalse(tokenManager.isUsed(token));
    }
    @Test
    @DisplayName("Token: isUsed returns true after markUsed")
    void token_isUsed_afterMark() {
        byte[] token = tokenManager.generateToken();
        tokenManager.markUsed(token);
        assertTrue(tokenManager.isUsed(token));
    }
    @Test
    @DisplayName("Token: empty string import throws SecurityException")
    void token_emptyImport() {
        assertThrows(SecurityException.class, () -> tokenManager.importToken(""));
        assertThrows(SecurityException.class, () -> tokenManager.importToken("   "));
        assertThrows(SecurityException.class, () -> tokenManager.importToken(null));
    }
    @Test
    @DisplayName("Token: malformed string import throws SecurityException")
    void token_malformedImport() {
        assertThrows(SecurityException.class,
            () -> tokenManager.importToken("!@#$%^&*()_+|"));
    }
    @Test
    @DisplayName("Token: too-short decoded bytes throws SecurityException")
    void token_tooShort() {
        String shortToken = Base64.getEncoder().encodeToString(new byte[16]);
        assertThrows(SecurityException.class, () -> tokenManager.importToken(shortToken));
    }
    @Test
    @DisplayName("Token: partial token (truncated) throws SecurityException")
    void token_partialToken() {
        byte[] token = tokenManager.generateToken();
        String full = tokenManager.exportToken(token, TokenManager.ExportFormat.BASE64);
        String partial = full.substring(0, full.length() / 2);
        assertThrows(SecurityException.class, () -> tokenManager.importToken(partial));
    }
    @Test
    @DisplayName("HKDF + Token: same token → same derived key (deterministic)")
    void hkdf_token_deterministic() {
        byte[] token = tokenManager.generateToken();
        byte[] key1 = HKDFService.derive(token, null, HKDFService.INFO_ENCRYPTION, 32);
        byte[] key2 = HKDFService.derive(token, null, HKDFService.INFO_ENCRYPTION, 32);
        assertArrayEquals(key1, key2, "HKDF must be deterministic for the same input");
    }
    @Test
    @DisplayName("HKDF + Token: different tokens → different derived keys")
    void hkdf_token_differentInputs() {
        byte[] token1 = tokenManager.generateToken();
        byte[] token2 = tokenManager.generateToken();
        byte[] key1 = HKDFService.derive(token1, null, HKDFService.INFO_ENCRYPTION, 32);
        byte[] key2 = HKDFService.derive(token2, null, HKDFService.INFO_ENCRYPTION, 32);
        assertFalse(Arrays.equals(key1, key2), "Different tokens must produce different keys");
    }
    @Test
    @DisplayName("HKDF + Token: raw token NOT equal to derived key")
    void hkdf_token_notRawKey() {
        byte[] token = tokenManager.generateToken();
        byte[] derivedKey = HKDFService.derive(token, null, HKDFService.INFO_ENCRYPTION, 32);
        assertFalse(Arrays.equals(token, derivedKey),
            "HKDF output must differ from raw token (token must never be raw key)");
    }
    @Test
    @DisplayName("Token: tampered token produces different derived key → decrypt fails")
    void hkdf_token_tamperedTokenDecryptFails() {
        byte[] token = tokenManager.generateToken();
        byte[] derivedCorrect = HKDFService.derive(token, null, HKDFService.INFO_ENCRYPTION, 32);
        byte[] tampered = Arrays.copyOf(token, token.length);
        tampered[0] ^= 0xFF;
        byte[] derivedTampered = HKDFService.derive(tampered, null, HKDFService.INFO_ENCRYPTION, 32);
        assertFalse(Arrays.equals(derivedCorrect, derivedTampered));
    }
    @Test
    @DisplayName("Token export: null token throws exception")
    void token_export_null() {
        assertThrows(SecurityException.class,
            () -> tokenManager.exportToken(null, TokenManager.ExportFormat.BASE64));
    }
    @Test
    @DisplayName("Token: markUsed with short bytes throws SecurityException")
    void token_markUsed_shortBytes() {
        assertThrows(SecurityException.class,
            () -> tokenManager.markUsed(new byte[8]));
    }
}
