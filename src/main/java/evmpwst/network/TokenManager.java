package evmpwst.network;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
public final class TokenManager {
    public enum ExportFormat { BASE64, HEX }
    private static final int TOKEN_BYTES = 32;
    private static final SecureRandom RNG = new SecureRandom();
    private final Set<String> usedTokens = Collections.newSetFromMap(new ConcurrentHashMap<>());
    public byte[] generateToken() {
        byte[] token = new byte[TOKEN_BYTES];
        RNG.nextBytes(token);
        return token;
    }
    public String exportToken(byte[] token, ExportFormat format) {
        validateTokenBytes(token);
        return switch (format) {
            case BASE64 -> Base64.getEncoder().encodeToString(token);
            case HEX    -> HexFormat.of().formatHex(token);
        };
    }
    public byte[] importToken(String tokenString) {
        if (tokenString == null || tokenString.isBlank()) {
            throw new SecurityException("Token must not be empty");
        }
        String trimmed = tokenString.strip();
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(trimmed);
        } catch (IllegalArgumentException e) {
            try {
                raw = HexFormat.of().parseHex(trimmed);
            } catch (Exception ex) {
                throw new SecurityException("Token format unrecognized (expected Base64 or Hex)");
            }
        }
        validateTokenBytes(raw);
        return raw;
    }
    public void markUsed(byte[] token) {
        validateTokenBytes(token);
        String key = Base64.getEncoder().encodeToString(token);
        if (!usedTokens.add(key)) {
            throw new SecurityException("ERR_TOKEN_REUSE: This token has already been used in this session");
        }
    }
    public boolean isUsed(byte[] token) {
        validateTokenBytes(token);
        return usedTokens.contains(Base64.getEncoder().encodeToString(token));
    }
    private static void validateTokenBytes(byte[] token) {
        if (token == null || token.length < TOKEN_BYTES) {
            throw new SecurityException(
                "ERR_TOKEN_INVALID: Token must be at least " + TOKEN_BYTES + " bytes (256-bit entropy)"
            );
        }
    }
}
