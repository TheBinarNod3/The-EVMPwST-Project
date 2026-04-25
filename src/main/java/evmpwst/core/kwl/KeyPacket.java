package evmpwst.core.kwl;
import java.util.Arrays;
import java.util.Base64;
public class KeyPacket {
    public static final byte VERSION_1 = 0x01;
    public static final byte ALGO_RSA_OAEP_2048 = 0x01;
    public static final byte ALGO_RSA_OAEP_4096 = 0x02;
    public static final byte ALGO_AES_GCM_256 = 0x10;
    private byte version;
    private byte algorithmId;
    private byte[] nonce;
    private byte[] ciphertext;
    private byte[] authTag;
    public KeyPacket(byte algorithmId, byte[] nonce, byte[] ciphertext, byte[] authTag) {
        this.version = VERSION_1;
        this.algorithmId = algorithmId;
        this.nonce = nonce != null ? nonce : new byte[0];
        this.ciphertext = ciphertext != null ? ciphertext : new byte[0];
        this.authTag = authTag != null ? authTag : new byte[0];
    }
    public byte getAlgorithmId() { return algorithmId; }
    public byte[] getNonce() { return nonce; }
    public byte[] getCiphertext() { return ciphertext; }
    public byte[] getAuthTag() { return authTag; }
    public String toBase64() {
        int totalLen = 2 + nonce.length + ciphertext.length + authTag.length;
        byte[] payload = new byte[totalLen];
        payload[0] = version;
        payload[1] = algorithmId;
        int offset = 2;
        System.arraycopy(nonce, 0, payload, offset, nonce.length);
        offset += nonce.length;
        System.arraycopy(ciphertext, 0, payload, offset, ciphertext.length);
        offset += ciphertext.length;
        System.arraycopy(authTag, 0, payload, offset, authTag.length);
        return Base64.getEncoder().encodeToString(payload);
    }
    public static KeyPacket fromBase64(String base64) {
        if (base64 == null || base64.trim().isEmpty()) {
            throw new SecurityException("ERR_INVALID_BASE64: Klucz P2P nie może być pusty");
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(base64.trim());
        } catch (IllegalArgumentException e) {
            throw new SecurityException("ERR_INVALID_BASE64: Klucz sieciowy nie opiera się na formacie Base64");
        }
        if (raw.length < 2) {
            throw new SecurityException("ERR_MALFORMED_PACKET: Pusta paczka");
        }
        byte ver = raw[0];
        if (ver != VERSION_1) {
            throw new SecurityException("ERR_UNSUPPORTED_VERSION: Niewspierana wersja paczki - " + ver);
        }
        byte algo = raw[1];
        byte[] dNonce = new byte[0];
        byte[] dCiphertext = new byte[0];
        byte[] dAuthTag = new byte[0];
        int offset = 2;
        int remaining = raw.length - offset;
        if (algo == ALGO_RSA_OAEP_2048) {
            if (remaining != 256) throw new SecurityException("ERR_MALFORMED_PACKET: Błędny rozmiar pakietu RSA 2048 (" + remaining + " bajtów)");
            dCiphertext = Arrays.copyOfRange(raw, offset, offset + 256);
        } else if (algo == ALGO_RSA_OAEP_4096) {
            if (remaining != 512) throw new SecurityException("ERR_MALFORMED_PACKET: Błędny rozmiar pakietu RSA 4096 (" + remaining + " bajtów)");
            dCiphertext = Arrays.copyOfRange(raw, offset, offset + 512);
        } else if (algo == ALGO_AES_GCM_256) {
            if (remaining != 60) throw new SecurityException("ERR_MALFORMED_PACKET: Oczekiwano 60 bytów AES GCM dla zawartości kryptograficznej, a odebrano " + remaining);
            dNonce = Arrays.copyOfRange(raw, offset, offset + 12);
            offset += 12;
            dCiphertext = Arrays.copyOfRange(raw, offset, offset + 32);
            offset += 32;
            dAuthTag = Arrays.copyOfRange(raw, offset, offset + 16);
        } else {
            throw new SecurityException("ERR_UNKNOWN_ALGORITHM: Szyfr " + algo + " nie obsugiwany");
        }
        return new KeyPacket(algo, dNonce, dCiphertext, dAuthTag);
    }
}
