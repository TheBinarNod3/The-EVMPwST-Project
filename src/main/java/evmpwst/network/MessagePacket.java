package evmpwst.network;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
public final class MessagePacket {
    public static final int PROTOCOL_VERSION = 2;
    public enum EncryptionMode { AUTO_X25519, MANUAL_TOKEN }
    private final int packetVersion;
    private final EncryptionMode encryptionMode;
    private final long timestamp;
    private final String replayProtectionId;
    private final String nonce;
    private final String ciphertext;
    private final String authTag;
    private final String senderPublicKey;
    private final String tokenHint;
    private final int protocolFlags;
    private static final Gson GSON = new GsonBuilder().create();
    private MessagePacket(Builder b) {
        this.packetVersion    = PROTOCOL_VERSION;
        this.encryptionMode   = b.encryptionMode;
        this.timestamp        = Instant.now().toEpochMilli();
        this.replayProtectionId = UUID.randomUUID().toString();
        this.nonce            = Base64.getEncoder().encodeToString(b.nonce);
        this.ciphertext       = Base64.getEncoder().encodeToString(b.ciphertext);
        this.authTag          = Base64.getEncoder().encodeToString(b.authTag);
        this.senderPublicKey  = b.senderPublicKey;
        this.tokenHint        = b.tokenHint;
        this.protocolFlags    = b.protocolFlags;
    }
    public byte[] getNonceBytes()      { return Base64.getDecoder().decode(nonce); }
    public byte[] getCiphertextBytes() { return Base64.getDecoder().decode(ciphertext); }
    public byte[] getAuthTagBytes()    { return Base64.getDecoder().decode(authTag); }
    public EncryptionMode getEncryptionMode() { return encryptionMode; }
    public int getPacketVersion()             { return packetVersion; }
    public long getTimestamp()                { return timestamp; }
    public String getReplayProtectionId()     { return replayProtectionId; }
    public String getSenderPublicKey()        { return senderPublicKey; }
    public String getTokenHint()              { return tokenHint; }
    public int getProtocolFlags()             { return protocolFlags; }
    public String toJson() {
        return GSON.toJson(this);
    }
    public static MessagePacket fromJson(String json) {
        return GSON.fromJson(json, MessagePacket.class);
    }
    public static final class Builder {
        private EncryptionMode encryptionMode;
        private byte[] nonce;
        private byte[] ciphertext;
        private byte[] authTag;
        private String senderPublicKey;
        private String tokenHint;
        private int protocolFlags = 0;
        public Builder mode(EncryptionMode mode) { this.encryptionMode = mode; return this; }
        public Builder nonce(byte[] n)            { this.nonce = n; return this; }
        public Builder ciphertext(byte[] c)       { this.ciphertext = c; return this; }
        public Builder authTag(byte[] t)          { this.authTag = t; return this; }
        public Builder senderPublicKey(String k)  { this.senderPublicKey = k; return this; }
        public Builder tokenHint(String h)        { this.tokenHint = h; return this; }
        public Builder protocolFlags(int f)       { this.protocolFlags = f; return this; }
        public MessagePacket build() {
            if (encryptionMode == null) throw new IllegalStateException("encryptionMode required");
            if (nonce == null || nonce.length != 12) throw new IllegalStateException("nonce must be 12 bytes");
            if (ciphertext == null) throw new IllegalStateException("ciphertext required");
            if (authTag == null || authTag.length != 16) throw new IllegalStateException("authTag must be 16 bytes");
            return new MessagePacket(this);
        }
    }
    public CryptoService.EncryptedPayload toEncryptedPayload() {
        return new CryptoService.EncryptedPayload(getNonceBytes(), getCiphertextBytes(), getAuthTagBytes());
    }
}
