package evmpwst.protocol;
public class MessageStructure {
    private Header header;
    private PatternType patternType;
    private byte[] nonce;
    private byte[] ciphertext;
    private byte[] authTag;
    public MessageStructure(Header header, PatternType patternType, byte[] nonce, byte[] ciphertext, byte[] authTag) {
        this.header = header;
        this.patternType = patternType;
        this.nonce = nonce;
        this.ciphertext = ciphertext;
        this.authTag = authTag;
    }
    public Header getHeader() { return header; }
    public PatternType getPatternType() { return patternType; }
    public byte[] getNonce() { return nonce; }
    public byte[] getCiphertext() { return ciphertext; }
    public byte[] getAuthTag() { return authTag; }
}
