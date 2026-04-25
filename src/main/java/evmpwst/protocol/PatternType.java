package evmpwst.protocol;
public enum PatternType {
    TEXT_MESSAGE(1),
    MULTI_MESSAGE(2),
    COMMAND_PACKET(3),
    FILE_PAYLOAD(4),
    COMPRESSED_BLOCK(5),
    DEBUG_FRAME(6),
    PRIVATE_CHANNEL_A(7),
    PRIVATE_CHANNEL_B(8),
    BROADCAST(9),
    SYSTEM_SYNC(10),
    KEY_UPDATE(11),
    CHAT_FRAGMENT(12),
    STREAM_BLOCK(13),
    METADATA_ONLY(14),
    RESERVED_15(15),
    RESERVED_16(16);
    private final int id;
    PatternType(int id) {
        this.id = id;
    }
    public int getId() {
        return id;
    }
    public static PatternType fromId(int id) {
        for (PatternType type : values()) {
            if (type.id == id) {
                return type;
            }
        }
        throw new IllegalArgumentException("ERR_INVALID_PATTERN: Nieznany identyfikator Pattern ID -> " + id);
    }
}
