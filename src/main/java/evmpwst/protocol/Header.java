package evmpwst.protocol;
import evmpwst.utils.BitStream;
public class Header {
    private int protocolVersion = 1;
    private int payloadLengthBytes;
    public Header(int payloadLengthBytes) {
        this.payloadLengthBytes = payloadLengthBytes;
    }
    private Header() {}
    public int getPayloadLengthBytes() {
        return payloadLengthBytes;
    }
    public int getProtocolVersion() {
        return protocolVersion;
    }
    public void writeToStream(BitStream stream) {
        stream.writeBits(protocolVersion, 8);
        stream.writeBits(payloadLengthBytes, 32);
        stream.writeBits(0, 24); 
    }
    public static Header readFromStream(BitStream stream) {
        Header header = new Header();
        header.protocolVersion = (int) stream.readBits(8);
        header.payloadLengthBytes = (int) stream.readBits(32);
        stream.readBits(24);
        return header;
    }
}
