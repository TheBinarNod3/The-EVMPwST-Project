package evmpwst.core;
import evmpwst.protocol.Header;
import evmpwst.protocol.PatternType;
import evmpwst.utils.BitStream;
import evmpwst.utils.CRC32Calculator;
import evmpwst.utils.ImageUtils;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.zip.Inflater;
public class Decoder {
    public static class DecodedPayload {
        public final byte[] plaintext;
        public final PatternType pattern;
        public final byte[] nonce;
        public final long timestamp;
        public DecodedPayload(byte[] plaintext, PatternType pattern, byte[] nonce) {
            this.plaintext = plaintext;
            this.pattern = pattern;
            this.nonce = nonce;
            this.timestamp = System.currentTimeMillis();
        }
    }
    public static DecodedPayload decode(BufferedImage img, CryptoEngine engine) {
        BitStream stream = ImageUtils.extractFromImage(img);
        stream.setReadPosition(0);
        long marker = stream.readBits(64);
        if (marker != ImageUtils.ORIENTATION_MARKER) {
            throw new SecurityException("ERR_ORIENTATION_MARKER: Problem walidacji w logicznym układzie buforu");
        }
        Header header = Header.readFromStream(stream);
        if(header.getPayloadLengthBytes() < 0 || header.getPayloadLengthBytes() > Encoder.MAX_CIPHERTEXT_SIZE) {
            throw new SecurityException("ERR_TRUNCATED_OR_OVERSIZED - Invalid Payload Size parameter");
        }
        int patternId = (int) stream.readBits(8);
        PatternType pattern;
        try {
            pattern = PatternType.fromId(patternId);
        } catch(IllegalArgumentException e) {
            throw new SecurityException("ERR_INVALID_PATTERN", e);
        }
        byte[] nonce = stream.readBytes(12);
        byte[] ciphertext = stream.readBytes(header.getPayloadLengthBytes());
        byte[] authTag = stream.readBytes(16);
        long crcFromImage = stream.readBits(32);
        int structureBytesAmount = 8  + 8  + 1  + 12  + ciphertext.length  + 16 ;
        stream.setReadPosition(0);
        byte[] strictValidationData = stream.readBytes(structureBytesAmount);
        long calculatedCrc = CRC32Calculator.calculate(strictValidationData);
        if (crcFromImage != calculatedCrc) {
             throw new SecurityException("ERR_CRC32_MISMATCH: Integralność naruszona. Moduł dekodujący zablokował rozpakowanie szyfrogramu!");
        }
        byte[] plaintext = engine.decrypt(ciphertext, authTag, nonce);
        if (pattern == PatternType.COMPRESSED_BLOCK) {
            plaintext = decompress(plaintext);
        }
        return new DecodedPayload(plaintext, pattern, nonce);
    }
    private static byte[] decompress(byte[] data) {
        try {
            Inflater inflater = new Inflater();
            inflater.setInput(data);
            ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);
            byte[] buffer = new byte[1024];
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                baos.write(buffer, 0, count);
            }
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Nieudana dekompresja struktury mimo udanego uwierzytelnienia. Paczka mogła być fałszywym skompresowanym payloadem.", e);
        }
    }
}
