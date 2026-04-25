package evmpwst.core;
import evmpwst.protocol.Header;
import evmpwst.protocol.PatternType;
import evmpwst.utils.BitStream;
import evmpwst.utils.CRC32Calculator;
import evmpwst.utils.ImageUtils;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.zip.Deflater;
public class Encoder {
    public static final int MAX_CIPHERTEXT_SIZE = 32719;
    public static BufferedImage encode(byte[] plaintext, PatternType pattern, CryptoEngine engine) {
        byte[] payloadToEncrypt = plaintext;
        if (pattern == PatternType.COMPRESSED_BLOCK) {
            payloadToEncrypt = compress(plaintext);
        }
        byte[] nonce = engine.generateNonce();
        byte[][] encryptedData = engine.encrypt(payloadToEncrypt, nonce);
        byte[] ciphertext = encryptedData[0];
        byte[] authTag = encryptedData[1];
        if (ciphertext.length > MAX_CIPHERTEXT_SIZE) {
            throw new IllegalArgumentException("Całkowita waga przekracza dozwoloną pojemność ramki (32,719 bytes). Obecna waga: " + ciphertext.length);
        }
        BitStream stream = new BitStream(33000);
        stream.writeBits(ImageUtils.ORIENTATION_MARKER, 64);
        Header header = new Header(ciphertext.length);
        header.writeToStream(stream);
        stream.writeBits(pattern.getId(), 8);
        stream.writeBytes(nonce);
        stream.writeBytes(ciphertext);
        stream.writeBytes(authTag);
        byte[] structureDataSoFar = stream.toByteArray();
        long crc32 = CRC32Calculator.calculate(structureDataSoFar);
        stream.writeBits(crc32, 32);
        return ImageUtils.encodeToImage(stream);
    }
    private static byte[] compress(byte[] data) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(data);
        deflater.finish();
        ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            baos.write(buffer, 0, count);
        }
        return baos.toByteArray();
    }
}
