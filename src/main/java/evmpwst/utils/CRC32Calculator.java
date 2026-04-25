package evmpwst.utils;
import java.util.zip.CRC32;
public class CRC32Calculator {
    public static long calculate(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        return crc.getValue();
    }
    public static boolean verify(byte[] data, long expectedCrc) {
        return calculate(data) == expectedCrc;
    }
}
