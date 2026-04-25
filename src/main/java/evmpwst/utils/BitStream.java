package evmpwst.utils;
import java.util.Arrays;
public class BitStream {
    private byte[] data;
    private int bitLength;
    private int readPosition;
    public BitStream(int capacityBytes) {
        this.data = new byte[capacityBytes];
        this.bitLength = 0;
        this.readPosition = 0;
    }
    public BitStream(byte[] sourceData, int bitLength) {
        this.data = Arrays.copyOf(sourceData, sourceData.length);
        this.bitLength = bitLength;
        this.readPosition = 0;
    }
    public void writeBits(long value, int numBits) {
        if (numBits > 64 || numBits <= 0) {
            throw new IllegalArgumentException("Dozwolone od 1 do 64 bitów jednorazowo");
        }
        for (int i = numBits - 1; i >= 0; i--) {
            int bit = (int) ((value >> i) & 1);
            writeBit(bit);
        }
    }
    public void writeBit(int bit) {
        int byteIndex = bitLength / 8;
        int bitIndex = 7 - (bitLength % 8);
        if (byteIndex >= data.length) {
            expandData();
        }
        if (bit == 1) {
            data[byteIndex] |= (1 << bitIndex);
        } else {
            data[byteIndex] &= ~(1 << bitIndex);
        }
        bitLength++;
    }
    public void writeBytes(byte[] bytes) {
        for (byte b : bytes) {
            writeBits(b & 0xFF, 8);
        }
    }
    public long readBits(int numBits) {
        if (numBits > 64 || numBits <= 0) {
            throw new IllegalArgumentException("Dozwolone od 1 do 64 bitów jednorazowo");
        }
        if (readPosition + numBits > bitLength) {
            throw new IndexOutOfBoundsException("Brak wystarczającej liczby bitów do odczytu");
        }
        long result = 0;
        for (int i = 0; i < numBits; i++) {
            result = (result << 1) | readBit();
        }
        return result;
    }
    public int readBit() {
        if (readPosition >= bitLength) {
            throw new IndexOutOfBoundsException("Koniec strumienia bitów");
        }
        int byteIndex = readPosition / 8;
        int bitIndex = 7 - (readPosition % 8);
        int bit = (data[byteIndex] >> bitIndex) & 1;
        readPosition++;
        return bit;
    }
    public byte[] readBytes(int numBytes) {
        byte[] result = new byte[numBytes];
        for (int i = 0; i < numBytes; i++) {
            result[i] = (byte) readBits(8);
        }
        return result;
    }
    public byte[] toByteArray() {
        int bytesCount = (bitLength + 7) / 8;
        return Arrays.copyOf(data, bytesCount);
    }
    public int getBitLength() { return bitLength; }
    public int getReadPosition() { return readPosition; }
    public void setReadPosition(int pos) { this.readPosition = pos; }
    private void expandData() {
        data = Arrays.copyOf(data, data.length * 2 + 1);
    }
}
