package evmpwst.utils;
import java.awt.image.BufferedImage;
public class ImageUtils {
    public static final int IMG_SIZE = 512;
    public static final int MARKER_SIZE = 8;
    public static final long ORIENTATION_MARKER = 0xAAC0A09088848281L;
    public static BufferedImage encodeToImage(BitStream stream) {
        if (stream.getBitLength() > IMG_SIZE * IMG_SIZE) {
            throw new IllegalArgumentException("Strumień przekracza maksymalną wielkość obrazu!");
        }
        BufferedImage img = new BufferedImage(IMG_SIZE, IMG_SIZE, BufferedImage.TYPE_BYTE_BINARY);
        int currentBitIndex = 0;
        stream.setReadPosition(0);
        while (stream.getReadPosition() < stream.getBitLength()) {
            int bit = stream.readBit();
            int[] coords = getCoordinatesForSequenceIndex(currentBitIndex);
            int color = (bit == 1) ? 0xFFFFFFFF : 0xFF000000;
            img.setRGB(coords[0], coords[1], color);
            currentBitIndex++;
        }
        while (currentBitIndex < IMG_SIZE * IMG_SIZE) {
            int bit = Math.random() > 0.5 ? 1 : 0;
            int[] coords = getCoordinatesForSequenceIndex(currentBitIndex);
            int color = (bit == 1) ? 0xFFFFFFFF : 0xFF000000;
            img.setRGB(coords[0], coords[1], color);
            currentBitIndex++;
        }
        return img;
    }
    public static BitStream extractFromImage(BufferedImage img) {
        if (img.getWidth() != IMG_SIZE || img.getHeight() != IMG_SIZE) {
            throw new IllegalArgumentException("ERR_IMAGE_DIMENSIONS: Nieprawidłowe wymiary obrazu.");
        }
        int rotation = detectRotation(img);
        if (rotation == -1) {
            throw new IllegalArgumentException("ERR_ORIENTATION_MARKER: Nie wykryto poprawnego markera 8x8.");
        }
        BitStream stream = new BitStream(IMG_SIZE * IMG_SIZE / 8);
        for (int i = 0; i < IMG_SIZE * IMG_SIZE; i++) {
            int[] rawCoords = getCoordinatesForSequenceIndex(i);
            int[] adjustedCoords = applyRotation(rawCoords[0], rawCoords[1], rotation);
            int rgb = img.getRGB(adjustedCoords[0], adjustedCoords[1]);
            int bit = isWhite(rgb) ? 1 : 0;
            stream.writeBit(bit);
        }
        return stream;
    }
    private static int detectRotation(BufferedImage img) {
        int[][] corners = {
            {0, 0},
            {IMG_SIZE - MARKER_SIZE, 0},
            {IMG_SIZE - MARKER_SIZE, IMG_SIZE - MARKER_SIZE},
            {0, IMG_SIZE - MARKER_SIZE}
        };
        for (int rotation = 0; rotation < 4; rotation++) {
            int startX = corners[rotation][0];
            int startY = corners[rotation][1];
            if (verifyMarkerAt(img, startX, startY, rotation)) {
                return rotation;
            }
        }
        return -1;
    }
    private static boolean verifyMarkerAt(BufferedImage img, int startX, int startY, int rotation) {
        long readMarker = 0;
        for (int i = 0; i < 64; i++) {
            int mx = i % MARKER_SIZE;
            int my = i / MARKER_SIZE;
            int realX = 0;
            int realY = 0;
            switch (rotation) {
                case 0: realX = startX + mx; realY = startY + my; break;
                case 1: realX = startX + (MARKER_SIZE - 1 - my); realY = startY + mx; break;
                case 2: realX = startX + (MARKER_SIZE - 1 - mx); realY = startY + (MARKER_SIZE - 1 - my); break;
                case 3: realX = startX + my; realY = startY + (MARKER_SIZE - 1 - mx); break;
            }
            int rgb = img.getRGB(realX, realY);
            if (isWhite(rgb)) {
                readMarker |= (1L << (63 - i));
            }
        }
        return readMarker == ORIENTATION_MARKER;
    }
    private static int[] applyRotation(int x, int y, int rotation) {
        switch (rotation) {
            case 0: return new int[]{x, y};
            case 1: return new int[]{IMG_SIZE - 1 - y, x};
            case 2: return new int[]{IMG_SIZE - 1 - x, IMG_SIZE - 1 - y};
            case 3: return new int[]{y, IMG_SIZE - 1 - x};
        }
        return new int[]{x, y};
    }
    private static int[] getCoordinatesForSequenceIndex(int index) {
        int x, y;
        if (index < 64) {
            x = index % MARKER_SIZE;
            y = index / MARKER_SIZE;
        } else {
            int rem = index - 64;
            if (rem < 8 * (IMG_SIZE - MARKER_SIZE)) {
                y = rem / (IMG_SIZE - MARKER_SIZE);
                x = MARKER_SIZE + (rem % (IMG_SIZE - MARKER_SIZE));
            } else {
                int lowerRem = rem - 8 * (IMG_SIZE - MARKER_SIZE);
                y = MARKER_SIZE + (lowerRem / IMG_SIZE);
                x = lowerRem % IMG_SIZE;
            }
        }
        return new int[]{x, y};
    }
    private static boolean isWhite(int rgb) {
        int r = (rgb >> 16) & 0xFF;
        int g = (rgb >> 8) & 0xFF;
        int b = rgb & 0xFF;
        return ((r + g + b) / 3) > 127;
    }
}
