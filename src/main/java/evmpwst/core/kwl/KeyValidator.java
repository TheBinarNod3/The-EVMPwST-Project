package evmpwst.core.kwl;
public class KeyValidator {
    public static void validateX25519PublicKey(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length != 32) {
            throw new SecurityException("ERR_INVALID_KEY_LENGTH: Odszyfrowany publiczny X25519 wymaga precyzyjnie 32 bajtów");
        }
        boolean allZeros = true;
        for (byte b : keyBytes) {
            if (b != 0) { allZeros = false; break; }
        }
        if (allZeros) {
            throw new SecurityException("ERR_WEAK_PUBLIC_KEY: Przedłożono pusty klucz należący do podgrupy ryzyka zera!");
        }
    }
}
