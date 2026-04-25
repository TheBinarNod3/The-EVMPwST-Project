package evmpwst.core;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.LinkedHashSet;
import java.util.Arrays;
import java.util.Base64;
public class CryptoEngine {
    private static final int NONCE_WINDOW_SIZE = 10000;
    private final LinkedHashSet<String> seenNonces;
    private final SecretKey sessionKey;
    public CryptoEngine(byte[] sessionKeyRaw) {
        if (sessionKeyRaw.length != 32) {
            throw new IllegalArgumentException("Klucz sesji musi mieć dokładnie 256 bitów (32 bajty)");
        }
        this.sessionKey = new SecretKeySpec(sessionKeyRaw, "ChaCha20");
        this.seenNonces = new LinkedHashSet<>();
    }
    public byte[] generateNonce() {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }
    public byte[][] encrypt(byte[] plaintext, byte[] nonce) {
        if (nonce.length != 12) {
            throw new IllegalArgumentException("Nonce musi mieć długość 96-bitów (12 bajtów)");
        }
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(nonce));
            byte[] encryptedAndTagged = cipher.doFinal(plaintext);
            int tagLength = 16;
            byte[] ciphertext = Arrays.copyOfRange(encryptedAndTagged, 0, encryptedAndTagged.length - tagLength);
            byte[] authTag = Arrays.copyOfRange(encryptedAndTagged, encryptedAndTagged.length - tagLength, encryptedAndTagged.length);
            return new byte[][] { ciphertext, authTag };
        } catch (Exception e) {
            throw new RuntimeException("Błąd podczas autoryzowanego szyfrowania komunikatu", e);
        }
    }
    public byte[] decrypt(byte[] ciphertext, byte[] authTag, byte[] nonce) {
        if (authTag.length != 16) {
             throw new SecurityException("ERR_AUTH_TAG_INVALID: Authtag uległ naruszeniu na poziomie bitów długości");
        }
        String nonceStr = Base64.getEncoder().encodeToString(nonce);
        synchronized(seenNonces) {
            if (seenNonces.contains(nonceStr)) {
                throw new SecurityException("ERR_NONCE_REUSE: Wykryto próbę ataku replay! Ten nonce został w niedalekiej przeszłości już wystemplowany.");
            }
        }
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(nonce));
            byte[] cAndT = new byte[ciphertext.length + authTag.length];
            System.arraycopy(ciphertext, 0, cAndT, 0, ciphertext.length);
            System.arraycopy(authTag, 0, cAndT, ciphertext.length, authTag.length);
            byte[] plaintext = cipher.doFinal(cAndT);
            synchronized(seenNonces) {
                seenNonces.add(nonceStr);
                if (seenNonces.size() > NONCE_WINDOW_SIZE) {
                    String firstElement = seenNonces.iterator().next();
                    seenNonces.remove(firstElement);
                }
            }
            return plaintext;
        } catch (javax.crypto.AEADBadTagException e) {
            throw new SecurityException("ERR_AUTH_TAG_INVALID: Weryfikacja kryptograficzna Poly1305 nieudana, wiadomość zmanipulowana", e);
        } catch (Exception e) {
            throw new SecurityException("ERR_DECRYPTION_FAILED: Nieznany błąd podczas odszyfrowywania (np. zmodyfikowany klucz/nieobsługiwane dane)", e);
        }
    }
}
