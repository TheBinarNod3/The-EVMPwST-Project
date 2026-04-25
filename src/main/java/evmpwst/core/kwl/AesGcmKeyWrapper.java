package evmpwst.core.kwl;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
public class AesGcmKeyWrapper implements KeyWrapper {
    private final byte[] bootstrapKey;
    private final NonceManager nonceManager;
    public AesGcmKeyWrapper(byte[] bootstrapKey, NonceManager nonceManager) {
        if (bootstrapKey == null || bootstrapKey.length != 32) {
            throw new SecurityException("ERR_INVALID_KEY_LENGTH: Współdzielony symetryczny klucz Bootstrap musi mieć równo 256-bitów");
        }
        this.bootstrapKey = bootstrapKey;
        this.nonceManager = nonceManager;
    }
    @Override
    public KeyPacket wrap(byte[] x25519PublicKeyBytes) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] nonce = new byte[12];
            random.nextBytes(nonce);
            SecretKeySpec secretKey = new SecretKeySpec(bootstrapKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce); 
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            byte[] encryptedAndTagged = cipher.doFinal(x25519PublicKeyBytes);
            byte[] ciphertext = Arrays.copyOfRange(encryptedAndTagged, 0, encryptedAndTagged.length - 16);
            byte[] authTag = Arrays.copyOfRange(encryptedAndTagged, encryptedAndTagged.length - 16, encryptedAndTagged.length);
            return new KeyPacket(KeyPacket.ALGO_AES_GCM_256, nonce, ciphertext, authTag);
        } catch (Exception e) {
            throw new SecurityException("ERR_ENCRYPTION_FAILED", e);
        }
    }
    @Override
    public byte[] unwrap(KeyPacket packet) {
        if (packet.getAlgorithmId() != KeyPacket.ALGO_AES_GCM_256) {
             throw new SecurityException("ERR_UNKNOWN_ALGORITHM");
        }
        if (!nonceManager.markNonceUsed(packet.getNonce())) {
            throw new SecurityException("ERR_NONCE_REUSE: Odmowa rozpakowania KWL z powodu powtórzenia sygnału Nonce!");
        }
        try {
            SecretKeySpec secretKey = new SecretKeySpec(bootstrapKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, packet.getNonce());
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            byte[] cAndT = new byte[packet.getCiphertext().length + packet.getAuthTag().length];
            System.arraycopy(packet.getCiphertext(), 0, cAndT, 0, packet.getCiphertext().length);
            System.arraycopy(packet.getAuthTag(), 0, cAndT, packet.getCiphertext().length, packet.getAuthTag().length);
            byte[] decrypted = cipher.doFinal(cAndT);
            KeyValidator.validateX25519PublicKey(decrypted);
            return decrypted;
        } catch (javax.crypto.AEADBadTagException e) {
            throw new SecurityException("ERR_AUTH_TAG_INVALID", e);
        } catch (Exception e) {
            throw new SecurityException("ERR_DECRYPTION_FAILED", e);
        }
    }
}
