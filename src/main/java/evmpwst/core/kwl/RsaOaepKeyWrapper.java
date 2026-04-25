package evmpwst.core.kwl;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
public class RsaOaepKeyWrapper implements KeyWrapper {
    private final PublicKey recipientPublicKey;
    private final PrivateKey myPrivateKey;
    public RsaOaepKeyWrapper(PublicKey recipientPublicKey, PrivateKey myPrivateKey) {
        this.recipientPublicKey = recipientPublicKey;
        this.myPrivateKey = myPrivateKey;
    }
    @Override
    public KeyPacket wrap(byte[] x25519PublicKeyBytes) {
        if (recipientPublicKey == null) throw new SecurityException("Brak asymetrycznego klucza Out-Of-Band (Publicznego) dla RSA");
        try {
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
            );
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey, oaepParams);
            byte[] ciphertext = cipher.doFinal(x25519PublicKeyBytes);
            byte algoId = (ciphertext.length == 512) ? KeyPacket.ALGO_RSA_OAEP_4096 : KeyPacket.ALGO_RSA_OAEP_2048;
            return new KeyPacket(algoId, null, ciphertext, null);
        } catch (Exception e) {
            throw new SecurityException("ERR_ENCRYPTION_FAILED: Zawiodło RSA-OAEP Key Wrapping", e);
        }
    }
    @Override
    public byte[] unwrap(KeyPacket packet) {
        if (myPrivateKey == null) throw new SecurityException("Brak klucza prywatnego instalacji RSA, by zwolnić blokadę Key Wrapping KWL");
        if (packet.getAlgorithmId() != KeyPacket.ALGO_RSA_OAEP_2048 && packet.getAlgorithmId() != KeyPacket.ALGO_RSA_OAEP_4096) {
             throw new SecurityException("Błędnie dobrany KeyWrapper dla tej paczki!");
        }
        try {
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT
            );
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.DECRYPT_MODE, myPrivateKey, oaepParams);
            byte[] decrypted = cipher.doFinal(packet.getCiphertext());
            KeyValidator.validateX25519PublicKey(decrypted);
            return decrypted;
        } catch (Exception e) {
            throw new SecurityException("ERR_DECRYPTION_FAILED: Odczyt zabezpieczonego klucza krzywej nie powiódł się z weryfikacją Paddingu.", e);
        }
    }
}
