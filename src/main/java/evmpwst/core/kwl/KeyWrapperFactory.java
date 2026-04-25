package evmpwst.core.kwl;
import java.security.PrivateKey;
import java.security.PublicKey;
public class KeyWrapperFactory {
    public static KeyWrapper getRsaWrapper(PublicKey recipientPublicKey, PrivateKey myPrivateKey) {
        return new RsaOaepKeyWrapper(recipientPublicKey, myPrivateKey);
    }
    public static KeyWrapper getAesGcmWrapper(byte[] bootstrapKey, NonceManager nonceManager) {
        return new AesGcmKeyWrapper(bootstrapKey, nonceManager);
    }
}
