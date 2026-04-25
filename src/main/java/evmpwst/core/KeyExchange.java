package evmpwst.core;
import java.security.*;
public class KeyExchange {
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algorytm X25519 nie jest wspierany na tej wirtualnej maszynie Java", e);
        }
    }
    public static byte[] deriveSessionKey(PrivateKey myPrivateKey, PublicKey otherPublicKey) {
        try {
            javax.crypto.KeyAgreement keyAgreement = javax.crypto.KeyAgreement.getInstance("X25519");
            keyAgreement.init(myPrivateKey);
            keyAgreement.doPhase(otherPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(sharedSecret);
        } catch (Exception e) {
            throw new RuntimeException("ERR_KEY_DERIVATION: Ustalanie i derywacja klucza sesji zakończona błędem", e);
        }
    }
    public static PublicKey loadPublicKeyFromBase64(String base64) throws Exception {
        byte[] keyBytes = java.util.Base64.getDecoder().decode(base64);
        java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("X25519");
        return kf.generatePublic(spec);
    }
    public static PrivateKey loadPrivateKeyFromBase64(String base64) throws Exception {
        byte[] keyBytes = java.util.Base64.getDecoder().decode(base64);
        java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("X25519");
        return kf.generatePrivate(spec);
    }
}
