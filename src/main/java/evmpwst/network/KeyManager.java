package evmpwst.network;
import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
public final class KeyManager {
    private final KeyPair keyPair;
    public KeyManager() {
        this.keyPair = generateKeyPair();
    }
    public KeyManager(String publicKeyBase64, String privateKeyBase64) {
        try {
            PublicKey pub = decodePublicKey(publicKeyBase64);
            PrivateKey priv = decodePrivateKey(privateKeyBase64);
            this.keyPair = new KeyPair(pub, priv);
        } catch (Exception e) {
            throw new RuntimeException("Failed to restore X25519 key pair", e);
        }
    }
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }
    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }
    public String getPrivateKeyBase64() {
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }
    public byte[] computeSharedSecret(String remotePublicKeyBase64) {
        try {
            PublicKey remoteKey = decodePublicKey(remotePublicKeyBase64);
            KeyAgreement ka = KeyAgreement.getInstance("X25519");
            ka.init(keyPair.getPrivate());
            ka.doPhase(remoteKey, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw new SecurityException("X25519 key agreement failed", e);
        }
    }
    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("X25519 not supported by this JVM", e);
        }
    }
    public static PublicKey decodePublicKey(String base64) throws Exception {
        byte[] raw = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(raw));
    }
    public static PrivateKey decodePrivateKey(String base64) throws Exception {
        byte[] raw = Base64.getDecoder().decode(base64);
        return KeyFactory.getInstance("X25519").generatePrivate(new PKCS8EncodedKeySpec(raw));
    }
}
