package evmpwst.network;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
public final class HKDFService {
    private static final String HMAC_ALG = "HmacSHA256";
    private static final int HASH_LEN = 32;
    public static final String INFO_ENCRYPTION = "evmpwst-enc-v1";
    public static final String INFO_NONCE_SEED  = "evmpwst-nonce-v1";
    private HKDFService() {}
    public static byte[] derive(byte[] ikm, byte[] salt, String info, int length) {
        if (ikm == null || ikm.length == 0) {
            throw new IllegalArgumentException("IKM must not be null or empty");
        }
        if (length <= 0 || length > 255 * HASH_LEN) {
            throw new IllegalArgumentException("Output length out of HKDF bounds");
        }
        byte[] pseudoRandomKey = extract(salt, ikm);
        return expand(pseudoRandomKey, info.getBytes(StandardCharsets.UTF_8), length);
    }
    public static DerivedKeys deriveAll(byte[] ikm, byte[] salt) {
        byte[] encKey   = derive(ikm, salt, INFO_ENCRYPTION, 32);
        byte[] nonceSeed = derive(ikm, salt, INFO_NONCE_SEED, 12);
        return new DerivedKeys(encKey, nonceSeed);
    }
    private static byte[] extract(byte[] salt, byte[] ikm) {
        if (salt == null || salt.length == 0) {
            salt = new byte[HASH_LEN];
        }
        return hmacSha256(salt, ikm);
    }
    private static byte[] expand(byte[] prk, byte[] info, int length) {
        int n = (int) Math.ceil((double) length / HASH_LEN);
        byte[] output = new byte[n * HASH_LEN];
        byte[] t = new byte[0];
        for (int i = 1; i <= n; i++) {
            byte[] input = new byte[t.length + info.length + 1];
            System.arraycopy(t, 0, input, 0, t.length);
            System.arraycopy(info, 0, input, t.length, info.length);
            input[input.length - 1] = (byte) i;
            t = hmacSha256(prk, input);
            System.arraycopy(t, 0, output, (i - 1) * HASH_LEN, HASH_LEN);
        }
        return Arrays.copyOf(output, length);
    }
    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(new SecretKeySpec(key, HMAC_ALG));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HKDF HMAC-SHA256 failure", e);
        }
    }
    public static final class DerivedKeys {
        public final byte[] encryptionKey;
        public final byte[] nonceSeed;
        private DerivedKeys(byte[] encryptionKey, byte[] nonceSeed) {
            this.encryptionKey = encryptionKey;
            this.nonceSeed = nonceSeed;
        }
    }
}
