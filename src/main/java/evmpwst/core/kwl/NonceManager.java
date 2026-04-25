package evmpwst.core.kwl;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
public class NonceManager {
    private final Set<ByteBuffer> usedNonces = Collections.newSetFromMap(new ConcurrentHashMap<>());
    public synchronized boolean markNonceUsed(byte[] nonce) {
        if (nonce == null) return false;
        ByteBuffer wrapped = ByteBuffer.wrap(nonce);
        return usedNonces.add(wrapped);
    }
}
