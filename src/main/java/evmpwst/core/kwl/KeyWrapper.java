package evmpwst.core.kwl;
public interface KeyWrapper {
    KeyPacket wrap(byte[] x25519PublicKeyBytes) throws SecurityException;
    byte[] unwrap(KeyPacket packet) throws SecurityException;
}
