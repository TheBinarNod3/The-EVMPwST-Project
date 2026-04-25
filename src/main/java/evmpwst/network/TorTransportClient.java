package evmpwst.network;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
public final class TorTransportClient implements Closeable {
    private static final String TOR_HOST = "127.0.0.1";
    private static final int    TOR_PORT = 9150;
    private static final int    CONNECT_TIMEOUT_MS = 30_000;
    private static final int    READ_TIMEOUT_MS    = 60_000;
    private Socket socket;
    private DataInputStream  in;
    private DataOutputStream out;
    public void connect(String remoteHost, int remotePort) throws IOException {
        validateAddress(remoteHost, remotePort);
        socket = new Socket();
        socket.connect(new InetSocketAddress(TOR_HOST, TOR_PORT), CONNECT_TIMEOUT_MS);
        socket.setSoTimeout(READ_TIMEOUT_MS);
        in  = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());
        performSocks5Handshake(remoteHost, remotePort);
    }
    public void send(byte[] data) throws IOException {
        requireConnected();
        out.writeInt(data.length);
        out.write(data);
        out.flush();
    }
    public byte[] receive() throws IOException {
        requireConnected();
        int length = in.readInt();
        if (length <= 0 || length > 10 * 1024 * 1024) {
            throw new IOException("ERR_FRAME_SIZE: Received invalid frame length: " + length);
        }
        byte[] data = new byte[length];
        in.readFully(data);
        return data;
    }
    public boolean isConnected() {
        return socket != null && socket.isConnected() && !socket.isClosed();
    }
    @Override
    public void close() {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException ignored) {}
    }
    private void performSocks5Handshake(String remoteHost, int remotePort) throws IOException {
        out.write(new byte[]{0x05, 0x01, 0x00});
        out.flush();
        byte[] authResponse = new byte[2];
        in.readFully(authResponse);
        if (authResponse[0] != 0x05 || authResponse[1] != 0x00) {
            throw new IOException("ERR_SOCKS5_AUTH: Proxy rejected no-auth method");
        }
        byte[] hostBytes  = remoteHost.getBytes(StandardCharsets.UTF_8);
        byte[] portBytes  = new byte[]{(byte)(remotePort >> 8), (byte)(remotePort & 0xFF)};
        ByteArrayOutputStream req = new ByteArrayOutputStream();
        req.write(new byte[]{
            0x05,
            0x01,
            0x00,
            0x03,
            (byte) hostBytes.length
        });
        req.write(hostBytes);
        req.write(portBytes);
        out.write(req.toByteArray());
        out.flush();
        byte[] resp = new byte[10];
        in.readFully(resp);
        if (resp[0] != 0x05) {
            throw new IOException("ERR_SOCKS5_VERSION: Unexpected SOCKS version in response");
        }
        if (resp[1] != 0x00) {
            throw new IOException("ERR_SOCKS5_CONNECT: Connection failed, reply code: 0x" + Integer.toHexString(resp[1]));
        }
    }
    private void requireConnected() {
        if (!isConnected()) {
            throw new IllegalStateException("ERR_NOT_CONNECTED: Call connect() before send/receive");
        }
    }
    private static void validateAddress(String host, int port) {
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Host must not be empty");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Invalid port: " + port);
        }
        if (host.endsWith(".onion")) {
            String label = host.replace(".onion", "");
            if (label.length() != 16 && label.length() != 56) {
                throw new IllegalArgumentException("ERR_INVALID_ONION: Malformed .onion address: " + host);
            }
        }
    }
}
