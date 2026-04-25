package evmpwst.network;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.BiConsumer;
public final class TorMessageServer implements Closeable {
    private final int           localPort;
    private final int           targetPort;
    private final KeyManager    keyManager;
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "TorServer-worker");
        t.setDaemon(true);
        return t;
    });
    private ServerSocket               serverSocket;
    private volatile boolean           running = false;
    private TorControlClient           controlClient;
    private TorControlClient.HiddenServiceInfo hiddenService;
    private BiConsumer<String, String> onMessage;
    public TorMessageServer(int localPort, int targetPort, KeyManager keyManager) {
        this.localPort  = localPort;
        this.targetPort = targetPort;
        this.keyManager = keyManager;
    }
    public void setOnMessage(BiConsumer<String, String> callback) {
        this.onMessage = callback;
    }
    public String start() throws IOException {
        serverSocket = new ServerSocket(localPort);
        serverSocket.setSoTimeout(0);
        controlClient = new TorControlClient();
        controlClient.connect();
        hiddenService = controlClient.createHiddenService(localPort, targetPort);
        running = true;
        pool.submit(this::acceptLoop);
        return hiddenService.onionAddress();
    }
    @Override
    public void close() {
        running = false;
        try {
            if (hiddenService != null && controlClient != null && controlClient.isConnected()) {
                controlClient.deleteHiddenService(hiddenService.serviceId());
            }
        } catch (IOException ignored) {}
        try { if (controlClient != null) controlClient.close(); } catch (Exception ignored) {}
        try { if (serverSocket != null && !serverSocket.isClosed()) serverSocket.close(); }
        catch (IOException ignored) {}
        pool.shutdownNow();
    }
    public boolean isRunning() { return running; }
    public int getLocalPort() { return localPort; }
    private void acceptLoop() {
        while (running) {
            try {
                Socket conn = serverSocket.accept();
                pool.submit(() -> handleConnection(conn));
            } catch (SocketException e) {
                if (running) logError("Accept loop interrupted: " + e.getMessage());
                break;
            } catch (IOException e) {
                if (running) logError("Accept error: " + e.getMessage());
            }
        }
    }
    private void handleConnection(Socket conn) {
        try (conn) {
            conn.setSoTimeout(30_000);
            DataInputStream in = new DataInputStream(conn.getInputStream());
            int frameLen = in.readInt();
            if (frameLen <= 0 || frameLen > 10 * 1024 * 1024) {
                logError("Invalid frame length: " + frameLen);
                return;
            }
            byte[] frameBytes = new byte[frameLen];
            in.readFully(frameBytes);
            String json = new String(frameBytes, java.nio.charset.StandardCharsets.UTF_8);
            MessagePacket packet = MessagePacket.fromJson(json);
            SecurityValidator.validatePacket(packet);
            ReceiverService receiver = new ReceiverService(keyManager);
            String decoded;
            String senderKey = null;
            if (packet.getEncryptionMode() == MessagePacket.EncryptionMode.AUTO_X25519) {
                senderKey = packet.getSenderPublicKey();
                byte[] sharedSecret = keyManager.computeSharedSecret(senderKey);
                evmpwst.core.CryptoEngine engine = new evmpwst.core.CryptoEngine(
                    HKDFService.derive(sharedSecret, null, HKDFService.INFO_ENCRYPTION, 32));
                byte[] plain = engine.decrypt(
                    packet.getCiphertextBytes(), packet.getAuthTagBytes(), packet.getNonceBytes());
                decoded = new String(plain, java.nio.charset.StandardCharsets.UTF_8);
            } else {
                decoded = "[MANUAL TOKEN message received — paste token to decrypt]";
                storeRawPacket(packet);
            }
            if (onMessage != null) {
                final String finalDecoded = decoded;
                final String finalKey = senderKey;
                onMessage.accept(finalDecoded, finalKey);
            }
        } catch (SecurityException se) {
            logError("Security rejected incoming message: " + se.getMessage());
        } catch (Exception e) {
            logError("Message handling error: " + e.getMessage());
        }
    }
    private volatile MessagePacket lastManualPacket;
    public MessagePacket getLastManualPacket() { return lastManualPacket; }
    private void storeRawPacket(MessagePacket p) { this.lastManualPacket = p; }
    private void logError(String msg) {
        System.err.println("[TorMessageServer] " + msg);
    }
}
