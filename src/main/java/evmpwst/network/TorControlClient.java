package evmpwst.network;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
public final class TorControlClient implements Closeable {
    private static final String CTRL_HOST = "127.0.0.1";
    private static final int    CTRL_PORT = 9151;
    private Socket socket;
    private BufferedReader reader;
    private PrintWriter    writer;
    public void connect() throws IOException {
        socket = new Socket(CTRL_HOST, CTRL_PORT);
        socket.setSoTimeout(15_000);
        reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
        writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII), true);
        sendCommand("PROTOCOLINFO 1");
        String protoReply = readReply();
        String cookiePath = null;
        for (String line : protoReply.split("\n")) {
            if (line.contains("COOKIEFILE=\"")) {
                int start = line.indexOf("COOKIEFILE=\"") + 12;
                int end = line.indexOf("\"", start);
                if (end > start) {
                    cookiePath = line.substring(start, end);
                }
            }
        }
        boolean authenticated = false;
        if (cookiePath != null) {
            try {
                byte[] cookie = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(cookiePath));
                StringBuilder hex = new StringBuilder();
                for (byte b : cookie) {
                    hex.append(String.format("%02X", b));
                }
                sendCommand("AUTHENTICATE " + hex.toString());
                String attempt = readReply();
                if (attempt.startsWith("250")) authenticated = true;
            } catch (Exception ignored) {
            }
        }
        if (!authenticated) {
            sendCommand("AUTHENTICATE \"\"");
            String authReply = readReply();
            if (!authReply.startsWith("250")) {
                throw new IOException("Tor control auth failed. Ensure Tor Browser is running. Reply: " + authReply);
            }
        }
    }
    public HiddenServiceInfo createHiddenService(int localPort, int targetPort) throws IOException {
        String cmd = "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=" + targetPort + ",127.0.0.1:" + localPort;
        sendCommand(cmd);
        String serviceId = null;
        String line;
        StringBuilder fullReply = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            fullReply.append(line).append('\n');
            if (line.startsWith("250-ServiceID=")) {
                serviceId = line.substring("250-ServiceID=".length()).trim();
            }
            if (line.equals("250 OK") || (line.startsWith("5") && line.length() >= 3)) break;
        }
        if (serviceId == null) {
            throw new IOException("ADD_ONION failed — no ServiceID in reply:\n" + fullReply);
        }
        return new HiddenServiceInfo(serviceId, serviceId + ".onion", localPort, targetPort);
    }
    public void deleteHiddenService(String serviceId) throws IOException {
        sendCommand("DEL_ONION " + serviceId);
        readReply();
    }
    @Override
    public void close() {
        try { if (socket != null && !socket.isClosed()) socket.close(); }
        catch (IOException ignored) {}
    }
    public boolean isConnected() {
        return socket != null && socket.isConnected() && !socket.isClosed();
    }
    private void sendCommand(String cmd) {
        writer.println(cmd);
    }
    private String readReply() throws IOException {
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append('\n');
            if (line.startsWith("250 ") || line.startsWith("5") || line.startsWith("4")) break;
        }
        return sb.toString().trim();
    }
    public record HiddenServiceInfo(
        String serviceId,
        String onionAddress,
        int    localPort,
        int    targetPort
    ) {}
}
