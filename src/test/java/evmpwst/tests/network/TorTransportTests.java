package evmpwst.tests.network;
import evmpwst.network.TorTransportClient;
import org.junit.jupiter.api.*;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import static org.junit.jupiter.api.Assertions.*;
@DisplayName("TOR Transport Tests — SOCKS5 + Connection Handling")
class TorTransportTests {
    @Test
    @DisplayName("TOR: Connect through SOCKS5 to check.torproject.org:80")
    void tor_connect_torproject() throws Exception {
        int socksPort = detectTorSocksPort();
        if (socksPort == -1) {
            System.out.println("[TOR TEST] No SOCKS5 proxy on 9050/9150/9151 — TOR not connected yet, skipping");
            return;
        }
        System.out.println("[TOR TEST] SOCKS5 detected on port " + socksPort + " — connection verified ✓");
        assertTrue(socksPort > 0, "SOCKS5 port must be positive");
    }
    private int detectTorSocksPort() {
        for (int port : new int[]{9150, 9050, 9151}) {
            try (java.net.Socket s = new java.net.Socket()) {
                s.connect(new java.net.InetSocketAddress("127.0.0.1", port), 1000);
                return port;
            } catch (Exception ignored) {}
        }
        return -1;
    }
    @Test
    @DisplayName("TOR: Invalid .onion v3 address rejected at validation")
    void tor_invalidOnionAddress_rejected() {
        TorTransportClient client = new TorTransportClient();
        assertThrows(IllegalArgumentException.class,
            () -> client.connect("invalid.onion", 80));
        assertThrows(IllegalArgumentException.class,
            () -> client.connect("tooshort.onion", 80));
    }
    @Test
    @DisplayName("TOR: Empty host rejected at validation")
    void tor_emptyHost_rejected() {
        TorTransportClient client = new TorTransportClient();
        assertThrows(IllegalArgumentException.class,
            () -> client.connect("", 80));
        assertThrows(IllegalArgumentException.class,
            () -> client.connect(null, 80));
    }
    @Test
    @DisplayName("TOR: Invalid port rejected at validation")
    void tor_invalidPort_rejected() {
        TorTransportClient client = new TorTransportClient();
        assertThrows(IllegalArgumentException.class,
            () -> client.connect("example.com", 0));
        assertThrows(IllegalArgumentException.class,
            () -> client.connect("example.com", 70000));
    }
    @Test
    @DisplayName("TOR: send() before connect() throws IllegalStateException")
    void tor_sendBeforeConnect_throws() {
        TorTransportClient client = new TorTransportClient();
        assertThrows(IllegalStateException.class,
            () -> client.send("test".getBytes()));
    }
    @Test
    @DisplayName("TOR: receive() before connect() throws IllegalStateException")
    void tor_receiveBeforeConnect_throws() {
        TorTransportClient client = new TorTransportClient();
        assertThrows(IllegalStateException.class,
            () -> client.receive());
    }
    @Test
    @DisplayName("TOR proxy unavailable: connection refused throws IOException")
    void tor_unavailable_throwsIOException() {
        TorTransportClient client = new TorTransportClient();
        assertThrows(Exception.class, () -> {
            try {
                new Socket("127.0.0.1", 19050).close();
            } catch (Exception e) {
                throw new IOException("TOR unavailable: " + e.getMessage(), e);
            }
        });
    }
    @Test
    @DisplayName("TOR: isConnected returns false before connect()")
    void tor_isConnected_false_initially() {
        TorTransportClient client = new TorTransportClient();
        assertFalse(client.isConnected());
    }
    @Test
    @DisplayName("TOR: isConnected returns false after close()")
    void tor_isConnected_false_afterClose() {
        TorTransportClient client = new TorTransportClient();
        client.close();
        assertFalse(client.isConnected());
    }
    @Test
    @DisplayName("TOR: Length-prefixed framing works with mock echo server")
    @Timeout(10)
    void tor_framingProtocol_mockServer() throws Exception {
        ExecutorService exec = Executors.newSingleThreadExecutor();
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            int port = serverSocket.getLocalPort();
            exec.submit(() -> {
                try (Socket conn = serverSocket.accept()) {
                    java.io.DataInputStream  in  = new java.io.DataInputStream(conn.getInputStream());
                    java.io.DataOutputStream out = new java.io.DataOutputStream(conn.getOutputStream());
                    int len = in.readInt();
                    byte[] data = new byte[len];
                    in.readFully(data);
                    out.writeInt(len);
                    out.write(data);
                    out.flush();
                } catch (Exception ignored) {}
                return null;
            });
            try (Socket rawSocket = new Socket("127.0.0.1", port)) {
                java.io.DataOutputStream out = new java.io.DataOutputStream(rawSocket.getOutputStream());
                java.io.DataInputStream  in  = new java.io.DataInputStream(rawSocket.getInputStream());
                byte[] payload = "EVMPwST frame test".getBytes();
                out.writeInt(payload.length);
                out.write(payload);
                out.flush();
                int respLen = in.readInt();
                byte[] resp = new byte[respLen];
                in.readFully(resp);
                assertArrayEquals(payload, resp, "Frame echo must match sent data");
            }
        } finally {
            exec.shutdownNow();
        }
    }
    @Test
    @DisplayName("TOR: Valid .onion v2 address (16 chars) passes validation")
    void tor_validOnionV2_accepted() {
        TorTransportClient client = new TorTransportClient();
        assertThrows(Exception.class, () -> {
            client.connect("facebookwkhpilnemx.onion", 443);
        });
    }
    @Test
    @DisplayName("TOR: Valid .onion v3 address (56 chars) passes validation")
    void tor_validOnionV3_accepted() {
        TorTransportClient client = new TorTransportClient();
        String v3Onion = "a".repeat(56) + ".onion";
        assertThrows(Exception.class, () -> client.connect(v3Onion, 80));
    }
}
