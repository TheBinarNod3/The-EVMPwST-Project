package evmpwst;
import evmpwst.network.*;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.Date;
public class GuiApp extends JFrame {
    private final KeyManager      keyManager      = new KeyManager();
    private final SenderService   senderService   = new SenderService(keyManager);
    private final ReceiverService receiverService = new ReceiverService(keyManager);
    private TorMessageServer torServer;
    private JRadioButton radioAuto, radioManual;
    private JPanel       modeCardPanel;
    private CardLayout   modeCardLayout;
    private JTextField   txtMyPublicKey, txtPartnerPublicKey;
    private JTextField   txtGeneratedToken, txtIncomingToken;
    private JTextArea    inputArea, outputArea;
    private JLabel       imagePreviewSender, imagePreviewReceiver;
    private JTextField   txtMyOnion;
    private JTextField   txtMyTorPublicKey;
    private JTextArea    torInboxArea;
    private JButton      btnStartReceiver, btnStopReceiver;
    private JLabel       torRecvStatus;
    private JTextField   txtRecipientOnion;
    private JTextField   txtRecipientPublicKey;
    private JSpinner     spinRecipientPort;
    private JTextArea    torSendArea;
    private JButton      btnSendViaTor;
    private JButton      btnSendTokenViaTor;
    private JLabel statusLabel;
    public GuiApp() {
        setTitle("EVMPwST");
        setSize(1150, 900);
        setMinimumSize(new Dimension(900, 720));
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        addWindowListener(new java.awt.event.WindowAdapter() {
            @Override public void windowClosing(java.awt.event.WindowEvent e) { shutdown(); }
        });
        setLocationRelativeTo(null);
        applyNimbus();
        buildUI();
    }
    private void buildUI() {
        setLayout(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane(JTabbedPane.TOP);
        tabs.setFont(new Font("Arial", Font.BOLD, 14));
        tabs.addTab("📁  Offline (File Exchange)", buildOfflineTab());
        tabs.addTab("📡  TOR — Receive",            buildTorReceiveTab());
        tabs.addTab("🚀  TOR — Send",               buildTorSendTab());
        add(tabs, BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);
    }
    private JPanel buildOfflineTab() {
        JPanel root = new JPanel(new BorderLayout(0, 0));
        root.setBorder(new EmptyBorder(8, 8, 8, 8));
        JPanel top = new JPanel(new BorderLayout(5, 5));
        top.add(buildModeSelector(), BorderLayout.NORTH);
        top.add(buildModeCards(),    BorderLayout.CENTER);
        root.add(top, BorderLayout.NORTH);
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            buildSenderPanel(), buildReceiverPanel());
        split.setResizeWeight(0.5);
        root.add(split, BorderLayout.CENTER);
        return root;
    }
    private JPanel buildModeSelector() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        p.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(new Color(80, 80, 160), 2),
            " Encryption Mode ", TitledBorder.LEFT, TitledBorder.TOP,
            new Font("Arial", Font.BOLD, 13), new Color(40, 40, 120)));
        radioAuto   = new JRadioButton("AUTO SECURE MODE  (X25519 + HKDF)", false);
        radioManual = new JRadioButton("MANUAL TOKEN MODE  (Ephemeral Token + HKDF)", true);
        radioAuto.setFont(new Font("Arial", Font.BOLD, 13));
        radioManual.setFont(new Font("Arial", Font.BOLD, 13));
        ButtonGroup bg = new ButtonGroup();
        bg.add(radioAuto);
        bg.add(radioManual);
        radioAuto.addActionListener   (e -> modeCardLayout.show(modeCardPanel, "AUTO"));
        radioManual.addActionListener (e -> modeCardLayout.show(modeCardPanel, "MANUAL"));
        p.add(radioAuto);
        p.add(radioManual);
        return p;
    }
    private JPanel buildModeCards() {
        modeCardLayout = new CardLayout();
        modeCardPanel  = new JPanel(modeCardLayout);
        modeCardPanel.add(buildAutoPanel(),   "AUTO");
        modeCardPanel.add(buildManualPanel(), "MANUAL");
        modeCardLayout.show(modeCardPanel, "MANUAL");
        return modeCardPanel;
    }
    private JPanel buildAutoPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(titledBorder(" X25519 Key Exchange ", new Color(20, 140, 80), new Color(10, 100, 50)));
        GridBagConstraints g = gbc();
        g.gridx=0; g.gridy=0; g.weightx=0;
        p.add(new JLabel("My X25519 Public Key (share this):"), g);
        txtMyPublicKey = monoField(keyManager.getPublicKeyBase64(), false);
        txtMyPublicKey.setBackground(new Color(235, 255, 235));
        g.gridx=1; g.weightx=1; p.add(txtMyPublicKey, g);
        g.gridx=2; g.weightx=0;
        JButton cp = smallBtn("Copy"); cp.addActionListener(e -> copyToClipboard(txtMyPublicKey.getText()));
        p.add(cp, g);
        g.gridx=0; g.gridy=1; g.weightx=0;
        p.add(new JLabel("Partner's X25519 Public Key:"), g);
        txtPartnerPublicKey = monoField("", true);
        g.gridx=1; g.weightx=1; p.add(txtPartnerPublicKey, g);
        return p;
    }
    private JPanel buildManualPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(titledBorder(" Manual Token (Ephemeral Key) ", new Color(180, 100, 20), new Color(140, 70, 10)));
        GridBagConstraints g = gbc();
        g.gridx=0; g.gridy=0; g.weightx=0;
        p.add(new JLabel("Generated Token:"), g);
        txtGeneratedToken = monoField("— encrypt first to generate token —", false);
        txtGeneratedToken.setBackground(new Color(255, 250, 220));
        g.gridx=1; g.weightx=1; p.add(txtGeneratedToken, g);
        JButton cp  = smallBtn("Copy");  cp.addActionListener(e -> copyToClipboard(txtGeneratedToken.getText()));
        JButton sv  = smallBtn("Save"); sv.addActionListener(e -> saveTokenToFile(txtGeneratedToken.getText()));
        g.gridx=2; g.weightx=0; p.add(cp, g);
        g.gridx=3; p.add(sv, g);
        return p;
    }
    private JPanel buildSenderPanel() {
        JPanel p = colored(" Transmitter — Encrypt ", new Color(50, 130, 240), new Color(30, 80, 180));
        inputArea = new JTextArea("Enter secret message here...");
        inputArea.setLineWrap(true); inputArea.setWrapStyleWord(true);
        inputArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        JScrollPane sc = new JScrollPane(inputArea);
        sc.setPreferredSize(new Dimension(400, 120));
        JButton btn = accentBtn("🔒  Encrypt → Export to /out/", new Color(50, 130, 240));
        btn.addActionListener(e -> performEncrypt());
        imagePreviewSender = previewLabel("No image yet");
        JPanel top = new JPanel(new BorderLayout(5, 5));
        top.add(sc, BorderLayout.CENTER);
        top.add(btn, BorderLayout.SOUTH);
        p.add(top, BorderLayout.NORTH);
        p.add(imagePreviewSender, BorderLayout.CENTER);
        return p;
    }
    private JPanel buildReceiverPanel() {
        JPanel p = colored(" Receiver — Decrypt ", new Color(210, 50, 50), new Color(160, 20, 20));
        JPanel tokenPanel = new JPanel(new BorderLayout(5, 5));
        txtIncomingToken = new JTextField();
        txtIncomingToken.setFont(new Font("Monospaced", Font.PLAIN, 12));
        txtIncomingToken.setBorder(BorderFactory.createTitledBorder("Paste Token here (MANUAL mode):"));
        tokenPanel.add(txtIncomingToken, BorderLayout.CENTER);
        JButton btn = accentBtn("📂  Load PNG + Decrypt", new Color(210, 50, 50));
        btn.addActionListener(e -> performDecrypt());
        outputArea = new JTextArea("Decrypted message will appear here...");
        outputArea.setLineWrap(true); outputArea.setWrapStyleWord(true);
        outputArea.setEditable(false);
        outputArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        JScrollPane sc = new JScrollPane(outputArea);
        sc.setPreferredSize(new Dimension(400, 120));
        imagePreviewReceiver = previewLabel("Awaiting image...");
        JPanel top = new JPanel(new BorderLayout(5, 5));
        top.add(tokenPanel, BorderLayout.NORTH);
        top.add(btn,        BorderLayout.CENTER);
        top.add(sc,         BorderLayout.SOUTH);
        p.add(top, BorderLayout.NORTH);
        p.add(imagePreviewReceiver, BorderLayout.CENTER);
        return p;
    }
    private JPanel buildTorReceiveTab() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(new EmptyBorder(12, 12, 12, 12));
        JPanel identity = new JPanel(new GridBagLayout());
        identity.setBorder(titledBorder(" My TOR Identity (share these with sender) ",
            new Color(0, 130, 100), new Color(0, 80, 60)));
        GridBagConstraints g = gbc();
        g.gridx=0; g.gridy=0; g.weightx=0;
        identity.add(bold("My .onion address:"), g);
        txtMyOnion = monoField("— start receiver to get address —", false);
        txtMyOnion.setBackground(new Color(230, 255, 245));
        g.gridx=1; g.weightx=1; identity.add(txtMyOnion, g);
        JButton cpOnion = smallBtn("Copy");
        cpOnion.addActionListener(e -> copyToClipboard(txtMyOnion.getText()));
        g.gridx=2; g.weightx=0; identity.add(cpOnion, g);
        g.gridx=0; g.gridy=1; g.weightx=0;
        identity.add(bold("My X25519 Public Key:"), g);
        txtMyTorPublicKey = monoField(keyManager.getPublicKeyBase64(), false);
        txtMyTorPublicKey.setBackground(new Color(230, 255, 245));
        g.gridx=1; g.weightx=1; identity.add(txtMyTorPublicKey, g);
        JButton cpKey = smallBtn("Copy");
        cpKey.addActionListener(e -> copyToClipboard(txtMyTorPublicKey.getText()));
        g.gridx=2; g.weightx=0; identity.add(cpKey, g);
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 8));
        btnStartReceiver = accentBtn("▶  Start Receiver", new Color(0, 150, 80));
        btnStopReceiver  = accentBtn("⏹  Stop Receiver",  new Color(180, 30, 30));
        btnStopReceiver.setEnabled(false);
        torRecvStatus = new JLabel("  Status: Not running");
        torRecvStatus.setFont(new Font("Arial", Font.BOLD, 13));
        torRecvStatus.setForeground(Color.GRAY);
        btnStartReceiver.addActionListener(e -> startTorReceiver());
        btnStopReceiver.addActionListener(e -> stopTorReceiver());
        controls.add(btnStartReceiver);
        controls.add(btnStopReceiver);
        controls.add(torRecvStatus);
        torInboxArea = new JTextArea("Incoming messages will appear here...\n");
        torInboxArea.setLineWrap(true); torInboxArea.setWrapStyleWord(true);
        torInboxArea.setEditable(false);
        torInboxArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        torInboxArea.setBackground(new Color(248, 255, 252));
        JScrollPane scroll = new JScrollPane(torInboxArea);
        scroll.setBorder(titledBorder(" Inbox ",
            new Color(0, 110, 80), new Color(0, 70, 50)));
        root.add(identity, BorderLayout.NORTH);
        root.add(controls, BorderLayout.CENTER);
        root.add(scroll,   BorderLayout.SOUTH);
        root.setPreferredSize(new Dimension(0, 0));
        scroll.setPreferredSize(new Dimension(300, 450));
        return root;
    }
    private JPanel buildTorSendTab() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(new EmptyBorder(12, 12, 12, 12));
        JPanel recipient = new JPanel(new GridBagLayout());
        recipient.setBorder(titledBorder(" Recipient's TOR Identity ",
            new Color(100, 60, 180), new Color(70, 30, 140)));
        GridBagConstraints g = gbc();
        g.gridx=0; g.gridy=0; g.weightx=0;
        recipient.add(bold("Recipient .onion address:"), g);
        txtRecipientOnion = monoField("e.g. abcdef1234567890.onion", true);
        g.gridx=1; g.weightx=1; recipient.add(txtRecipientOnion, g);
        g.gridx=0; g.gridy=1; g.weightx=0;
        recipient.add(bold("Recipient X25519 Public Key:"), g);
        txtRecipientPublicKey = monoField("Paste their public key here", true);
        g.gridx=1; g.weightx=1; recipient.add(txtRecipientPublicKey, g);
        g.gridx=0; g.gridy=2; g.weightx=0;
        recipient.add(bold("Recipient port:"), g);
        spinRecipientPort = new JSpinner(new SpinnerNumberModel(8765, 1024, 65535, 1));
        spinRecipientPort.setFont(new Font("Monospaced", Font.PLAIN, 12));
        g.gridx=1; g.weightx=0; g.fill=GridBagConstraints.NONE;
        recipient.add(spinRecipientPort, g);
        g.fill=GridBagConstraints.HORIZONTAL;
        torSendArea = new JTextArea("Type your confidential message here...");
        torSendArea.setLineWrap(true); torSendArea.setWrapStyleWord(true);
        torSendArea.setFont(new Font("Monospaced", Font.PLAIN, 14));
        JScrollPane scroll = new JScrollPane(torSendArea);
        scroll.setBorder(titledBorder(" Send ",
            new Color(100, 60, 180), new Color(70, 30, 140)));
        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 8));
        btnSendTokenViaTor = accentBtn("🔑 Send Token (.txt)", new Color(200, 100, 0));
        btnSendTokenViaTor.setFont(new Font("Arial", Font.BOLD, 15));
        btnSendTokenViaTor.setPreferredSize(new Dimension(200, 46));
        btnSendTokenViaTor.addActionListener(e -> performSendTokenViaTor());
        bottom.add(btnSendTokenViaTor);
        btnSendViaTor = accentBtn("🚀  Send via TOR  (AUTO SECURE)", new Color(100, 60, 180));
        btnSendViaTor.setFont(new Font("Arial", Font.BOLD, 15));
        btnSendViaTor.setPreferredSize(new Dimension(320, 46));
        btnSendViaTor.addActionListener(e -> performSendViaTor());
        bottom.add(btnSendViaTor);
        JPanel center = new JPanel(new BorderLayout(5, 5));
        center.add(scroll, BorderLayout.CENTER);
        center.add(bottom, BorderLayout.SOUTH);
        root.add(recipient, BorderLayout.NORTH);
        root.add(center,    BorderLayout.CENTER);
        return root;
    }
    private JPanel buildStatusBar() {
        statusLabel = new JLabel(" Ready. Choose a tab.");
        statusLabel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.LIGHT_GRAY));
        statusLabel.setOpaque(true);
        statusLabel.setBackground(new Color(240, 240, 240));
        statusLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        JPanel bar = new JPanel(new BorderLayout());
        bar.add(statusLabel, BorderLayout.CENTER);
        return bar;
    }
    private void performEncrypt() {
        String text = inputArea.getText().strip();
        if (text.isEmpty()) { warn("Message cannot be empty."); return; }
        try {
            File outDir = new File("out");
            outDir.mkdirs();
            String sig = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            if (radioAuto.isSelected()) {
                String partnerKey = txtPartnerPublicKey.getText().strip();
                if (partnerKey.isEmpty()) { warn("AUTO mode requires partner's public key."); return; }
                byte[] shared  = keyManager.computeSharedSecret(partnerKey);
                byte[] frame   = buildFrame(text.getBytes(StandardCharsets.UTF_8), shared);
                byte[] imgKey  = HKDFService.derive(shared, null, "evmpwst-img-v1", 32);
                BufferedImage img = encodeToImage(frame, imgKey);
                File pngFile = new File(outDir, "auto_" + sig + ".png");
                ImageIO.write(img, "png", pngFile);
                updatePreview(imagePreviewSender, img);
                setStatus("AUTO encrypt → " + pngFile.getName());
                JOptionPane.showMessageDialog(this,
                    "Saved: " + pngFile.getAbsolutePath() +
                    "\n\nRecipient needs your public key:\n" + keyManager.getPublicKeyBase64(),
                    "Encrypted", JOptionPane.INFORMATION_MESSAGE);
            } else {
                SenderService.OfflineResult result = senderService.encryptOffline(text.getBytes(StandardCharsets.UTF_8));
                File pngFile = new File(outDir, "manual_" + sig + ".png");
                File txtFile = new File(outDir, "manual_" + sig + ".txt");
                Files.write(pngFile.toPath(), result.pngBytes());
                Files.writeString(txtFile.toPath(), result.tokenBase64());
                txtGeneratedToken.setText(result.tokenBase64());
                BufferedImage img = ImageIO.read(pngFile);
                updatePreview(imagePreviewSender, img);
                setStatus("MANUAL encrypt → " + pngFile.getName());
                JOptionPane.showMessageDialog(this,
                    "Saved in: " + outDir.getAbsolutePath() +
                    "\n  Image: " + pngFile.getName() +
                    "\n  Token: " + txtFile.getName() +
                    "\n\nShare BOTH files with recipient.",
                    "Encrypted", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception ex) {
            error("Encryption failed: " + ex.getMessage());
        }
    }
    private void performDecrypt() {
        JFileChooser chooser = new JFileChooser(new File("out"));
        chooser.setDialogTitle("Select encrypted PNG");
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        File pngFile = chooser.getSelectedFile();
        try {
            byte[] pngBytes = Files.readAllBytes(pngFile.toPath());
            BufferedImage img = ImageIO.read(pngFile);
            if (img != null) updatePreview(imagePreviewReceiver, img);
            ReceiverService.DecryptResult result;
            if (radioAuto.isSelected()) {
                String partnerKey = txtPartnerPublicKey.getText().strip();
                if (partnerKey.isEmpty()) { warn("AUTO mode requires sender's public key."); return; }
                result = receiverService.decryptOfflineAuto(pngBytes, partnerKey);
            } else {
                String token = txtIncomingToken.getText().strip();
                if (token.isEmpty()) { warn("Paste the token first."); return; }
                result = receiverService.decryptOffline(pngBytes, token);
            }
            outputArea.setText("=== DECRYPTED [" + result.patternName() + "] ===\n\n" + result.asString());
            setStatus("Decryption OK — " + pngFile.getName());
        } catch (SecurityException se) {
            outputArea.setText("");
            error("Security validation failed: " + se.getMessage());
        } catch (Exception ex) {
            outputArea.setText("");
            error("Decryption error: " + ex.getMessage());
        }
    }
    private void startTorReceiver() {
        btnStartReceiver.setEnabled(false);
        torRecvStatus.setForeground(new Color(200, 120, 0));
        torRecvStatus.setText("  Status: Connecting to Tor control port...");
        setStatus("Starting TOR receiver...");
        SwingWorker<String, Void> worker = new SwingWorker<>() {
            @Override protected String doInBackground() throws Exception {
                torServer = new TorMessageServer(findFreePort(), 8765, keyManager);
                torServer.setOnMessage((msg, senderKey) ->
                    SwingUtilities.invokeLater(() -> appendToInbox(msg, senderKey)));
                return torServer.start();
            }
            @Override protected void done() {
                try {
                    String onion = get();
                    txtMyOnion.setText(onion);
                    btnStartReceiver.setEnabled(false);
                    btnStopReceiver.setEnabled(true);
                    torRecvStatus.setForeground(new Color(0, 130, 60));
                    torRecvStatus.setText("  Status: ✅ Listening on " + onion);
                    setStatus("TOR receiver active — " + onion);
                    JOptionPane.showMessageDialog(GuiApp.this,
                        "TOR Receiver is LIVE!\n\n" +
                        "Your .onion address:\n" + onion + "\n\n" +
                        "Your X25519 public key:\n" + keyManager.getPublicKeyBase64() +
                        "\n\nShare BOTH values with whoever wants to send you a message.",
                        "Receiver Started", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    btnStartReceiver.setEnabled(true);
                    torRecvStatus.setForeground(Color.RED);
                    torRecvStatus.setText("  Status: ❌ Failed");
                    error("Failed to start TOR receiver:\n" + ex.getMessage() +
                          "\n\nMake sure Tor Browser is running and connected.");
                }
            }
        };
        worker.execute();
    }
    private void stopTorReceiver() {
        if (torServer != null) {
            torServer.close();
            torServer = null;
        }
        txtMyOnion.setText("— start receiver to get address —");
        btnStartReceiver.setEnabled(true);
        btnStopReceiver.setEnabled(false);
        torRecvStatus.setForeground(Color.GRAY);
        torRecvStatus.setText("  Status: Stopped");
        setStatus("TOR receiver stopped.");
    }
    private void appendToInbox(String message, String senderKey) {
        String ts = new SimpleDateFormat("HH:mm:ss").format(new Date());
        String from = senderKey != null ? senderKey.substring(0, 12) + "..." : "MANUAL-TOKEN";
        torInboxArea.append("\n─────────────────────────────\n");
        torInboxArea.append("[" + ts + "] From: " + from + "\n");
        torInboxArea.append(message + "\n");
        torInboxArea.setCaretPosition(torInboxArea.getDocument().getLength());
        setStatus("New message received at " + ts);
    }
    private void performSendTokenViaTor() {
        JFileChooser chooser = new JFileChooser(new File("out"));
        chooser.setDialogTitle("Select token .txt file to share");
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            String token = Files.readString(chooser.getSelectedFile().toPath()).strip();
            if (token.isEmpty()) { warn("Selected token file is empty."); return; }
            String message = "[SYSTEM] Sender shared a decryption token:\n" + token;
            executeTorSendTask(message, btnSendTokenViaTor);
        } catch (Exception e) {
            error("Could not read token file: " + e.getMessage());
        }
    }
    private void performSendViaTor() {
        String message = torSendArea.getText().strip();
        if (message.isEmpty())  { warn("Message cannot be empty."); return; }
        executeTorSendTask(message, btnSendViaTor);
    }
    private void executeTorSendTask(String message, JButton sourceBtn) {
        String onion      = txtRecipientOnion.getText().strip();
        String recipKey   = txtRecipientPublicKey.getText().strip();
        if (onion.isEmpty())    { warn("Enter recipient's .onion address."); return; }
        if (recipKey.isEmpty()) { warn("Enter recipient's X25519 public key."); return; }
        if (!onion.endsWith(".onion")) {
            warn("Invalid .onion address — must end with '.onion'");
            return;
        }
        sourceBtn.setEnabled(false);
        setStatus("Connecting via TOR...");
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override protected Void doInBackground() throws Exception {
                int port = (int) spinRecipientPort.getValue();
                try (TorTransportClient transport = new TorTransportClient()) {
                    transport.connect(onion, port);
                    senderService.sendAuto(message.getBytes(StandardCharsets.UTF_8), recipKey, transport);
                }
                return null;
            }
            @Override protected void done() {
                sourceBtn.setEnabled(true);
                try {
                    get();
                    setStatus("Message sent via TOR ✅");
                    JOptionPane.showMessageDialog(GuiApp.this,
                        "Message delivered via TOR!\nRecipient's inbox received it.",
                        "Sent", JOptionPane.INFORMATION_MESSAGE);
                    if (sourceBtn == btnSendViaTor) torSendArea.setText("");
                } catch (Exception ex) {
                    error("TOR send failed:\n" + ex.getMessage() +
                          "\n\nCheck:\n• Recipient's .onion address is correct\n" +
                          "• Recipient has started their Receiver\n• Tor Browser is running");
                }
            }
        };
        worker.execute();
    }
    private byte[] buildFrame(byte[] plaintext, byte[] sharedSecret) {
        byte[] encKey = HKDFService.derive(sharedSecret, null, HKDFService.INFO_ENCRYPTION, 32);
        evmpwst.core.CryptoEngine engine = new evmpwst.core.CryptoEngine(encKey);
        byte[] nonce = engine.generateNonce();
        byte[][] parts = engine.encrypt(plaintext, nonce);
        return SenderService.packFrame(nonce, parts[1], parts[0]);
    }
    private BufferedImage encodeToImage(byte[] frame, byte[] imgKey) throws IOException {
        evmpwst.core.CryptoEngine imgEngine = new evmpwst.core.CryptoEngine(imgKey);
        return evmpwst.core.Encoder.encode(frame, evmpwst.protocol.PatternType.TEXT_MESSAGE, imgEngine);
    }
    private static int findFreePort() throws IOException {
        try (java.net.ServerSocket s = new java.net.ServerSocket(0)) {
            return s.getLocalPort();
        }
    }
    private void updatePreview(JLabel label, BufferedImage img) {
        label.setText("");
        label.setIcon(new ImageIcon(img.getScaledInstance(270, 270, Image.SCALE_SMOOTH)));
    }
    private void copyToClipboard(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        setStatus("Copied to clipboard.");
    }
    private void saveTokenToFile(String token) {
        if (token.startsWith("—")) { warn("No token generated yet."); return; }
        JFileChooser fc = new JFileChooser(new File("out"));
        fc.setSelectedFile(new File("token.txt"));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            try { Files.writeString(fc.getSelectedFile().toPath(), token);
                  setStatus("Token saved."); }
            catch (IOException e) { error("Save failed: " + e.getMessage()); }
        }
    }
    private void setStatus(String msg) {
        statusLabel.setText(" " + msg);
        statusLabel.setForeground(new Color(30, 100, 30));
    }
    private void warn(String msg)  { JOptionPane.showMessageDialog(this, msg, "Warning", JOptionPane.WARNING_MESSAGE); }
    private void error(String msg) { JOptionPane.showMessageDialog(this, msg, "Error",   JOptionPane.ERROR_MESSAGE); }
    private void shutdown() {
        if (torServer != null) torServer.close();
        dispose();
        System.exit(0);
    }
    private static JPanel colored(String title, Color border, Color text) {
        JPanel p = new JPanel(new BorderLayout(5, 5));
        p.setBorder(titledBorder(title, border, text));
        return p;
    }
    private static TitledBorder titledBorder(String title, Color border, Color text) {
        return BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(border, 2), title,
            TitledBorder.LEFT, TitledBorder.TOP,
            new Font("Arial", Font.BOLD, 13), text);
    }
    private static GridBagConstraints gbc() {
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 6, 4, 6);
        g.fill   = GridBagConstraints.HORIZONTAL;
        return g;
    }
    private static JTextField monoField(String text, boolean editable) {
        JTextField f = new JTextField(text);
        f.setEditable(editable);
        f.setFont(new Font("Monospaced", Font.PLAIN, 11));
        return f;
    }
    private static JButton smallBtn(String text) {
        JButton b = new JButton(text);
        b.setFont(new Font("Arial", Font.PLAIN, 11));
        return b;
    }
    private static JButton accentBtn(String text, Color bg) {
        JButton b = new JButton(text);
        b.setBackground(bg);
        b.setForeground(Color.WHITE);
        b.setFont(new Font("Arial", Font.BOLD, 13));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.setOpaque(true);
        b.setBorderPainted(false);
        return b;
    }
    private static JLabel bold(String text) {
        JLabel l = new JLabel(text);
        l.setFont(new Font("Arial", Font.BOLD, 12));
        return l;
    }
    private static JLabel previewLabel(String text) {
        JLabel l = new JLabel(text, SwingConstants.CENTER);
        l.setPreferredSize(new Dimension(400, 260));
        l.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        return l;
    }
    private static void applyNimbus() {
        try {
            for (UIManager.LookAndFeelInfo i : UIManager.getInstalledLookAndFeels())
                if ("Nimbus".equals(i.getName())) { UIManager.setLookAndFeel(i.getClassName()); break; }
        } catch (Exception ignored) {}
    }
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new GuiApp().setVisible(true));
    }
}
