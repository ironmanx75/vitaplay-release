import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A stand-in iPhone for testing VitaPlay without a phone or the Bluetooth bootstrap.
 *
 * It plays the phone's side of the wireless CarPlay AirPlay session with only JDK crypto:
 * pair-setup (SRP-6a, PIN 3939), pair-verify, auth-setup, /info, SETUP, an encrypted H.264
 * screen stream, and the event channel that carries touch reports back.
 *
 *   java tools/FakePhone.java <vita-ip> [mfi-public-key.der]
 *   java tools/FakePhone.java --gen-test-mfi <dir>   (test identity for host runs only)
 */
public class FakePhone {
    static final SecureRandom RANDOM = new SecureRandom();
    static int failures = 0;

    public static void main(String[] args) throws Exception {
        if (args.length >= 2 && args[0].equals("--gen-test-mfi")) {
            genTestMfi(new File(args[1]));
            return;
        }
        List<String> positional = new ArrayList<>();
        FakePhone phone = new FakePhone();
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--relay-port") && i + 1 < args.length) phone.relayPort = Integer.parseInt(args[++i]);
            else positional.add(args[i]);
        }
        if (positional.isEmpty()) {
            System.out.println("usage: java tools/FakePhone.java <vita-ip[:port]> [mfi-public-key.der] [--relay-port N]");
            System.exit(2);
        }
        PublicKey mfiKey = positional.size() > 1
            ? KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(new File(positional.get(1)).toPath())))
            : null;
        phone.run(positional.get(0), mfiKey);
        System.out.println(failures == 0 ? "\nALL CHECKS PASSED" : "\n" + failures + " CHECK(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    static void check(boolean ok, String what) {
        System.out.println((ok ? "  PASS  " : "  FAIL  ") + what);
        if (!ok) failures++;
    }

    /** Writes a P-256 PKCS#8 key and, in place of a real certificate, its public key. */
    static void genTestMfi(File dir) throws Exception {
        dir.mkdirs();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        Files.write(new File(dir, "identity.pk8").toPath(), pair.getPrivate().getEncoded());
        Files.write(new File(dir, "certificate.p7b").toPath(), pair.getPublic().getEncoded());
        System.out.println("test MFi identity written to " + dir);
    }

    // ---- session ----

    /** When set, also act as PlayPort's iAP2 relay end and test the Vita's tunnel relay. */
    int relayPort = 0;
    Socket control;
    InputStream in;
    OutputStream out;
    int cseq = 0;
    byte[] controlWriteKey, controlReadKey;
    long writeCounter, readCounter;
    ByteArrayOutputStream plainBuffer = new ByteArrayOutputStream();
    byte[] shared;

    void run(String target, PublicKey mfiKey) throws Exception {
        String host = target.contains(":") ? target.substring(0, target.lastIndexOf(':')) : target;
        int port = target.contains(":") ? Integer.parseInt(target.substring(target.lastIndexOf(':') + 1)) : 7000;
        control = new Socket(host, port);
        control.setTcpNoDelay(true);
        in = control.getInputStream();
        out = control.getOutputStream();
        System.out.println("connected to " + host + ":" + port);

        // pair-setup
        System.out.println("pair-setup (the Vita computes a 3072-bit SRP verifier; this can take a few seconds)");
        Map<Integer, byte[]> m2 = Tlv.decode(request("POST", "/pair-setup", "application/pairing+tlv8",
            Tlv.encode(6, new byte[] {1}, 0, new byte[] {0})).body);
        check(m2.get(6) != null && m2.get(6)[0] == 2 && m2.get(3) != null && m2.get(2) != null, "pair-setup M2 has B and salt");
        byte[] salt = m2.get(2);
        BigInteger bigB = new BigInteger(1, m2.get(3));
        Srp srp = new Srp(salt, bigB);
        Map<Integer, byte[]> m4 = Tlv.decode(request("POST", "/pair-setup", "application/pairing+tlv8",
            Tlv.encode(6, new byte[] {3}, 3, Srp.pad(srp.bigA), 4, srp.m1)).body);
        check(m4.get(4) != null && Arrays.equals(m4.get(4), srp.expectedM2), "pair-setup M4 server proof matches SRP");

        KeyPair controllerKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] controllerLtpk = rawEd25519(controllerKey.getPublic());
        byte[] controllerId = "FakePhone-0001".getBytes(StandardCharsets.UTF_8);
        byte[] setupKey = hkdf(srp.key, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info");
        byte[] signKey = hkdf(srp.key, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info");
        byte[] signature = sign(controllerKey, concat(signKey, controllerId, controllerLtpk));
        byte[] sub = Tlv.encode(1, controllerId, 3, controllerLtpk, 10, signature);
        Map<Integer, byte[]> m6 = Tlv.decode(request("POST", "/pair-setup", "application/pairing+tlv8",
            Tlv.encode(6, new byte[] {5}, 5, chacha(true, setupKey, label("PS-Msg05"), sub, new byte[0]))).body);
        check(m6.get(5) != null, "pair-setup M6 has encrypted data");
        Map<Integer, byte[]> accessory = Tlv.decode(chacha(false, setupKey, label("PS-Msg06"), m6.get(5), new byte[0]));
        byte[] accessoryId = accessory.get(1), accessoryLtpk = accessory.get(3);
        byte[] accessorySignKey = hkdf(srp.key, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info");
        check(verifyEd25519(accessoryLtpk, concat(accessorySignKey, accessoryId, accessoryLtpk), accessory.get(10)),
            "pair-setup accessory signature valid (id " + new String(accessoryId, StandardCharsets.UTF_8) + ")");

        // pair-verify
        KeyPair ephemeral = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        byte[] ownEph = rawX25519(ephemeral.getPublic());
        Map<Integer, byte[]> v2 = Tlv.decode(request("POST", "/pair-verify", "application/pairing+tlv8",
            Tlv.encode(6, new byte[] {1}, 3, ownEph)).body);
        byte[] accessoryEph = v2.get(3);
        KeyAgreement agreement = KeyAgreement.getInstance("XDH");
        agreement.init(ephemeral.getPrivate());
        agreement.doPhase(x25519Public(accessoryEph), true);
        shared = agreement.generateSecret();
        byte[] verifyKey = hkdf(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info");
        Map<Integer, byte[]> v2sub = Tlv.decode(chacha(false, verifyKey, label("PV-Msg02"), v2.get(5), new byte[0]));
        check(Arrays.equals(v2sub.get(1), accessoryId)
                && verifyEd25519(accessoryLtpk, concat(accessoryEph, accessoryId, ownEph), v2sub.get(10)),
            "pair-verify M2 accessory signature valid");
        byte[] v3sig = sign(controllerKey, concat(ownEph, controllerId, accessoryEph));
        Map<Integer, byte[]> v4 = Tlv.decode(request("POST", "/pair-verify", "application/pairing+tlv8",
            Tlv.encode(6, new byte[] {3}, 5,
                chacha(true, verifyKey, label("PV-Msg03"), Tlv.encode(1, controllerId, 10, v3sig), new byte[0]))).body);
        check(v4.get(6) != null && v4.get(6)[0] == 4 && v4.get(7) == null, "pair-verify M4 accepted");

        controlWriteKey = hkdf(shared, "Control-Salt", "Control-Write-Encryption-Key");
        controlReadKey = hkdf(shared, "Control-Salt", "Control-Read-Encryption-Key");

        // auth-setup over the encrypted channel
        KeyPair authEph = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        byte[] authPk = rawX25519(authEph.getPublic());
        Response auth = request("POST", "/auth-setup", "application/octet-stream", concat(new byte[] {1}, authPk));
        if (auth.status != 200) {
            check(false, "auth-setup returned " + auth.status + " (is the MFi identity in place?)");
        } else {
            byte[] body = auth.body;
            byte[] accessoryAuthPk = Arrays.copyOfRange(body, 0, 32);
            int certLen = u32be(body, 32);
            byte[] cert = Arrays.copyOfRange(body, 36, 36 + certLen);
            int sigLen = u32be(body, 36 + certLen);
            byte[] encryptedSig = Arrays.copyOfRange(body, 40 + certLen, 40 + certLen + sigLen);
            KeyAgreement authAgreement = KeyAgreement.getInstance("XDH");
            authAgreement.init(authEph.getPrivate());
            authAgreement.doPhase(x25519Public(accessoryAuthPk), true);
            byte[] authShared = authAgreement.generateSecret();
            byte[] aesKey = Arrays.copyOf(sha("SHA-1", "AES-KEY".getBytes(), authShared), 16);
            byte[] aesIv = Arrays.copyOf(sha("SHA-1", "AES-IV".getBytes(), authShared), 16);
            Cipher ctr = Cipher.getInstance("AES/CTR/NoPadding");
            ctr.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(aesIv));
            byte[] rawSig = ctr.doFinal(encryptedSig);
            check(certLen > 0 && sigLen == 64, "auth-setup returned certificate (" + certLen + " bytes) and 64-byte signature");
            if (mfiKey != null) {
                Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
                verifier.initVerify(mfiKey);
                verifier.update(concat(accessoryAuthPk, authPk));
                check(verifier.verify(rawSig), "auth-setup ECDSA signature verifies with the MFi public key");
            }
        }

        // /info
        Response info = request("GET", "/info", null, new byte[0]);
        Object infoPlist = Bplist.decode(info.body);
        Map<?, ?> infoMap = infoPlist instanceof Map ? (Map<?, ?>) infoPlist : Map.of();
        List<?> displays = (List<?>) infoMap.get("displays");
        Map<?, ?> display = displays != null && !displays.isEmpty() ? (Map<?, ?>) displays.get(0) : Map.of();
        check(info.status == 200 && "VitaPlay".equals(infoMap.get("name")), "/info decodes (name=" + infoMap.get("name") + ")");
        check(Long.valueOf(960).equals(display.get("widthPixels")) && Long.valueOf(544).equals(display.get("heightPixels")),
            "/info display is 960x544");
        List<?> hid = (List<?>) infoMap.get("hidDevices");
        check(hid != null && hid.size() == 4, "/info lists 4 HID devices");

        // session SETUP
        DatagramSocket timing = new DatagramSocket(0);
        timing.setSoTimeout(3000);
        Map<String, Object> setup = new LinkedHashMap<>();
        setup.put("name", "FakePhone");
        setup.put("deviceID", "AA:BB:CC:DD:EE:FF");
        setup.put("model", "iPhone17,1");
        setup.put("osVersion", "26.1");
        setup.put("timingPort", (long) timing.getLocalPort());
        setup.put("keepAliveLowPower", true);
        Map<?, ?> setupResponse = (Map<?, ?>) Bplist.decode(request("SETUP", "rtsp://vita/1", "application/x-apple-binary-plist",
            Bplist.encode(setup)).body);
        Long eventPort = (Long) setupResponse.get("eventPort");
        check(eventPort != null && setupResponse.get("timingPort") != null, "SETUP returns eventPort " + eventPort
            + " and timingPort " + setupResponse.get("timingPort"));
        check(setupResponse.get("keepAlivePort") != null, "SETUP opened keepAlivePort");

        byte[] ntp = new byte[64];
        DatagramPacket ntpPacket = new DatagramPacket(ntp, ntp.length);
        try {
            timing.receive(ntpPacket);
            check(ntpPacket.getLength() == 32 && (ntp[1] & 0xff) == 210, "timing request received from the Vita");
        } catch (java.net.SocketTimeoutException e) {
            check(false, "timing request received from the Vita");
        }

        Socket event = new Socket(host, eventPort.intValue());
        byte[] eventReadKey = hkdf(shared, "Events-Salt", "Events-Write-Encryption-Key");

        // stream SETUP: main screen, with a streamConnectionID above 2^63 to exercise unsigned ints
        long connectionId = 0xF000000000000123L;
        Map<String, Object> screen = new LinkedHashMap<>();
        screen.put("type", 110L);
        screen.put("streamConnectionID", new BigInteger(Long.toUnsignedString(connectionId)));
        Map<String, Object> streamsSetup = new LinkedHashMap<>();
        streamsSetup.put("streams", List.of(screen));
        Map<?, ?> streamsResponse = (Map<?, ?>) Bplist.decode(request("SETUP", "rtsp://vita/1",
            "application/x-apple-binary-plist", Bplist.encode(streamsSetup)).body);
        List<?> streams = (List<?>) streamsResponse.get("streams");
        Long dataPort = streams != null && !streams.isEmpty() ? (Long) ((Map<?, ?>) streams.get(0)).get("dataPort") : null;
        check(dataPort != null, "screen stream SETUP returns dataPort " + dataPort);
        request("RECORD", "rtsp://vita/1", null, new byte[0]);

        // screen stream: VideoConfig then two encrypted frames
        byte[] screenKey = hkdf(shared, "DataStream-Salt" + Long.toUnsignedString(connectionId),
            "DataStream-Output-Encryption-Key");
        Socket video = new Socket(host, dataPort.intValue());
        OutputStream videoOut = video.getOutputStream();
        byte[] sps = {0x67, 0x64, 0x00, 0x1f, (byte) 0xac, (byte) 0xd9, 0x40, 0x3c};
        byte[] pps = {0x68, (byte) 0xeb, (byte) 0xe3, (byte) 0xcb};
        ByteArrayOutputStream avcc = new ByteArrayOutputStream();
        avcc.write(new byte[] {1, 0x64, 0, 0x1f, (byte) 0xff, (byte) 0xe1});
        avcc.write(sps.length >> 8);
        avcc.write(sps.length);
        avcc.write(sps);
        avcc.write(1);
        avcc.write(pps.length >> 8);
        avcc.write(pps.length);
        avcc.write(pps);
        byte[] config = concat(new byte[4], "avcC".getBytes(), avcc.toByteArray());
        videoOut.write(screenHeader(config.length, 1));
        videoOut.write(config);
        for (int i = 0; i < 2; i++) {
            byte[] idr = new byte[600 + i * 100];
            RANDOM.nextBytes(idr);
            idr[0] = (byte) (i == 0 ? 0x65 : 0x41);
            byte[] sei = {0x06, 0x05, 0x01, 0x00};
            byte[] frame = concat(u32beBytes(sei.length), sei, u32beBytes(idr.length), idr);
            byte[] header = screenHeader(frame.length + 16, 0);
            videoOut.write(header);
            videoOut.write(chacha(true, screenKey, nonce64(i), frame, header));
        }
        videoOut.flush();
        check(true, "sent VideoConfig and 2 encrypted frames");

        // iAP2 tunnel relay: phone -> Vita (encrypted DataStream) -> relay, and relay -> phone (event channel)
        byte[] relayReply = "reply-from-playport".getBytes(StandardCharsets.US_ASCII);
        Socket tunnel = null;
        if (relayPort > 0) {
            byte[] fromPhone = "hello-iap2-from-phone".getBytes(StandardCharsets.US_ASCII);
            byte[][] relayGot = new byte[1][];
            ServerSocket relayServer = new ServerSocket(relayPort);
            relayServer.setSoTimeout(10000);
            Thread relayThread = new Thread(() -> {
                try (Socket relay = relayServer.accept()) {
                    DataInputStream relayIn = new DataInputStream(relay.getInputStream());
                    byte[] got = new byte[relayIn.readInt()];
                    relayIn.readFully(got);
                    relayGot[0] = got;
                    DataOutputStream relayOut = new DataOutputStream(relay.getOutputStream());
                    relayOut.writeInt(relayReply.length);
                    relayOut.write(relayReply);
                    relayOut.flush();
                    Thread.sleep(3000);
                } catch (Exception e) {
                    // reported by the check below
                }
            });
            relayThread.start();

            long seed = 0xE000000000000042L;
            Map<String, Object> iap = new LinkedHashMap<>();
            iap.put("type", 130L);
            iap.put("clientTypeUUID", "E9459FD0-BCAD-4C45-820F-1E72447EF2F2");
            iap.put("seed", new BigInteger(Long.toUnsignedString(seed)));
            iap.put("streamConnectionID", 77L);
            Map<?, ?> iapResponse = (Map<?, ?>) Bplist.decode(request("SETUP", "rtsp://vita/1",
                "application/x-apple-binary-plist", Bplist.encode(Map.of("streams", List.of(iap)))).body);
            List<?> iapStreams = (List<?>) iapResponse.get("streams");
            Long iapPort = iapStreams != null && !iapStreams.isEmpty() ? (Long) ((Map<?, ?>) iapStreams.get(0)).get("dataPort") : null;
            check(iapPort != null, "iAP2 data stream SETUP returns dataPort " + iapPort);

            byte[] tunnelKey = hkdf(shared, "DataStream-Salt" + Long.toUnsignedString(seed), "DataStream-Output-Encryption-Key");
            byte[] pkg = new byte[32 + fromPhone.length];
            System.arraycopy(u32beBytes(pkg.length), 0, pkg, 0, 4);
            System.arraycopy("comm".getBytes(StandardCharsets.US_ASCII), 0, pkg, 16, 4);
            System.arraycopy(fromPhone, 0, pkg, 32, fromPhone.length);
            byte[] lengthBytes = {(byte) pkg.length, (byte) (pkg.length >> 8)};
            tunnel = new Socket(host, iapPort.intValue());
            tunnel.getOutputStream().write(concat(lengthBytes, chacha(true, tunnelKey, nonce64(0), pkg, lengthBytes)));
            tunnel.getOutputStream().flush();
            relayThread.join(12000);
            relayServer.close();
            check(Arrays.equals(relayGot[0], fromPhone), "relay received the phone's iAP2 bytes from the Vita");
        }

        // event channel: wait for a touch-down report and a knob select report, in any order
        System.out.println("\n  >>> Now TAP the Vita's screen, then PRESS CROSS (30 seconds) <<<\n");
        event.setSoTimeout(30000);
        InputStream eventIn = event.getInputStream();
        long eventCounter = 0;
        ByteArrayOutputStream eventPlain = new ByteArrayOutputStream();
        List<Map<?, ?>> commands = new ArrayList<>();
        Map<?, ?> touchDown = null, knobSelect = null;
        boolean iapReplied = false;
        try {
            while (touchDown == null || knobSelect == null || (relayPort > 0 && !iapReplied)) {
                DataInputStream data = new DataInputStream(eventIn);
                int lo = data.readUnsignedByte(), hi = data.readUnsignedByte();
                int length = lo | (hi << 8);
                byte[] sealed = new byte[length + 16];
                data.readFully(sealed);
                eventPlain.write(chacha(false, eventReadKey, nonce64(eventCounter++), sealed, new byte[] {(byte) lo, (byte) hi}));
                byte[] buffered = eventPlain.toByteArray();
                Response message;
                while ((message = Response.parse(buffered)) != null) {
                    Map<?, ?> command = (Map<?, ?>) Bplist.decode(message.body);
                    commands.add(command);
                    byte[] report = (byte[]) command.get("hidReport");
                    if (touchDown == null && "hidSendReport".equals(command.get("type"))
                            && "2a2a2a2a".equals(command.get("uuid")) && report != null && report.length == 12
                            && report[1] == 1) touchDown = command;
                    if (knobSelect == null && "2a2a2a2b".equals(command.get("uuid")) && report != null
                            && report.length == 4 && report[0] == 1) knobSelect = command;
                    if ("iAPSendMessage".equals(command.get("type")) && command.get("params") instanceof Map<?, ?> params
                            && params.get("data") instanceof byte[] iapData && Arrays.equals(iapData, relayReply)) iapReplied = true;
                    buffered = Arrays.copyOfRange(buffered, message.consumed, buffered.length);
                }
                eventPlain.reset();
                eventPlain.write(buffered);
            }
        } catch (java.net.SocketTimeoutException e) {
            // fall through to the checks
        }
        System.out.println("    received " + commands.size() + " event commands");
        byte[] touchReport = touchDown != null ? (byte[]) touchDown.get("hidReport") : null;
        check(touchReport != null, touchReport == null ? "touch report (none received)"
            : "touch report: finger down at (" + ((touchReport[2] & 0xff) | ((touchReport[3] & 0xff) << 8)) + ","
                + ((touchReport[4] & 0xff) | ((touchReport[5] & 0xff) << 8)) + ")");
        check(knobSelect != null, "knob report: select pressed");
        if (relayPort > 0) check(iapReplied, "relay's reply reached the phone as iAPSendMessage");
        if (tunnel != null) tunnel.close();

        Map<String, Object> teardown = new LinkedHashMap<>();
        teardown.put("streams", List.of(Map.of("type", 110L)));
        check(request("TEARDOWN", "rtsp://vita/1", "application/x-apple-binary-plist", Bplist.encode(teardown)).status == 200,
            "TEARDOWN accepted");
        video.close();
        event.close();
        control.close();
        timing.close();
    }

    static byte[] screenHeader(int bodySize, int opcode) {
        byte[] header = new byte[128];
        header[0] = (byte) bodySize;
        header[1] = (byte) (bodySize >> 8);
        header[2] = (byte) (bodySize >> 16);
        header[3] = (byte) (bodySize >> 24);
        header[4] = (byte) opcode;
        return header;
    }

    // ---- RTSP over the (optionally encrypted) control channel ----

    static class Response {
        int status;
        byte[] body;
        int consumed;

        static Response parse(byte[] buffer) {
            String text = new String(buffer, StandardCharsets.ISO_8859_1);
            int end = text.indexOf("\r\n\r\n");
            if (end < 0) return null;
            int length = 0;
            for (String line : text.substring(0, end).split("\r\n")) {
                int colon = line.indexOf(':');
                if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase("content-length"))
                    length = Integer.parseInt(line.substring(colon + 1).trim());
            }
            if (buffer.length < end + 4 + length) return null;
            Response r = new Response();
            String[] first = text.substring(0, text.indexOf("\r\n")).split(" ");
            r.status = first.length > 1 && first[1].matches("\\d+") ? Integer.parseInt(first[1]) : 0;
            r.body = Arrays.copyOfRange(buffer, end + 4, end + 4 + length);
            r.consumed = end + 4 + length;
            return r;
        }
    }

    Response request(String method, String path, String contentType, byte[] body) throws Exception {
        StringBuilder head = new StringBuilder(method + " " + path + " RTSP/1.0\r\nCSeq: " + (++cseq) + "\r\n");
        if (contentType != null) head.append("Content-Type: ").append(contentType).append("\r\n");
        head.append("Content-Length: ").append(body.length).append("\r\n\r\n");
        byte[] wire = concat(head.toString().getBytes(StandardCharsets.ISO_8859_1), body);
        if (controlWriteKey != null) {
            ByteArrayOutputStream framed = new ByteArrayOutputStream();
            for (int offset = 0; offset < wire.length; offset += 0x4000) {
                byte[] chunk = Arrays.copyOfRange(wire, offset, Math.min(wire.length, offset + 0x4000));
                byte[] lengthBytes = {(byte) chunk.length, (byte) (chunk.length >> 8)};
                framed.write(lengthBytes);
                framed.write(chacha(true, controlWriteKey, nonce64(writeCounter++), chunk, lengthBytes));
            }
            wire = framed.toByteArray();
        }
        out.write(wire);
        out.flush();

        control.setSoTimeout(60000);
        byte[] chunk = new byte[16384];
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        while (true) {
            Response response = Response.parse(plainBuffer.toByteArray());
            if (response != null) {
                byte[] rest = Arrays.copyOfRange(plainBuffer.toByteArray(), response.consumed, plainBuffer.size());
                plainBuffer.reset();
                plainBuffer.write(rest);
                System.out.println("    " + method + " " + path + " -> " + response.status + " (" + response.body.length + " bytes)");
                return response;
            }
            int n = in.read(chunk);
            if (n < 0) throw new IllegalStateException("control connection closed by the Vita");
            if (controlReadKey == null) {
                plainBuffer.write(chunk, 0, n);
                continue;
            }
            raw.write(chunk, 0, n);
            byte[] encrypted = raw.toByteArray();
            int offset = 0;
            while (encrypted.length - offset >= 2) {
                int length = (encrypted[offset] & 0xff) | ((encrypted[offset + 1] & 0xff) << 8);
                if (encrypted.length < offset + 2 + length + 16) break;
                byte[] aad = Arrays.copyOfRange(encrypted, offset, offset + 2);
                byte[] sealed = Arrays.copyOfRange(encrypted, offset + 2, offset + 2 + length + 16);
                plainBuffer.write(chacha(false, controlReadKey, nonce64(readCounter++), sealed, aad));
                offset += 2 + length + 16;
            }
            raw.reset();
            raw.write(encrypted, offset, encrypted.length - offset);
        }
    }

    // ---- SRP-6a client ----

    static class Srp {
        static final BigInteger N = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
                + "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
                + "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
                + "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
                + "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183"
                + "995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A"
                + "85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7AB"
                + "F5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8"
                + "7602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208"
                + "E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16);
        static final BigInteger G = BigInteger.valueOf(5);

        BigInteger bigA;
        byte[] m1, expectedM2, key;

        Srp(byte[] salt, BigInteger bigB) throws Exception {
            byte[] identity = "Pair-Setup".getBytes();
            BigInteger k = new BigInteger(1, sha("SHA-512", minimal(N), pad(G)));
            BigInteger x = new BigInteger(1, sha("SHA-512", salt, sha("SHA-512", "Pair-Setup:3939".getBytes())));
            BigInteger a = new BigInteger(1, randomBytes(32));
            bigA = G.modPow(a, N);
            BigInteger u = new BigInteger(1, sha("SHA-512", pad(bigA), pad(bigB)));
            BigInteger base = bigB.subtract(k.multiply(G.modPow(x, N))).mod(N);
            BigInteger s = base.modPow(a.add(u.multiply(x)), N);
            key = sha("SHA-512", minimal(s));
            byte[] hn = sha("SHA-512", minimal(N)), hg = sha("SHA-512", minimal(G));
            for (int i = 0; i < hn.length; i++) hn[i] ^= hg[i];
            m1 = sha("SHA-512", hn, sha("SHA-512", identity), salt, pad(bigA), pad(bigB), key);
            expectedM2 = sha("SHA-512", pad(bigA), m1, key);
        }

        static byte[] minimal(BigInteger v) {
            byte[] b = v.toByteArray();
            return b.length > 1 && b[0] == 0 ? Arrays.copyOfRange(b, 1, b.length) : b;
        }

        static byte[] pad(BigInteger v) {
            byte[] b = minimal(v), out = new byte[384];
            System.arraycopy(b, 0, out, 384 - b.length, b.length);
            return out;
        }
    }

    // ---- TLV8 ----

    static class Tlv {
        static byte[] encode(Object... typeValuePairs) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (int i = 0; i < typeValuePairs.length; i += 2) {
                int type = (Integer) typeValuePairs[i];
                byte[] value = (byte[]) typeValuePairs[i + 1];
                int offset = 0;
                do {
                    int n = Math.min(255, value.length - offset);
                    out.write(type);
                    out.write(n);
                    out.write(value, offset, n);
                    offset += n;
                } while (offset < value.length);
            }
            return out.toByteArray();
        }

        static Map<Integer, byte[]> decode(byte[] data) {
            Map<Integer, byte[]> out = new HashMap<>();
            int pos = 0, lastType = -1, lastLength = 0;
            while (pos + 2 <= data.length) {
                int type = data[pos] & 0xff, n = data[pos + 1] & 0xff;
                byte[] value = Arrays.copyOfRange(data, pos + 2, pos + 2 + n);
                out.put(type, type == lastType && lastLength == 255 ? concat(out.get(type), value) : value);
                lastType = type;
                lastLength = n;
                pos += 2 + n;
            }
            return out;
        }
    }

    // ---- binary plist (just what this test needs) ----

    static class Bplist {
        static byte[] encode(Object root) {
            List<Object> objects = new ArrayList<>();
            List<int[]> refs = new ArrayList<>();
            flatten(root, objects, refs);
            int refSize = objects.size() < 256 ? 1 : 2;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.writeBytes("bplist00".getBytes());
            long[] offsets = new long[objects.size()];
            for (int i = 0; i < objects.size(); i++) {
                offsets[i] = out.size();
                Object o = objects.get(i);
                if (o instanceof Boolean b) out.write(b ? 0x09 : 0x08);
                else if (o instanceof Long l) writeInt(out, l);
                else if (o instanceof BigInteger big) {
                    out.write(0x14);
                    byte[] b = big.toByteArray(), sixteen = new byte[16];
                    System.arraycopy(b, Math.max(0, b.length - 16), sixteen, 16 - Math.min(16, b.length), Math.min(16, b.length));
                    out.writeBytes(sixteen);
                } else if (o instanceof String s) {
                    marker(out, 0x50, s.length());
                    out.writeBytes(s.getBytes(StandardCharsets.US_ASCII));
                } else if (o instanceof byte[] d) {
                    marker(out, 0x40, d.length);
                    out.writeBytes(d);
                } else if (o instanceof List<?> list) {
                    marker(out, 0xa0, list.size());
                    for (int r : refs.get(i)) writeRef(out, r, refSize);
                } else if (o instanceof Map<?, ?> map) {
                    marker(out, 0xd0, map.size());
                    for (int r : refs.get(i)) writeRef(out, r, refSize);
                }
            }
            long table = out.size();
            for (long offset : offsets) {
                out.write((int) (offset >> 8));
                out.write((int) offset);
            }
            byte[] trailer = new byte[32];
            trailer[6] = 2;
            trailer[7] = (byte) refSize;
            for (int i = 0; i < 8; i++) {
                trailer[8 + i] = (byte) ((long) objects.size() >> (56 - 8 * i));
                trailer[24 + i] = (byte) (table >> (56 - 8 * i));
            }
            out.writeBytes(trailer);
            return out.toByteArray();
        }

        static int flatten(Object o, List<Object> objects, List<int[]> refs) {
            int index = objects.size();
            objects.add(o instanceof Integer i ? (Object) (long) i : o);
            refs.add(new int[0]);
            if (o instanceof List<?> list) {
                int[] r = new int[list.size()];
                for (int i = 0; i < list.size(); i++) r[i] = flatten(list.get(i), objects, refs);
                refs.set(index, r);
            } else if (o instanceof Map<?, ?> map) {
                int[] r = new int[map.size() * 2];
                int i = 0;
                for (Object key : map.keySet()) r[i++] = flatten(key, objects, refs);
                for (Object value : map.values()) r[i++] = flatten(value, objects, refs);
                refs.set(index, r);
            }
            return index;
        }

        static void marker(ByteArrayOutputStream out, int high, int length) {
            if (length < 15) out.write(high | length);
            else {
                out.write(high | 0x0f);
                writeInt(out, length);
            }
        }

        static void writeInt(ByteArrayOutputStream out, long v) {
            if (v >= 0 && v < 256) { out.write(0x10); out.write((int) v); }
            else if (v >= 0 && v < 65536) { out.write(0x11); out.write((int) (v >> 8)); out.write((int) v); }
            else { out.write(0x13); for (int i = 7; i >= 0; i--) out.write((int) (v >> (8 * i))); }
        }

        static void writeRef(ByteArrayOutputStream out, int ref, int size) {
            if (size == 2) out.write(ref >> 8);
            out.write(ref);
        }

        static Object decode(byte[] d) {
            int t = d.length - 32;
            int offsetSize = d[t + 6], refSize = d[t + 7];
            long count = be(d, t + 8, 8), top = be(d, t + 16, 8), table = be(d, t + 24, 8);
            return object(d, (int) top, offsetSize, refSize, (int) table, (int) count);
        }

        static Object object(byte[] d, int index, int os, int rs, int table, int count) {
            int pos = (int) be(d, table + index * os, os);
            int marker = d[pos] & 0xff, high = marker >> 4, low = marker & 0x0f;
            pos++;
            if (high == 0) return marker == 0x09;
            if (high == 1) {
                int n = 1 << low;
                return n == 16 ? new BigInteger(1, Arrays.copyOfRange(d, pos, pos + 16)) : (Object) be(d, pos, n);
            }
            long length = low;
            if (low == 0x0f && (high == 4 || high == 5 || high == 6 || high == 0xa || high == 0xd)) {
                int n = 1 << (d[pos] & 0x0f);
                length = be(d, pos + 1, n);
                pos += 1 + n;
            }
            switch (high) {
                case 4: return Arrays.copyOfRange(d, pos, pos + (int) length);
                case 5: return new String(d, pos, (int) length, StandardCharsets.US_ASCII);
                case 6: return new String(d, pos, (int) length * 2, StandardCharsets.UTF_16BE);
                case 0xa: {
                    List<Object> list = new ArrayList<>();
                    for (int i = 0; i < length; i++) list.add(object(d, (int) be(d, pos + i * rs, rs), os, rs, table, count));
                    return list;
                }
                case 0xd: {
                    Map<Object, Object> map = new LinkedHashMap<>();
                    for (int i = 0; i < length; i++) {
                        Object key = object(d, (int) be(d, pos + i * rs, rs), os, rs, table, count);
                        Object value = object(d, (int) be(d, pos + (int) (length + i) * rs, rs), os, rs, table, count);
                        map.put(key, value);
                    }
                    return map;
                }
                default: throw new IllegalArgumentException("unsupported bplist marker " + marker);
            }
        }

        static long be(byte[] d, int pos, int n) {
            long v = 0;
            for (int i = 0; i < n; i++) v = (v << 8) | (d[pos + i] & 0xff);
            return v;
        }
    }

    // ---- crypto helpers ----

    static byte[] hkdf(byte[] ikm, String salt, String info) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(salt.getBytes(StandardCharsets.US_ASCII), "HmacSHA512"));
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, "HmacSHA512"));
        mac.update(info.getBytes(StandardCharsets.US_ASCII));
        mac.update((byte) 1);
        return Arrays.copyOf(mac.doFinal(), 32);
    }

    static byte[] chacha(boolean encrypt, byte[] key, byte[] nonce, byte[] data, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"),
            new IvParameterSpec(nonce));
        if (aad.length > 0) cipher.updateAAD(aad);
        return cipher.doFinal(data);
    }

    static byte[] label(String text) {
        byte[] nonce = new byte[12];
        byte[] ascii = text.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(ascii, 0, nonce, 4, Math.min(8, ascii.length));
        return nonce;
    }

    static byte[] nonce64(long counter) {
        byte[] nonce = new byte[12];
        for (int i = 4; i < 12; i++) {
            nonce[i] = (byte) counter;
            counter >>>= 8;
        }
        return nonce;
    }

    static final byte[] ED25519_PREFIX = hex("302a300506032b6570032100");
    static final byte[] X25519_PREFIX = hex("302a300506032b656e032100");

    static byte[] rawEd25519(PublicKey key) {
        byte[] e = key.getEncoded();
        return Arrays.copyOfRange(e, e.length - 32, e.length);
    }

    static byte[] rawX25519(PublicKey key) {
        byte[] e = key.getEncoded();
        return Arrays.copyOfRange(e, e.length - 32, e.length);
    }

    static PublicKey x25519Public(byte[] raw) throws Exception {
        return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(concat(X25519_PREFIX, raw)));
    }

    static byte[] sign(KeyPair key, byte[] data) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key.getPrivate());
        signer.update(data);
        return signer.sign();
    }

    static boolean verifyEd25519(byte[] raw, byte[] data, byte[] signature) throws Exception {
        if (raw == null || signature == null) return false;
        PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(concat(ED25519_PREFIX, raw)));
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(key);
        verifier.update(data);
        return verifier.verify(signature);
    }

    static byte[] sha(String algorithm, byte[]... parts) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        for (byte[] part : parts) digest.update(part);
        return digest.digest();
    }

    static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) out.writeBytes(part);
        return out.toByteArray();
    }

    static int u32be(byte[] d, int pos) {
        return ((d[pos] & 0xff) << 24) | ((d[pos + 1] & 0xff) << 16) | ((d[pos + 2] & 0xff) << 8) | (d[pos + 3] & 0xff);
    }

    static byte[] u32beBytes(int v) {
        return new byte[] {(byte) (v >> 24), (byte) (v >> 16), (byte) (v >> 8), (byte) v};
    }

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
}
