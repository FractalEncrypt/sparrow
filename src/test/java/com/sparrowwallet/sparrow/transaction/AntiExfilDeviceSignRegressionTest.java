package com.sparrowwallet.sparrow.transaction;

import com.google.common.eventbus.EventBus;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator;
import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.antiexfil.VerifiedAntiExfilSignature;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.*;
import com.sparrowwallet.sparrow.event.OpenWalletsEvent;
import com.sparrowwallet.sparrow.io.Config;
import com.sparrowwallet.sparrow.io.Storage;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.Stage;
import javafx.stage.Window;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * A6: in a mixed wallet (Required QR signer plus a USB cosigner), a tab holding the Required signer's signature
 * without a matching proof is quarantined, but openWallets re-enables Sign and the USB path hands the live PSBT,
 * including that signature, to the device. The USB send must be refused at click time like every other PSBT egress.
 * No device is attached; the test only observes whether the device dialog would open.
 */
class AntiExfilDeviceSignRegressionTest {
    @TempDir Path temp;
    private static String previousHome;
    private Network previousNetwork;
    private Object previousServices;
    private Object previousEventBus;
    private JsonObject vector;
    private final List<String> alerts = new CopyOnWriteArrayList<>();
    private final List<Throwable> eventErrors = new CopyOnWriteArrayList<>();
    private final List<Stage> stages = new ArrayList<>();
    private final List<HeadersController> controllers = new ArrayList<>();

    @BeforeAll static void toolkit() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        try { Platform.startup(ready::countDown); } catch(IllegalStateException alreadyStarted) { ready.countDown(); }
        assertTrue(ready.await(10, TimeUnit.SECONDS));
        Platform.setImplicitExit(false);
        previousHome = System.getProperty("sparrow.home");
        System.setProperty("sparrow.home", Files.createTempDirectory("sparrow-a6-regression-home-").toString());
    }

    @AfterAll static void restoreHome() {
        if(previousHome == null) System.clearProperty("sparrow.home"); else System.setProperty("sparrow.home", previousHome);
    }

    @BeforeEach void setup() throws Exception {
        previousNetwork = Network.get();
        Network.set(Network.TESTNET4);
        previousEventBus = get(EventManager.class, "SINGLETON");
        set(EventManager.class, null, "SINGLETON", new EventBus((error, context) -> eventErrors.add(error)));
        set(Config.class, null, "INSTANCE", new Config());
        previousServices = get(AppServices.class, "INSTANCE");
        AppServices.initialize(null, new InteractionServices() {
            @Override public Optional<ButtonType> showAlert(String title, String content, Alert.AlertType type, Node graphic, ButtonType... buttons) {
                alerts.add(title + ": " + content); return Optional.of(ButtonType.NO);
            }
            @Override public Optional<String> requestPassphrase(String walletName, Keystore keystore) {
                throw new AssertionError("No secrets may be requested");
            }
        });
        EventManager.get().unregister(AppServices.get());
        try(var reader = new InputStreamReader(getClass().getResourceAsStream(
                "/com/sparrowwallet/sparrow/io/protocol-v1-mixed-provenance-vector.json"), StandardCharsets.UTF_8)) {
            vector = JsonParser.parseReader(reader).getAsJsonObject();
        }
    }

    @AfterEach void cleanup() throws Exception {
        fx(() -> { controllers.forEach(HeadersController::close); stages.forEach(Stage::close); return null; });
        set(AppServices.class, null, "INSTANCE", previousServices);
        set(EventManager.class, null, "SINGLETON", previousEventBus);
        Network.set(previousNetwork);
        assertTrue(eventErrors.isEmpty(), eventErrors.toString());
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void usbSignRefusesQuarantinedPsbt() throws Exception {
        Fixture f = boundTab(AntiExfilKeystorePolicy.REQUIRED, Set.of());
        fx(() -> {
            assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, AntiExfilPolicy.evaluatePsbtEgress(f.data));
            assertTrue(f.node("provenanceWarning").isVisible(), "the tab is quarantined");
            System.out.println("[A6] quarantined tab after openWallets: signButtonDisabled=" + f.node("signButton").isDisabled()
                    + " signButtonBoxVisible=" + f.node("signButtonBox").isVisible());
            return null;
        });
        int before = alerts.size();
        List<String> opened = signThroughHandler(f);
        assertEquals(List.of(), opened, "the device dialog must not receive the quarantined PSBT");
        assertEquals(List.of("PSBT export blocked: Sparrow cannot send this PSBT to a signing device because protected-signing provenance could not be verified (REQUIRED_PROOF_MISSING)."),
                alerts.subList(before, alerts.size()));
    }

    /**
     * Guard (passes before and after the fix): a permitted PSBT still reaches the device dialog, both when signer A is
     * Optional and in the protected flow itself, where A is Required and its signature carries the ceremony proof.
     */
    @Test void usbSignStillOffersPermittedPsbtToTheDevice() throws Exception {
        Map<String, Fixture> cases = new LinkedHashMap<>();
        cases.put("A optional", boundTab(AntiExfilKeystorePolicy.OPTIONAL, Set.of()));
        cases.put("A required with proof", boundTab(AntiExfilKeystorePolicy.REQUIRED, proofForSignerA()));
        for(Map.Entry<String, Fixture> c : cases.entrySet()) {
            Fixture f = c.getValue();
            fx(() -> { assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, AntiExfilPolicy.evaluatePsbtEgress(f.data), c.getKey()); return null; });
            assertEquals(1, signThroughHandler(f).size(), c.getKey() + ": the device dialog opens");
        }
        assertTrue(alerts.isEmpty(), alerts.toString());
    }

    record Fixture(HeadersController controller, TransactionData data, Stage stage, Map<String, Object> namespace) {
        Node node(String id) { return (Node)namespace.get(id); }
    }

    /** Signer A's signature only (no proof supplied), opened fresh and bound to the wallet by the real openWallets. */
    private Fixture boundTab(AntiExfilKeystorePolicy policyA, Set<VerifiedAntiExfilSignature> proofs) throws Exception {
        Wallet wallet = new Wallet("mixed-usb-" + policyA);
        wallet.getKeystores().add(keystore(vector.getAsJsonObject("signer_a"), policyA, WalletModel.KERN, KeystoreSource.HW_AIRGAPPED));
        wallet.getKeystores().add(keystore(vector.getAsJsonObject("signer_b"), AntiExfilKeystorePolicy.UNSUPPORTED, WalletModel.TREZOR_T, KeystoreSource.HW_USB));
        wallet.setPolicyType(PolicyType.MULTI_HD); wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        wallet.checkWallet();

        PSBT onlyA = new PSBT(Utils.hexToBytes(vector.get("signed_psbt_hex").getAsString()), false);
        String fingerprintB = wallet.getKeystores().get(1).getKeyDerivation().getMasterFingerprint();
        onlyA.getPsbtInputs().getFirst().getPartialSignatures().keySet().removeIf(key ->
                onlyA.getPsbtInputs().getFirst().getDerivedPublicKeys().get(key).getMasterFingerprint().equals(fingerprintB));
        PSBT psbt = new PSBT(onlyA.serialize(), false);
        assertEquals(1, psbt.getPsbtInputs().getFirst().getPartialSignatures().size());
        assertFalse(psbt.isSigned());

        Fixture f = fx(() -> {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("headers.fxml"));
            Parent root = loader.load();
            HeadersController controller = loader.getController();
            Stage stage = new Stage(); stage.setScene(new Scene(root, 1100, 900));
            TransactionData data = new TransactionData("signer-a-return", psbt, proofs);
            controller.setModel(new HeadersForm(data));
            stage.show(); root.applyCss(); root.layout();
            stages.add(stage); controllers.add(controller);
            return new Fixture(controller, data, stage, loader.getNamespace());
        });
        fx(() -> {
            EventManager.get().post(new OpenWalletsEvent(f.stage, List.of()) {
                @Override public Map<Wallet, Storage> getWalletsMap() {
                    Map<Wallet, Storage> wallets = new LinkedHashMap<>(); wallets.put(wallet, null); return wallets;
                }
                @Override public List<Wallet> getWallets() { return List.of(wallet); }
            });
            assertSame(wallet, f.data.getSigningWallet());
            return null;
        });
        return f;
    }

    /** Signer A's genuine ceremony proof for the vector's signed PSBT (the signature kept in boundTab). */
    private Set<VerifiedAntiExfilSignature> proofForSignerA() throws Exception {
        Method create = AntiExfilCoordinator.class.getDeclaredMethod("create", Path.class, Path.class, byte[].class,
                Keystore.class, AntiExfilNetwork.class, boolean.class, SecureRandom.class);
        create.setAccessible(true);
        AntiExfilCoordinator coordinator = (AntiExfilCoordinator)create.invoke(null, temp.resolve("a.aexs"), temp.resolve("a.aexj"),
                Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()),
                keystore(vector.getAsJsonObject("signer_a"), AntiExfilKeystorePolicy.REQUIRED, WalletModel.KERN, KeystoreSource.HW_AIRGAPPED),
                AntiExfilNetwork.TESTNET4, false, new SecureRandom() {
                    int call;
                    @Override public void nextBytes(byte[] bytes) { Arrays.fill(bytes, call++ == 0 ? (byte)'m' : (byte)0xa1); }
                });
        coordinator.acceptOpenings(Utils.hexToBytes(vector.get("message_2_hex").getAsString()));
        return coordinator.complete(Utils.hexToBytes(vector.get("message_4_hex").getAsString())).getVerifiedSignatures();
    }

    /** Invokes the Sign handler (signButton onAction) and closes, recording, any window it opens. */
    private List<String> signThroughHandler(Fixture f) throws Exception {
        Set<Window> known = Collections.newSetFromMap(new ConcurrentHashMap<>());
        fx(() -> { known.addAll(Window.getWindows()); return null; });
        List<String> opened = new CopyOnWriteArrayList<>();
        AtomicBoolean done = new AtomicBoolean();
        Thread closer = new Thread(() -> {
            while(!done.get()) {
                Platform.runLater(() -> Window.getWindows().stream().filter(w -> w.isShowing() && !known.contains(w)).toList()
                        .forEach(w -> { opened.add(w.getClass().getName() + (w instanceof Stage s ? " \"" + s.getTitle() + "\"" : "")); w.hide(); }));
                try { Thread.sleep(100); } catch(InterruptedException e) { return; }
            }
        }, "a6-window-closer");
        closer.setDaemon(true);
        closer.start();
        try {
            fx(() -> { f.controller.signPSBT(null); return null; });
        } finally {
            done.set(true);
            closer.join(2000);
        }
        return opened;
    }

    private static Keystore keystore(JsonObject signer, AntiExfilKeystorePolicy policy, WalletModel model, KeystoreSource source) throws Exception {
        Keystore keystore = Keystore.fromSeed(new DeterministicSeed(signer.get("mnemonic").getAsString(), "", 0,
                DeterministicSeed.Type.BIP39), PolicyType.MULTI_HD, KeyDerivation.parsePath(signer.get("account_derivation").getAsString()));
        keystore.setSeed(null); keystore.setMasterPrivateExtendedKey(null); keystore.setSource(source);
        keystore.setLabel(keystore.getKeyDerivation().getMasterFingerprint());
        keystore.setWalletModel(model);
        if(model == WalletModel.KERN) keystore.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);
        keystore.setAntiExfilPolicy(policy);
        return keystore;
    }

    private static Object get(Class<?> type, String name) throws Exception {
        Field field = type.getDeclaredField(name); field.setAccessible(true); return field.get(null);
    }

    private static void set(Class<?> type, Object target, String name, Object value) throws Exception {
        Field field = type.getDeclaredField(name); field.setAccessible(true); field.set(target, value);
    }

    private static <T> T fx(Callable<T> callable) throws Exception {
        FutureTask<T> task = new FutureTask<>(callable); Platform.runLater(task); return task.get(30, TimeUnit.SECONDS);
    }
}
