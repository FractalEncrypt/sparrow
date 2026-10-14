package com.sparrowwallet.sparrow.transaction;

import com.google.common.eventbus.EventBus;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.AntiExfilProfile;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.KeystoreSource;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.sparrow.AppServices;
import com.sparrowwallet.sparrow.EventManager;
import com.sparrowwallet.sparrow.InteractionServices;
import com.sparrowwallet.sparrow.event.OpenWalletsEvent;
import com.sparrowwallet.sparrow.io.Config;
import com.sparrowwallet.sparrow.io.Storage;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.stage.Stage;
import javafx.stage.Window;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A11: the Protected QR action serializes the live PSBT, existing signatures included, into a new anti-exfil
 * session and QR. It must refuse at handler time when the tab's protected-signing provenance fails, like every
 * other PSBT egress. Testnet4 public fixture only; nothing connects or broadcasts and no device is present.
 */
class AntiExfilProtectedQrEgressRegressionTest {
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
        System.setProperty("sparrow.home", Files.createTempDirectory("sparrow-a11-regression-home-").toString());
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
    @Test void protectedQrRefusesQuarantinedPsbt() throws Exception {
        Fixture f = boundTab(AntiExfilKeystorePolicy.REQUIRED);
        fx(() -> {
            assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, AntiExfilPolicy.evaluatePsbtEgress(f.data));
            return null;
        });
        int before = alerts.size();
        List<String> opened = fireProtectedQr(f);
        assertEquals(List.of(), opened, "no anti-exfil QR window may open for the quarantined PSBT");
        assertEquals(List.of("PSBT export blocked: Sparrow cannot start a protected signing session with this PSBT because protected-signing provenance could not be verified (REQUIRED_PROOF_MISSING)."),
                alerts.subList(before, alerts.size()));
    }

    @Test void unsignedProtectedStartStaysPermitted() throws Exception {
        //Guard: an unsigned PSBT bound to the same Required wallet is PERMITTED, so the handler would proceed.
        Fixture f = boundTab(AntiExfilKeystorePolicy.REQUIRED);
        fx(() -> {
            PSBT unsigned = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()), false);
            for(PSBTInput input : unsigned.getPsbtInputs()) input.getPartialSignatures().clear();
            PSBT reparsed = new PSBT(unsigned.serialize(), false);
            TransactionData data = new TransactionData("protected-qr-unsigned", reparsed);
            data.setSigningWallet(f.data.getSigningWallet());
            assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, AntiExfilPolicy.evaluatePsbtEgress(data));
            return null;
        });
    }

    record Fixture(HeadersController controller, TransactionData data, Stage stage, Map<String, Object> namespace) {
        Node node(String id) { return (Node)namespace.get(id); }
    }

    /** Signer A's signature only (no proof), bound to the Required wallet by the real openWallets. */
    private Fixture boundTab(AntiExfilKeystorePolicy policyA) throws Exception {
        Wallet wallet = new Wallet("a11-" + policyA);
        wallet.getKeystores().add(keystore(vector.getAsJsonObject("signer_a"), policyA));
        wallet.getKeystores().add(keystore(vector.getAsJsonObject("signer_b"), AntiExfilKeystorePolicy.OPTIONAL));
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        wallet.checkWallet();

        PSBT psbt = new PSBT(Utils.hexToBytes(vector.get("signed_psbt_hex").getAsString()), false);
        Fixture f = fx(() -> {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("headers.fxml"));
            Parent root = loader.load();
            HeadersController controller = loader.getController();
            Stage stage = new Stage(); stage.setScene(new Scene(root, 1100, 900));
            TransactionData data = new TransactionData("protected-qr", psbt);
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

    /** Invokes the Protected QR handler (antiExfilButton onAction) and closes, recording, any window it opens. */
    private List<String> fireProtectedQr(Fixture f) throws Exception {
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
        }, "a11-window-closer");
        closer.setDaemon(true);
        closer.start();
        try {
            fx(() -> { f.controller.signAntiExfil(null); return null; });
        } finally {
            done.set(true);
            closer.join(2000);
        }
        return opened;
    }

    private static Keystore keystore(JsonObject signer, AntiExfilKeystorePolicy policy) throws Exception {
        Keystore keystore = Keystore.fromSeed(new DeterministicSeed(signer.get("mnemonic").getAsString(), "", 0,
                DeterministicSeed.Type.BIP39), PolicyType.MULTI_HD,
                KeyDerivation.parsePath(signer.get("account_derivation").getAsString()));
        keystore.setSeed(null);
        keystore.setMasterPrivateExtendedKey(null);
        keystore.setSource(KeystoreSource.HW_AIRGAPPED);
        keystore.setLabel(keystore.getKeyDerivation().getMasterFingerprint());
        keystore.setWalletModel(WalletModel.KERN);
        keystore.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);
        keystore.setAntiExfilPolicy(policy);
        return keystore;
    }

    private static Object get(Class<?> type, String name) throws Exception {
        Field field = type.getDeclaredField(name); field.setAccessible(true); return field.get(null);
    }

    private static void set(Class<?> type, Object target, String name, Object value) throws Exception {
        Field field = type.getDeclaredField(name); field.setAccessible(true); field.set(target, value);
    }

    private static <T> T fx(java.util.concurrent.Callable<T> callable) throws Exception {
        FutureTask<T> task = new FutureTask<>(callable); Platform.runLater(task); return task.get(30, TimeUnit.SECONDS);
    }
}
