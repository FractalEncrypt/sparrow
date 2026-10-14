package com.sparrowwallet.sparrow.transaction;

import com.google.common.eventbus.EventBus;
import com.google.common.eventbus.Subscribe;
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
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.*;
import com.sparrowwallet.sparrow.event.OpenWalletsEvent;
import com.sparrowwallet.sparrow.event.PSBTCombinedEvent;
import com.sparrowwallet.sparrow.event.RequestConnectEvent;
import com.sparrowwallet.sparrow.io.Config;
import com.sparrowwallet.sparrow.io.Storage;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.Stage;
import org.junit.jupiter.api.*;

import java.io.File;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * A2: a fully signed PSBT opened with no wallet that can attribute its signatures is quarantined as
 * POLICY_CONTEXT_UNAVAILABLE. Opening the unsigned original into the same window merges (the incoming copy has
 * no signatures), and the merge must not install a keystore-less FinalizingPSBTWallet that lifts the quarantine,
 * auto-finalizes and enables Broadcast. Testnet4 public fixture only; nothing connects or broadcasts.
 */
class AntiExfilQuarantineMergeRegressionTest {
    private static String previousHome;
    private Network previousNetwork;
    private Object previousServices;
    private Object previousEventBus;
    private JsonObject vector;
    private final List<String> alerts = new CopyOnWriteArrayList<>();
    private final List<Throwable> eventErrors = new CopyOnWriteArrayList<>();
    private final List<Stage> stages = new ArrayList<>();
    private final List<HeadersController> controllers = new ArrayList<>();
    private final AtomicInteger merges = new AtomicInteger();
    private final AtomicInteger connects = new AtomicInteger();

    @BeforeAll static void toolkit() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        try { Platform.startup(ready::countDown); } catch(IllegalStateException alreadyStarted) { ready.countDown(); }
        assertTrue(ready.await(10, TimeUnit.SECONDS));
        Platform.setImplicitExit(false);
        previousHome = System.getProperty("sparrow.home");
        System.setProperty("sparrow.home", Files.createTempDirectory("sparrow-a2-regression-home-").toString());
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
        EventManager.get().register(new Object() {
            @Subscribe public void combined(PSBTCombinedEvent event) { merges.incrementAndGet(); }
            @Subscribe public void connect(RequestConnectEvent event) { connects.incrementAndGet(); }
        });
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
        assertEquals(0, connects.get(), "no connection may be requested");
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void mergingUnsignedOriginalKeepsNoContextQuarantine() throws Exception {
        Fixture f = signedTabWithoutWallet();
        fx(() -> {
            assertEquals(AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE, HeadersController.evaluateTransactionProvenance(f.data));
            assertTrue(f.node("broadcastButton").isDisabled());

            // File > Open Transaction of the unsigned original into the same window: the real AppController route.
            AppController app = new AppController();
            TabPane tabs = new TabPane();
            Tab tab = new Tab();
            tab.setGraphic(new Label("signed-return"));
            tab.setUserData(new TransactionTabData(TabData.TabType.TRANSACTION, null, f.data));
            tabs.getTabs().add(tab);
            set(AppController.class, app, "tabs", tabs);
            Method open = AppController.class.getDeclaredMethod("addTransactionTab", String.class, File.class, PSBT.class);
            open.setAccessible(true);
            open.invoke(app, "unsigned-original", null, unsignedOriginal());
            assertEquals(1, merges.get(), "precondition: the unsigned copy merges into the quarantined tab");
            assertEquals(1, tabs.getTabs().size());

            Wallet bound = f.data.getSigningWallet();
            assertFalse(bound instanceof FinalizingPSBTWallet, "a keystore-less finalizing wallet must not be bound");
            assertNull(bound);
            assertFalse(f.data.getPsbt().isFinalized(), "no automatic finalization without policy context");
            assertEquals(AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE, HeadersController.evaluateTransactionProvenance(f.data));
            assertTrue(f.node("provenanceWarning").isVisible());
            for(String id : List.of("broadcastButton", "viewFinalButton", "savePsbtButton", "showPsbtButton", "payjoinButton")) {
                assertTrue(f.node(id).isDisabled(), id + " must stay disabled");
            }
            int before = alerts.size();
            assertFalse(f.controller.extractTransaction());
            assertTrue(alerts.subList(before, alerts.size()).stream().anyMatch(a -> a.contains("POLICY_CONTEXT_UNAVAILABLE")), alerts.toString());
            return null;
        });
    }

    /** Guard (passes before and after the fix): once a policy wallet is opened it decides, as for any signed import. */
    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void openingAPolicyWalletAfterTheMergeDecides() throws Exception {
        for(AntiExfilKeystorePolicy policyA : List.of(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL)) {
            Fixture f = signedTabWithoutWallet();
            Wallet wallet = wallet(policyA);
            fx(() -> {
                f.data.combineVerifiedPsbt(unsignedOriginal(), Set.of());
                EventManager.get().post(new PSBTCombinedEvent(f.data.getPsbt()));
                EventManager.get().post(openWallets(f.stage, wallet));
                assertSame(wallet, f.data.getSigningWallet());
                AntiExfilPolicy.ProvenanceStatus expected = policyA == AntiExfilKeystorePolicy.REQUIRED
                        ? AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING : AntiExfilPolicy.ProvenanceStatus.PERMITTED;
                assertEquals(expected, HeadersController.evaluateTransactionProvenance(f.data), "A=" + policyA);
                assertEquals(expected != AntiExfilPolicy.ProvenanceStatus.PERMITTED, f.node("broadcastButton").isDisabled(), "A=" + policyA);
                return null;
            });
        }
    }

    record Fixture(HeadersController controller, TransactionData data, Stage stage, Map<String, Object> namespace) {
        Node node(String id) { return (Node)namespace.get(id); }
    }

    /** A fully signed, unfinalized PSBT (signer A Required, no proof) opened while no wallet that can sign it is open. */
    private Fixture signedTabWithoutWallet() throws Exception {
        PSBT signed = new PSBT(Utils.hexToBytes(vector.get("signed_psbt_hex").getAsString()), false);
        assertTrue(signed.isSigned());
        assertFalse(signed.isFinalized());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet(AntiExfilKeystorePolicy.REQUIRED), signed, Set.of()));
        Fixture f = fx(() -> {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("headers.fxml"));
            Parent root = loader.load();
            HeadersController controller = loader.getController();
            Stage stage = new Stage(); stage.setScene(new Scene(root, 1100, 900));
            TransactionData data = new TransactionData("signed-return", signed);
            controller.setModel(new HeadersForm(data));
            stage.show(); root.applyCss(); root.layout();
            stages.add(stage); controllers.add(controller);
            return new Fixture(controller, data, stage, loader.getNamespace());
        });
        fx(() -> { EventManager.get().post(openWallets(f.stage)); return null; }); // no open wallet can sign it
        return f;
    }

    private PSBT unsignedOriginal() throws Exception {
        PSBT unsigned = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()), false);
        for(PSBTInput input : unsigned.getPsbtInputs()) input.getPartialSignatures().clear();
        PSBT reparsed = new PSBT(unsigned.serialize(), false);
        assertFalse(reparsed.hasSignatures());
        return reparsed;
    }

    private Wallet wallet(AntiExfilKeystorePolicy policyA) throws Exception {
        Wallet wallet = new Wallet("vault-" + policyA);
        wallet.getKeystores().add(signer(vector.getAsJsonObject("signer_a"), policyA));
        wallet.getKeystores().add(signer(vector.getAsJsonObject("signer_b"), AntiExfilKeystorePolicy.OPTIONAL));
        wallet.setPolicyType(PolicyType.MULTI_HD); wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        wallet.checkWallet();
        return wallet;
    }

    private static Keystore signer(JsonObject data, AntiExfilKeystorePolicy policy) throws Exception {
        Keystore key = Keystore.fromSeed(new DeterministicSeed(data.get("mnemonic").getAsString(), "", 0,
                DeterministicSeed.Type.BIP39), PolicyType.MULTI_HD, KeyDerivation.parsePath(data.get("account_derivation").getAsString()));
        key.setSeed(null); key.setMasterPrivateExtendedKey(null); key.setSource(KeystoreSource.HW_AIRGAPPED);
        key.setLabel(key.getKeyDerivation().getMasterFingerprint());
        key.setWalletModel(WalletModel.KERN); key.setAntiExfilProfile(AntiExfilProfile.AEXT_V1); key.setAntiExfilPolicy(policy);
        return key;
    }

    private static OpenWalletsEvent openWallets(Stage stage, Wallet... wallets) {
        return new OpenWalletsEvent(stage, List.of()) {
            @Override public Map<Wallet, Storage> getWalletsMap() {
                Map<Wallet, Storage> map = new LinkedHashMap<>();
                for(Wallet wallet : wallets) map.put(wallet, null);
                return map;
            }
            @Override public List<Wallet> getWallets() { return List.of(wallets); }
        };
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
