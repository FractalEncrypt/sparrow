package com.sparrowwallet.sparrow.transaction;

import com.google.common.eventbus.EventBus;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.*;
import com.sparrowwallet.sparrow.io.Config;
import javafx.application.Platform;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import javafx.stage.Window;
import org.junit.jupiter.api.*;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * A4: File > Save Transaction and File > Show Transaction as QR export a raw signed transaction tab's bytes. They must
 * apply the same provenance predicate the tab's own final-transaction buttons use, at click time, so a quarantined
 * raw transaction cannot leave the host through the File menu. Testnet4 throwaway keys; nothing connects or broadcasts.
 */
class AntiExfilRawTransactionExportRegressionTest {
    private static final String MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    private static String previousHome;
    private Network previousNetwork;
    private Object previousServices;
    private Object previousEventBus;
    private final List<String> alerts = new CopyOnWriteArrayList<>();
    private final List<Throwable> eventErrors = new CopyOnWriteArrayList<>();
    private final List<Stage> stages = new ArrayList<>();

    @BeforeAll static void toolkit() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        try { Platform.startup(ready::countDown); } catch(IllegalStateException alreadyStarted) { ready.countDown(); }
        assertTrue(ready.await(10, TimeUnit.SECONDS));
        Platform.setImplicitExit(false);
        previousHome = System.getProperty("sparrow.home");
        System.setProperty("sparrow.home", Files.createTempDirectory("sparrow-a4-regression-home-").toString());
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
    }

    @AfterEach void cleanup() throws Exception {
        fx(() -> { stages.forEach(Stage::close); return null; });
        set(AppServices.class, null, "INSTANCE", previousServices);
        set(EventManager.class, null, "SINGLETON", previousEventBus);
        Network.set(previousNetwork);
        assertTrue(eventErrors.isEmpty(), eventErrors.toString());
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void fileMenuSaveTransactionRefusesQuarantinedRawTransaction() throws Exception {
        for(TransactionData data : quarantinedRawTabs()) {
            String status = HeadersController.evaluateTransactionProvenance(data).toString();
            AppController app = appWithSelectedTab(data);
            int before = alerts.size();
            assertDoesNotThrow(() -> fx(() -> { app.saveTransaction(null); return null; }),
                    data.getName() + ": File > Save Transaction must stop before the file chooser");
            assertEquals(List.of("Transaction export blocked: Sparrow cannot save this transaction because protected-signing provenance could not be verified (" + status + ")."),
                    alerts.subList(before, alerts.size()));
        }
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void fileMenuShowTransactionRefusesQuarantinedRawTransaction() throws Exception {
        for(TransactionData data : quarantinedRawTabs()) {
            String status = HeadersController.evaluateTransactionProvenance(data).toString();
            AppController app = appWithSelectedTab(data);
            int before = alerts.size();
            List<String> opened = showTransaction(app);
            assertEquals(List.of(), opened, data.getName() + ": no QR dialog may open");
            assertEquals(List.of("Transaction export blocked: Sparrow cannot display this transaction as QR because protected-signing provenance could not be verified (" + status + ")."),
                    alerts.subList(before, alerts.size()));
        }
    }

    /** A Required signer's ordinary signature as a raw transaction, attributed through the wallet history, and the same bytes with no wallet. */
    private List<TransactionData> quarantinedRawTabs() throws Exception {
        Fixture required = fixture(AntiExfilKeystorePolicy.REQUIRED);
        TransactionData attributed = new TransactionData("raw-required", new Transaction(required.raw.bitcoinSerialize()));
        attributed.setSigningWallet(required.wallet);
        TransactionData noWallet = new TransactionData("raw-no-wallet", new Transaction(required.raw.bitcoinSerialize()));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, HeadersController.evaluateTransactionProvenance(attributed));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE, HeadersController.evaluateTransactionProvenance(noWallet));
        return List.of(attributed, noWallet);
    }

    /** Guard (passes before and after the fix): permitted raw transactions and wallet history still export. */
    @Test void permittedAndWalletHistoryTransactionsStillExport() throws Exception {
        Fixture optional = fixture(AntiExfilKeystorePolicy.OPTIONAL);
        TransactionData permitted = new TransactionData("raw-optional", new Transaction(optional.raw.bitcoinSerialize()));
        permitted.setSigningWallet(optional.wallet);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, HeadersController.evaluateTransactionProvenance(permitted));
        Fixture required = fixture(AntiExfilKeystorePolicy.REQUIRED);
        Transaction broadcast = new Transaction(required.raw.bitcoinSerialize());
        TransactionData history = new TransactionData("history", new BlockTransaction(broadcast.getTxId(), 101, new Date(), 0L, broadcast));

        for(TransactionData data : List.of(permitted, history)) {
            AppController app = appWithSelectedTab(data);
            ExecutionException chooser = assertThrows(ExecutionException.class, () -> fx(() -> { app.saveTransaction(null); return null; }),
                    data.getName() + ": the save handler proceeds to the file chooser");
            assertInstanceOf(UnsupportedOperationException.class, chooser.getCause(), "headless glass has no file chooser");
            assertEquals(1, showTransaction(app).size(), data.getName() + ": the QR dialog opens");
        }
        assertTrue(alerts.isEmpty(), alerts.toString());
    }

    private record Fixture(Wallet wallet, Transaction raw) {}

    /** P2WPKH single-sig host wallet whose history holds the funding transaction, and an ordinarily signed spend of it. */
    private static Fixture fixture(AntiExfilKeystorePolicy policy) throws Exception {
        Keystore secret = Keystore.fromSeed(new DeterministicSeed(MNEMONIC, "", 0, DeterministicSeed.Type.BIP39),
                PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
        Wallet signer = new Wallet("signer");
        signer.setPolicyType(PolicyType.SINGLE_HD); signer.setScriptType(ScriptType.P2WPKH);
        signer.getKeystores().add(secret);
        signer.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, signer.getKeystores(), 1));
        Address address = signer.getFreshNode(KeyPurpose.RECEIVE).getAddress();
        byte[] previous = new byte[32]; Arrays.fill(previous, (byte)0x44);
        Transaction funding = new Transaction();
        funding.addInput(Sha256Hash.wrap(previous), 0, new Script(new byte[0]));
        funding.addOutput(100000, address);
        Transaction spend = new Transaction();
        spend.addInput(funding.getTxId(), 0, new Script(new byte[0]));
        spend.addOutput(90000, address);
        PSBT psbt = new PSBT(spend);
        psbt.getPsbtInputs().getFirst().setWitnessUtxo(funding.getOutputs().getFirst());
        psbt.addKeyPathInformation(signer);
        signer.sign(psbt);
        signer.finalise(psbt);

        Keystore watch = Keystore.fromSeed(new DeterministicSeed(MNEMONIC, "", 0, DeterministicSeed.Type.BIP39),
                PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
        watch.setSeed(null); watch.setMasterPrivateExtendedKey(null); watch.setSource(KeystoreSource.HW_AIRGAPPED);
        watch.setLabel(watch.getKeyDerivation().getMasterFingerprint());
        watch.setWalletModel(WalletModel.SEEDSIGNER); watch.setAntiExfilProfile(AntiExfilProfile.AEXT_V1); watch.setAntiExfilPolicy(policy);
        Wallet host = new Wallet("host-" + policy);
        host.setPolicyType(PolicyType.SINGLE_HD); host.setScriptType(ScriptType.P2WPKH);
        host.getKeystores().add(watch);
        host.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, host.getKeystores(), 1));
        host.checkWallet();
        host.updateTransactions(Map.of(funding.getTxId(), new BlockTransaction(funding.getTxId(), 100, new Date(), 0L, funding)));
        return new Fixture(host, psbt.extractTransaction());
    }

    private AppController appWithSelectedTab(TransactionData data) throws Exception {
        return fx(() -> {
            AppController app = new AppController();
            Tab tab = new Tab();
            tab.setGraphic(new Label(data.getName()));
            tab.setUserData(new TransactionTabData(TabData.TabType.TRANSACTION, null, data));
            TabPane tabs = new TabPane(tab);
            tabs.getSelectionModel().select(tab);
            StackPane rootStack = new StackPane(tabs);
            Stage stage = new Stage(); stage.setScene(new Scene(rootStack, 800, 600)); stage.show();
            stages.add(stage);
            set(AppController.class, app, "tabs", tabs);
            set(AppController.class, app, "rootStack", rootStack);
            return app;
        });
    }

    /** Fires File > Show Transaction as QR and closes (and records) any window it opens. */
    private List<String> showTransaction(AppController app) throws Exception {
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
        }, "a4-window-closer");
        closer.setDaemon(true);
        closer.start();
        try {
            fx(() -> { app.showTransaction(null); return null; });
        } finally {
            done.set(true);
            closer.join(2000);
        }
        return opened;
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
