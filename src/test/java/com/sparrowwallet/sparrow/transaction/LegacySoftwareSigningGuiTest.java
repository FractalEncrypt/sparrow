package com.sparrowwallet.sparrow.transaction;

import com.google.common.eventbus.EventBus;
import com.google.gson.*;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.antiexfil.*;
import com.sparrowwallet.drongo.policy.*;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.*;
import com.sparrowwallet.sparrow.control.QRScanDialog;
import com.sparrowwallet.sparrow.io.*;
import javafx.animation.*;
import javafx.fxml.FXMLLoader;
import javafx.scene.*;
import javafx.scene.control.DialogPane;
import javafx.stage.*;
import javafx.util.Duration;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;
import static com.sparrowwallet.sparrow.transaction.ProtectedCompletionGuiTest.*;

/** Production FXML/controller signing, public test seeds, isolated state and no network/device services. */
class LegacySoftwareSigningGuiTest {
    private static final String A = "model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast";
    private static final String B = "abandon amount liar amount expire adjust cage candy arch gather drum buyer";
    @TempDir Path temp;
    private Network previousNetwork;
    private String oldHome, homeProperty;
    private final List<View> views = new ArrayList<>();
    private final List<Throwable> eventErrors = new CopyOnWriteArrayList<>();
    private final List<String> alerts = new ArrayList<>();

    @BeforeAll static void startup() throws Exception { toolkit(); }
    @BeforeEach void setup() throws Exception {
        previousNetwork = Network.get(); Network.set(Network.TESTNET4);
        homeProperty = ApplicationDir.getHomeProperty(SparrowWallet.APP_NAME);
        oldHome = System.getProperty(homeProperty); System.setProperty(homeProperty, temp.toString());
        set(EventManager.class, null, "SINGLETON", new EventBus((e,c) -> eventErrors.add(e)));
        set(Config.class, null, "INSTANCE", new Config());
        var constructor = AppServices.class.getDeclaredConstructor(javafx.application.Application.class, InteractionServices.class);
        constructor.setAccessible(true);
        Object services = constructor.newInstance(null, new InteractionServices() {
            @Override public Optional<javafx.scene.control.ButtonType> showAlert(String title, String content, javafx.scene.control.Alert.AlertType type, Node graphic, javafx.scene.control.ButtonType... buttons) {
                alerts.add(title+" "+content); return Optional.empty();
            }
            @Override public Optional<String> requestPassphrase(String name, Keystore key) { fail("No passphrase dialog expected"); return Optional.empty(); }
        });
        set(AppServices.class, null, "INSTANCE", services); EventManager.get().unregister(services);
    }
    @AfterEach void cleanup() throws Exception {
        fx(() -> { for(View v : views) { v.controller.close(); v.stage.close(); } return null; });
        try(var files = Files.walk(temp)) {
            assertFalse(files.anyMatch(p -> p.toString().endsWith(".aexs") || p.toString().endsWith(".aexj")),
                    "Ordinary signing must not create AE session/history files");
        }
        if(oldHome == null) System.clearProperty(homeProperty); else System.setProperty(homeProperty, oldHome);
        Network.set(previousNetwork); assertTrue(eventErrors.isEmpty(), eventErrors.toString());
    }
    private static DeterministicSeed seed(String words) throws Exception {
        return new DeterministicSeed(words, "", 0, DeterministicSeed.Type.BIP39);
    }
    private Keystore key(String words, String path, PolicyType type, AntiExfilKeystorePolicy policy, boolean privateKey) throws Exception {
        Keystore key = Keystore.fromSeed(seed(words), type, KeyDerivation.parsePath(path));
        key.setLabel(key.getKeyDerivation().getMasterFingerprint());
        if(!privateKey) { key.setSeed(null); key.setMasterPrivateExtendedKey(null); key.setSource(KeystoreSource.HW_AIRGAPPED); key.setWalletModel(WalletModel.KERN); }
        key.setAntiExfilProfile(AntiExfilProfile.AEXT_V1); key.setAntiExfilPolicy(policy); return key;
    }
    private Wallet wallet(List<Keystore> keys, boolean multi) throws Exception {
        Wallet wallet = new Wallet("Public isolated F6 regression");
        wallet.setPolicyType(multi ? PolicyType.MULTI_HD : PolicyType.SINGLE_HD);
        wallet.setScriptType(multi ? ScriptType.P2WSH : ScriptType.P2WPKH); wallet.getKeystores().addAll(keys);
        wallet.setDefaultPolicy(Policy.getPolicy(wallet.getPolicyType(), wallet.getScriptType(), keys, multi ? 2 : 1));
        wallet.checkWallet(); return wallet;
    }
    private record View(HeadersController controller, TransactionData data, Stage stage) {}
    private View view(Wallet wallet, byte[] bytes) throws Exception {
        return fx(() -> {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("headers.fxml")); Parent root = loader.load();
            HeadersController controller = loader.getController();
            TransactionData data = new TransactionData("public-f6.psbt", new PSBT(bytes, false));
            Stage stage = new Stage(); stage.setScene(new Scene(root,1100,850));
            controller.setModel(new HeadersForm(data)); data.setSigningWallet(wallet);
            data.getAvailableWallets().put(wallet, new Storage(temp.resolve("unused-wallet.mv.db").toFile()) {
                @Override public String getWalletId(Wallet ignored) { return "isolated-public-f6"; }
            });
            stage.show(); root.applyCss(); root.layout(); View v = new View(controller,data,stage); views.add(v); return v;
        });
    }
    private byte[] singlePsbt() throws Exception {
        try(var input = getClass().getResourceAsStream("offline-singlesig-A-first.psbt")) { return input.readAllBytes(); }
    }
    private List<String> invoke(View v, String name, Class<?> argumentType, Object argument) throws Exception {
        return fx(() -> {
            List<String> dialogs = new ArrayList<>();
            alerts.clear();
            Timeline dismiss = new Timeline(new KeyFrame(Duration.millis(50), e -> {
                for(Window window : new ArrayList<>(Window.getWindows())) {
                    if(window == v.stage || window.getScene() == null) continue;
                    Node node = window.getScene().getRoot().lookup(".dialog-pane");
                    if(node instanceof DialogPane pane) { dialogs.add(pane.getHeaderText()+" "+pane.getContentText()); window.hide(); }
                }
            }));
            dismiss.setCycleCount(300); dismiss.play();
            try { Method method = HeadersController.class.getDeclaredMethod(name, argumentType); method.setAccessible(true); method.invoke(v.controller, argument); }
            finally { dismiss.stop(); }
            dialogs.addAll(alerts); return dialogs;
        });
    }
    private void ordinary(View v, int signatures) throws Exception {
        fx(() -> {
            v.data.getPsbt().verifySignatures();
            assertEquals(signatures, v.data.getPsbt().getPsbtInputs().getFirst().getPartialSignatures().size());
            assertTrue(v.data.getVerifiedAntiExfilSignatures().isEmpty()); assertFalse(v.data.hasProtectedSigningContext());
            assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, AntiExfilPolicy.evaluatePsbtEgress(v.data)); return null;
        });
    }
    @Test void scannedSeedLegacyMetadata() throws Exception { scannedSeedSignsOrdinarily(AntiExfilKeystorePolicy.REQUIRED); }
    @Test void scannedSeedEnabledMetadata() throws Exception { scannedSeedSignsOrdinarily(AntiExfilKeystorePolicy.OPTIONAL); }
    @Test void scannedSeedUnsupportedMetadata() throws Exception { scannedSeedSignsOrdinarily(AntiExfilKeystorePolicy.UNSUPPORTED); }
    private void scannedSeedSignsOrdinarily(AntiExfilKeystorePolicy policy) throws Exception {
        for(WalletModel model : List.of(WalletModel.SEEDSIGNER, WalletModel.KERN)) {
            Keystore watch = key(A,"m/84'/1'/0'",PolicyType.SINGLE_HD,policy,false); watch.setWalletModel(model);
            Wallet wallet = wallet(List.of(watch),false); View v = view(wallet,singlePsbt()); DeterministicSeed input = seed(A);
            assertTrue(invoke(v,"signFromSeed",DeterministicSeed.class,input).isEmpty()); ordinary(v,1);
            assertTrue(input.getMnemonicCode().isEmpty(),"Scanned seed cleared on exit"); assertFalse(watch.hasPrivateKey());
            assertEquals(policy,watch.getAntiExfilPolicy(),"Ordinary signing does not rewrite legacy metadata");
        }
    }
    @Test void softwareSignButtonLegacyMetadata() throws Exception { softwareSignButtonOrdinary(AntiExfilKeystorePolicy.REQUIRED); }
    @Test void softwareSignButtonEnabledMetadata() throws Exception { softwareSignButtonOrdinary(AntiExfilKeystorePolicy.OPTIONAL); }
    @Test void softwareSignButtonUnsupportedMetadata() throws Exception { softwareSignButtonOrdinary(AntiExfilKeystorePolicy.UNSUPPORTED); }
    private void softwareSignButtonOrdinary(AntiExfilKeystorePolicy policy) throws Exception {
        Keystore signer=key(A,"m/84'/1'/0'",PolicyType.SINGLE_HD,policy,true);
        View v=view(wallet(List.of(signer),false),singlePsbt());
        assertTrue(invoke(v,"signPSBT",javafx.event.ActionEvent.class,new javafx.event.ActionEvent()).isEmpty()); ordinary(v,1);
    }
    @Test void wrongScannedSeedIsRefusedAndCleared() throws Exception {
        View v=view(wallet(List.of(key(A,"m/84'/1'/0'",PolicyType.SINGLE_HD,AntiExfilKeystorePolicy.REQUIRED,false)),false),singlePsbt());
        byte[] before=v.data.getPsbt().serialize(); DeterministicSeed wrong=seed(B);
        List<String> errors=invoke(v,"signFromSeed",DeterministicSeed.class,wrong);
        assertTrue(errors.stream().anyMatch(e->e.contains("does not match")),errors.toString());
        assertArrayEquals(before,v.data.getPsbt().serialize()); assertTrue(wrong.getMnemonicCode().isEmpty()); ordinary(v,0);
    }
    @Test void matchingFingerprintWithDifferentAccountDoesNotSignTheFixture() throws Exception {
        View v=view(wallet(List.of(key(A,"m/84'/1'/1'",PolicyType.SINGLE_HD,AntiExfilKeystorePolicy.REQUIRED,false)),false),singlePsbt());
        DeterministicSeed input=seed(A); assertTrue(invoke(v,"signFromSeed",DeterministicSeed.class,input).isEmpty());
        ordinary(v,0); assertTrue(input.getMnemonicCode().isEmpty());
    }
    @Test void legacyMultisigSignsOnlyTheScannedParticipantThenAcceptsTheSecond() throws Exception {
        JsonObject vector;
        try(var reader=new InputStreamReader(getClass().getResourceAsStream("/com/sparrowwallet/sparrow/io/protocol-v1-mixed-provenance-vector.json"),StandardCharsets.UTF_8)) { vector=JsonParser.parseReader(reader).getAsJsonObject(); }
        JsonObject a=vector.getAsJsonObject("signer_a"),b=vector.getAsJsonObject("signer_b");
        Wallet wallet=wallet(List.of(key(a.get("mnemonic").getAsString(),a.get("account_derivation").getAsString(),PolicyType.MULTI_HD,AntiExfilKeystorePolicy.REQUIRED,false),key(b.get("mnemonic").getAsString(),b.get("account_derivation").getAsString(),PolicyType.MULTI_HD,AntiExfilKeystorePolicy.REQUIRED,false)),true);
        PSBT unsigned = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()),false);
        unsigned.getPsbtInputs().forEach(input -> input.getPartialSignatures().clear());
        View v=view(wallet,unsigned.serialize());
        assertTrue(invoke(v,"signFromSeed",DeterministicSeed.class,seed(a.get("mnemonic").getAsString())).isEmpty()); ordinary(v,1); assertFalse(v.data.getPsbt().isSigned());
        assertTrue(invoke(v,"signFromSeed",DeterministicSeed.class,seed(b.get("mnemonic").getAsString())).isEmpty()); ordinary(v,2); assertTrue(v.data.getPsbt().isSigned());
        assertTrue(wallet.getKeystores().stream().noneMatch(Keystore::hasPrivateKey));
    }
    @Test void protectedScannerCannotTreatAnOrdinaryPsbtOrSeedAsAnAeReply() throws Exception {
        List<String> errors=new ArrayList<>();
        for(AntiExfilStage stage:List.of(AntiExfilStage.SIGNER_OPENINGS,AntiExfilStage.SIGNER_SIGNATURES)) {
            assertTrue(AntiExfilQrExchange.decodeScanResult(Optional.of(new QRScanDialog.Result(new PSBT(singlePsbt(),false))),stage,AntiExfilNetwork.TESTNET4,errors::add).isEmpty());
            DeterministicSeed input=seed(A);
            assertTrue(AntiExfilQrExchange.decodeScanResult(Optional.of(new QRScanDialog.Result(input)),stage,AntiExfilNetwork.TESTNET4,errors::add).isEmpty()); input.clear();
        }
        assertEquals(4,errors.size());
    }
}
