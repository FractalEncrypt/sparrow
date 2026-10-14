package com.sparrowwallet.sparrow.transaction;

import com.google.common.eventbus.EventBus;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.antiexfil.*;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Independent adversarial review (DeepSeek, 2026-10-12) of the corrected candidate.
 *
 * Hypothesis under test: when a Required policy wallet is closed and re-bound through the
 * retained-authority path, HeadersController adds it to the signingWallet item list but not to
 * headersForm.getAvailableWallets() (the Wallet->Storage map). Because reloadVerifiedAntiExfilSignatures
 * and signAntiExfil resolve storage through that map, the retained Required wallet loses its storage:
 * proof restoration is skipped and a protected-signing session cannot start.
 *
 * The original assertion fails on 4c22bfea. Follow-up tests use real disposable Storage references,
 * completed public-only sessions, actual proof restoration and explicit policy transitions.
 */
class DeepseekRetainedStorageReviewTest {
    @TempDir Path temp;
    private static String previousHome;
    private Network previousNetwork;
    private Object previousServices;
    private Object previousEventBus;
    private JsonObject vector;
    private final List<Stage> stages = new ArrayList<>();
    private final List<HeadersController> controllers = new ArrayList<>();

    @BeforeAll static void toolkit() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        try { Platform.startup(ready::countDown); } catch(IllegalStateException alreadyStarted) { ready.countDown(); }
        ready.await(10, TimeUnit.SECONDS);
        Platform.setImplicitExit(false);
        previousHome = System.getProperty("sparrow.home");
        System.setProperty("sparrow.home", Files.createTempDirectory("sparrow-deepseek-retained-home-").toString());
    }

    @AfterAll static void restoreHome() {
        if(previousHome == null) System.clearProperty("sparrow.home"); else System.setProperty("sparrow.home", previousHome);
    }

    @BeforeEach void setup() throws Exception {
        previousNetwork = Network.get();
        Network.set(Network.TESTNET4);
        previousEventBus = get(EventManager.class, "SINGLETON");
        set(EventManager.class, null, "SINGLETON", new EventBus((error, context) -> { }));
        set(Config.class, null, "INSTANCE", new Config());
        previousServices = get(AppServices.class, "INSTANCE");
        AppServices.initialize(null, new InteractionServices() {
            @Override public Optional<ButtonType> showAlert(String title, String content, Alert.AlertType type, Node graphic, ButtonType... buttons) {
                return Optional.of(ButtonType.NO);
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
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void retainedRequiredWalletKeepsItsStorage() throws Exception {
        Wallet required = multisig(AntiExfilKeystorePolicy.REQUIRED);
        Wallet optional = multisig(AntiExfilKeystorePolicy.OPTIONAL);
        Storage requiredStorage = new Storage(new File(temp.toFile(), "required-retained.mv.db"));
        Storage optionalStorage = new Storage(new File(temp.toFile(), "optional-retained.mv.db"));
        PSBT unsigned = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()), false);

        Fixture f = fx(() -> {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("headers.fxml"));
            Parent root = loader.load();
            HeadersController controller = loader.getController();
            Stage stage = new Stage(); stage.setScene(new Scene(root, 1100, 900));
            TransactionData data = new TransactionData("retained-storage", unsigned);
            controller.setModel(new HeadersForm(data));
            stage.show(); root.applyCss(); root.layout();
            stages.add(stage); controllers.add(controller);
            return new Fixture(controller, data, stage);
        });

        // Both open: the Required wallet is bound. Register storage as the app would.
        postWallets(f, required, optional);
        fx(() -> {
            // Mirror the app sequence that establishes getSigningWallet() for an unsigned PSBT.
            EventManager.get().post(new com.sparrowwallet.sparrow.event.FinalizeTransactionEvent(unsigned, optional));
            assertSame(required, f.data.getSigningWallet(), "Required authority must be bound while both are open");
            f.data.getAvailableWallets().put(required, requiredStorage);
            f.data.getAvailableWallets().put(optional, optionalStorage);
            return null;
        });

        // The Required wallet is closed; the Optional duplicate stays open. The retained path must rebind Required.
        postWallets(f, optional);
        fx(() -> {
            assertSame(required, f.data.getSigningWallet(), "retained Required authority must be rebound");
            assertNotNull(f.data.getAvailableWallets().get(required),
                    "bound Required wallet must keep its storage so proof restoration and protected signing work");
            assertSame(requiredStorage, f.data.getAvailableWallets().get(required));
            return null;
        });
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void retainedStorageRestoresCompletedProofAndCreatesProtectedSession() throws Exception {
        Wallet required = multisig(AntiExfilKeystorePolicy.REQUIRED);
        Wallet optional = multisig(AntiExfilKeystorePolicy.OPTIONAL);
        Storage requiredStorage = new Storage(temp.resolve("required-proof.mv.db").toFile());
        Storage optionalStorage = new Storage(temp.resolve("optional-proof.mv.db").toFile());
        PSBT unsigned = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()), false);
        var completion = completedPublicSession(required, requiredStorage, unsigned);
        PSBT signed = new PSBT(completion.getSignedPsbt(), false);
        Fixture f = fixture(signed);
        postStoredWallets(f, Map.of(required, requiredStorage, optional, optionalStorage));
        fx(() -> {
            f.data.setSigningWallet(required);
            f.data.replaceVerifiedAntiExfilSignatures(Set.of());
            return null;
        });
        postStoredWallets(f, Map.of(optional, optionalStorage));
        fx(() -> {
            assertSame(required, f.data.getSigningWallet());
            assertSame(requiredStorage, f.data.getAvailableWallets().get(required));
            assertNotSame(optionalStorage, f.data.getAvailableWallets().get(required));
            Method reload = HeadersController.class.getDeclaredMethod("reloadVerifiedAntiExfilSignatures", Wallet.class);
            reload.setAccessible(true); reload.invoke(f.controller, required);
            assertEquals(completion.getVerifiedSignatures(), f.data.getVerifiedAntiExfilSignatures());
            assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                    AntiExfilPolicy.evaluateSignatureProvenance(required, signed, f.data.getVerifiedAntiExfilSignatures()));
            return null;
        });
        // The same storage lookup used by signAntiExfil admits a fresh unsigned session, not the Optional store.
        Storage retained = f.data.getAvailableWallets().get(required);
        assertEquals(requiredStorage.getWalletId(required), retained.getWalletId(required));
        var next = AntiExfilCoordinator.create(temp.resolve("next.aexs"), temp.resolve("next.aexj"),
                unsigned.getForExport().serialize(), required.getKeystores().getFirst(), AntiExfilNetwork.TESTNET4);
        assertEquals(AntiExfilStage.HOST_COMMIT, AntiExfilCodec.decode(next.getHostCommitMessage()).getStage());
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void closingAllQuarantinesAndDeliberateOptionalEditClearsRetainedStorage() throws Exception {
        Wallet required = multisig(AntiExfilKeystorePolicy.REQUIRED);
        Wallet optional = multisig(AntiExfilKeystorePolicy.OPTIONAL);
        Storage storage = new Storage(temp.resolve("authority.mv.db").toFile());
        Storage duplicate = new Storage(temp.resolve("duplicate.mv.db").toFile());
        PSBT unsigned = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()), false);
        Fixture f = fixture(unsigned);
        postStoredWallets(f, Map.of(required, storage, optional, duplicate));
        fx(() -> {
            EventManager.get().post(new com.sparrowwallet.sparrow.event.FinalizeTransactionEvent(f.data.getPsbt(), optional));
            assertSame(required, f.data.getSigningWallet());
            return null;
        });
        postStoredWallets(f, Map.of());
        fx(() -> { assertNull(f.data.getSigningWallet());assertTrue(f.data.getAvailableWallets().isEmpty());return null; });
        postStoredWallets(f, Map.of(optional, duplicate));
        fx(() -> {
            // An unsigned transaction is still editable after all wallets close; bind through its normal finalize event.
            EventManager.get().post(new com.sparrowwallet.sparrow.event.FinalizeTransactionEvent(f.data.getPsbt(), optional));
            assertSame(required, f.data.getSigningWallet());
            assertSame(storage, f.data.getAvailableWallets().get(required));
            Wallet before = required.copy();required.getKeystores().getFirst().setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
            EventManager.get().post(new com.sparrowwallet.sparrow.event.KeystoreAntiExfilPoliciesChangedEvent(
                    required, before, storage.getWalletId(required), List.of(required.getKeystores().getFirst())));
            Field field = HeadersController.class.getDeclaredField("retainedRequiredPolicyStorage");field.setAccessible(true);
            assertNull(field.get(f.controller), "Intentional policy downgrade clears cached authority storage");
            return null;
        });
    }

    private Fixture fixture(PSBT psbt) throws Exception {
        return fx(() -> {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("headers.fxml"));Parent root = loader.load();
            HeadersController controller = loader.getController();Stage stage = new Stage();stage.setScene(new Scene(root, 1100, 900));
            TransactionData data = new TransactionData("retained-storage-proof", psbt);controller.setModel(new HeadersForm(data));
            stage.show();root.applyCss();root.layout();stages.add(stage);controllers.add(controller);return new Fixture(controller, data, stage);
        });
    }

    private void postStoredWallets(Fixture f, Map<Wallet, Storage> wallets) throws Exception {
        fx(() -> {
            EventManager.get().post(new OpenWalletsEvent(f.stage(), List.of()) {
                @Override public Map<Wallet, Storage> getWalletsMap() { return new LinkedHashMap<>(wallets); }
                @Override public List<Wallet> getWallets() { return new ArrayList<>(wallets.keySet()); }
                @Override public Storage getStorage(Wallet wallet) { return wallets.get(wallet); }
            });return null;
        });
    }

    private AntiExfilCoordinator.Completion completedPublicSession(Wallet wallet, Storage storage, PSBT psbt) throws Exception {
        Keystore publicSigner = wallet.getKeystores().getFirst();
        Keystore privateSigner = Keystore.fromSeed(new DeterministicSeed(vector.getAsJsonObject("signer_a").get("mnemonic").getAsString(), "", 0, DeterministicSeed.Type.BIP39),
                PolicyType.MULTI_HD, publicSigner.getKeyDerivation().getDerivation());
        Path root = Storage.getStateDir().toPath().resolve("anti-exfil");
        String walletDirectory = Utils.bytesToHex(Sha256Hash.hash(storage.getWalletId(wallet).getBytes(StandardCharsets.UTF_8))).substring(0, 32);
        String identity = Utils.bytesToHex(AntiExfilCoordinator.getWalletKeyIdentity(publicSigner));
        Path session = root.resolve("sessions").resolve(walletDirectory).resolve(identity).resolve("public.aexs");
        Path journal = root.resolve("journals").resolve(identity + ".aexj");
        var coordinator = AntiExfilCoordinator.create(session, journal, psbt.getForExport().serialize(), publicSigner, AntiExfilNetwork.TESTNET4);
        var commit = AntiExfilCodec.decode(coordinator.getHostCommitMessage());BigInteger nonce = BigInteger.valueOf(1234);
        byte[] opening = ECKey.fromPrivate(nonce).getPubKey();
        var openings = commit.getSlots().stream().map(s -> new AntiExfilSlot(s.getInputIndex(), s.getSighashType(), s.getSignerPublicKey(), s.getMessageHash(), s.getCommitment(), opening, null, null)).toList();
        var reveal = AntiExfilCodec.decode(coordinator.acceptOpenings(AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_OPENINGS, commit.getSessionId(), commit.getPsbtDigest(), openings))));
        ECKey key = privateSigner.getExtendedMasterPrivateKey().getKey(KeyDerivation.parsePath(publicSigner.getKeyDerivation().getDerivationPath() + "/0/0"));
        BigInteger n = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
        List<AntiExfilSlot> signatures = new ArrayList<>();
        for(var slot : reveal.getSlots()) {
            assertArrayEquals(key.getPubKey(), slot.getSignerPublicKey());
            BigInteger tweak = new BigInteger(1, Utils.taggedHash("s2c/ecdsa/point", Utils.concat(opening, slot.getHostRandomness())));
            BigInteger k = nonce.add(tweak).mod(n);BigInteger r = new BigInteger(1, Arrays.copyOfRange(ECKey.fromPrivate(k).getPubKey(), 1, 33)).mod(n);
            BigInteger s = k.modInverse(n).multiply(new BigInteger(1, slot.getMessageHash()).add(r.multiply(key.getPrivKey()))).mod(n);
            if(s.compareTo(n.shiftRight(1)) > 0) s = n.subtract(s);
            byte[] signature = Utils.concat(Utils.bigIntegerToBytes(r, 32), Utils.bigIntegerToBytes(s, 32));
            signatures.add(new AntiExfilSlot(slot.getInputIndex(), slot.getSighashType(), slot.getSignerPublicKey(), slot.getMessageHash(), slot.getCommitment(), opening, null, signature));
        }
        var completion = coordinator.complete(AntiExfilCodec.encode(new AntiExfilMessage(commit.getNetwork(), AntiExfilStage.SIGNER_SIGNATURES, commit.getSessionId(), commit.getPsbtDigest(), signatures)));
        AntiExfilProvenanceStore.record(wallet, storage, session, new PSBT(completion.getSignedPsbt(), false));return completion;
    }

    private record Fixture(HeadersController controller, TransactionData data, Stage stage) { }

    private void postWallets(Fixture f, Wallet... wallets) throws Exception {
        fx(() -> {
            EventManager.get().post(new OpenWalletsEvent(f.stage(), List.of()) {
                @Override public Map<Wallet, Storage> getWalletsMap() {
                    Map<Wallet, Storage> map = new LinkedHashMap<>();
                    for(Wallet wallet : wallets) map.put(wallet, null);
                    return map;
                }
                @Override public List<Wallet> getWallets() { return List.of(wallets); }
            });
            return null;
        });
    }

    private Wallet multisig(AntiExfilKeystorePolicy policyA) throws Exception {
        Wallet wallet = new Wallet("retained-" + policyA);
        wallet.getKeystores().add(signer(vector.getAsJsonObject("signer_a"), policyA));
        wallet.getKeystores().add(signer(vector.getAsJsonObject("signer_b"), AntiExfilKeystorePolicy.OPTIONAL));
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        wallet.checkWallet();
        return wallet;
    }

    private static Keystore signer(JsonObject data, AntiExfilKeystorePolicy policy) throws Exception {
        Keystore keystore = Keystore.fromSeed(new DeterministicSeed(data.get("mnemonic").getAsString(), "", 0,
                DeterministicSeed.Type.BIP39), PolicyType.MULTI_HD,
                KeyDerivation.parsePath(data.get("account_derivation").getAsString()));
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

    private static <T> T fx(Callable<T> callable) throws Exception {
        FutureTask<T> task = new FutureTask<>(callable); Platform.runLater(task); return task.get(30, TimeUnit.SECONDS);
    }
}
