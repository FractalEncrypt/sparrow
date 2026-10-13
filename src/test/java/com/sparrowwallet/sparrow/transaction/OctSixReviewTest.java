package com.sparrowwallet.sparrow.transaction;

import com.google.common.eventbus.EventBus;
import com.google.common.eventbus.Subscribe;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.antiexfil.*;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTSignatureException;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.*;
import com.sparrowwallet.sparrow.event.OpenWalletsEvent;
import com.sparrowwallet.sparrow.event.PSBTCombinedEvent;
import com.sparrowwallet.sparrow.event.RequestConnectEvent;
import com.sparrowwallet.sparrow.event.PSBTFinalizedEvent;
import com.sparrowwallet.sparrow.event.ViewPSBTEvent;
import com.sparrowwallet.sparrow.io.Config;
import com.sparrowwallet.sparrow.io.Storage;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.layout.VBox;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.Stage;
import javafx.stage.Window;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * October review cases converted to repaired-behavior regressions; original vulnerable-behavior
 * evidence remains preserved in the independent assessment/review checkouts.
 * The E1 Optional-invalid cases still characterize an unresolved finding, not a passing repair claim.
 * Uses the same real path as SequentialProtectedCompletionTest:
 * EventBus -> AppController.viewPSBT -> handleTransactionMerge, with the real Drongo coordinator.
 * Testnet4 public test vectors only. Nothing is broadcast.
 */
public class OctSixReviewTest {
    private static final BigInteger N = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    private static final String FORGED_FINGERPRINT = "deadbeef";
    @TempDir Path temporary;
    private int ceremony;
    private static Network previousNetwork;
    private static String previousSparrowHome;

    @BeforeAll static void startFx() throws Exception {
        previousNetwork = Network.get();
        previousSparrowHome = System.getProperty("sparrow.home");
        System.setProperty("sparrow.home", Files.createTempDirectory("sparrow-oct6-review-home-").toString());
        Network.set(Network.TESTNET4);
        CountDownLatch started = new CountDownLatch(1);
        try { Platform.startup(started::countDown); }
        catch(IllegalStateException alreadyRunning) { started.countDown(); }
        assertTrue(started.await(15, TimeUnit.SECONDS));
        Platform.setImplicitExit(false);
    }

    @AfterAll static void restoreGlobalState() {
        if(previousNetwork != null) Network.set(previousNetwork);
        if(previousSparrowHome != null) System.setProperty("sparrow.home", previousSparrowHome);
        else System.clearProperty("sparrow.home");
    }

    // ---------------------------------------------------------------------------------------------
    // F1: forged Required derivations must be rejected through the actual in-tab merge check.
    // ---------------------------------------------------------------------------------------------

    /** 2-of-2, A Optional and B Required. A signs ordinarily, then B returns an ordinary (unproven) signature. */
    @Test void inTabScanRequiredOrdinarySignatureControlIsRejected() throws Exception {
        Fixture f = fixture("OR");
        PSBT aReturn = ordinarySign(copy(f.psbt), f, 0);
        PSBT bReturn = ordinarySign(copy(aReturn), f, 1);
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(aReturn, f.psbt, Set.of());
                assertEquals(1, h.observer.merges, h.alerts.toString());
                h.assertRejectedUnchanged(bReturn, aReturn, Set.of());
                assertTrue(h.alerts.toString().contains("REQUIRED_PROOF_MISSING"), h.alerts.toString());
                System.out.println("F1 control (B derivation intact): alerts=" + h.alerts);
            }
            return null;
        });
    }

    @Test void inTabScanForgedRequiredDerivationIsRejected() throws Exception {
        Fixture f = fixture("OR");
        PSBT aReturn = ordinarySign(copy(f.psbt), f, 0);
        PSBT bReturn = ordinarySign(copy(aReturn), f, 1);
        forgeDerivation(bReturn, f, 1);
        bReturn.verifySignatures(); // valid signature, unprotected Required return
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(aReturn, f.psbt, Set.of());
                assertEquals(1, h.observer.merges, h.alerts.toString());
                h.assertRejectedUnchanged(bReturn, aReturn, Set.of());
                assertTrue(h.alerts.toString().contains("REQUIRED_PROOF_MISSING"), h.alerts.toString());
                assertEquals(1, h.data.getPsbt().getPsbtInputs().getFirst().getPartialSignatures().size());
                assertFalse(h.data.getPsbt().isFinalized());
            }
            return null;
        });
    }

    /** 2-of-2 RR, no protected ceremony at all: both signatures ordinary, both derivations forged. */
    @Test void inTabScanForgedDerivationsCannotBypassRequiredRequired() throws Exception {
        Fixture f = fixture("RR");
        PSBT control = ordinarySign(ordinarySign(copy(f.psbt), f, 0), f, 1);
        PSBT forged = copy(control);
        forgeDerivation(forged, f, 0);
        forgeDerivation(forged, f, 1);
        forged.verifySignatures();
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.assertRejectedUnchanged(control, f.psbt, Set.of());
                h.alerts.clear();
                h.assertRejectedUnchanged(forged, f.psbt, Set.of());
                assertTrue(h.alerts.toString().contains("REQUIRED_PROOF_MISSING"), h.alerts.toString());
                assertTrue(h.data.getPsbt().getPsbtInputs().getFirst().getPartialSignatures().isEmpty());
            }
            return null;
        });
    }

    record SingleSig(Wallet host, PSBT tabPsbt, PSBT control, PSBT forged) {}

    /** Single-sig P2WPKH Required SeedSigner wallet; control = ordinary signature, forged = same with a relabelled derivation. */
    static SingleSig singleSig() throws Exception {
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        Keystore priv = Keystore.fromSeed(new DeterministicSeed(mnemonic, "", 0, DeterministicSeed.Type.BIP39),
                PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
        Wallet signer = new Wallet("ss-signer");
        signer.setPolicyType(PolicyType.SINGLE_HD);
        signer.setScriptType(ScriptType.P2WPKH);
        signer.getKeystores().add(priv);
        signer.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, signer.getKeystores(), 1));
        com.sparrowwallet.drongo.address.Address address = signer.getFreshNode(com.sparrowwallet.drongo.KeyPurpose.RECEIVE).getAddress();
        byte[] h = new byte[32];
        Arrays.fill(h, (byte)0x33);
        Transaction funding = new Transaction();
        funding.addInput(Sha256Hash.wrap(h), 0, new Script(new byte[0]));
        funding.addOutput(100000, address);
        Transaction spend = new Transaction();
        spend.addInput(funding.getTxId(), 0, new Script(new byte[0]));
        spend.addOutput(90000, address);
        PSBT unsigned = new PSBT(spend);
        unsigned.getPsbtInputs().getFirst().setWitnessUtxo(funding.getOutputs().getFirst());

        Keystore watch = priv.copy();
        watch.setSeed(null);
        watch.setMasterPrivateExtendedKey(null);
        watch.setSource(KeystoreSource.HW_AIRGAPPED);
        watch.setLabel("SeedSigner");
        watch.setWalletModel(WalletModel.SEEDSIGNER);
        watch.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);
        watch.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED);
        Wallet host = new Wallet("ss-host");
        host.setPolicyType(PolicyType.SINGLE_HD);
        host.setScriptType(ScriptType.P2WPKH);
        host.getKeystores().add(watch);
        host.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, host.getKeystores(), 1));
        host.checkWallet();
        unsigned.addKeyPathInformation(host);
        PSBT tabPsbt = copy(unsigned);
        assertTrue(host.canSign(tabPsbt));
        assertEquals(1, tabPsbt.getPsbtInputs().getFirst().getDerivedPublicKeys().size());

        PSBT control = copy(unsigned);
        signer.sign(control);
        PSBT forged = copy(control);
        PSBTInput input = forged.getPsbtInputs().getFirst();
        Map.Entry<ECKey, KeyDerivation> real = input.getDerivedPublicKeys().entrySet().iterator().next();
        input.getDerivedPublicKeys().put(real.getKey(), new KeyDerivation(FORGED_FINGERPRINT, real.getValue().getDerivationPath()));
        return new SingleSig(host, tabPsbt, control, forged);
    }

    /** Single-sig Required (the tester release's first qualified configuration): one forged derivation suffices. */
    @Test void inTabScanSingleSigRequiredForgedDerivationIsRejected() throws Exception {
        SingleSig ss = singleSig();
        ss.forged().verifySignatures();
        fx(() -> {
            try(Harness h = new Harness(ss.host(), copy(ss.tabPsbt()))) {
                h.assertRejectedUnchanged(ss.control(), ss.tabPsbt(), Set.of());
                h.alerts.clear();
                h.assertRejectedUnchanged(ss.forged(), ss.tabPsbt(), Set.of());
                assertTrue(h.alerts.toString().contains("REQUIRED_PROOF_MISSING"), h.alerts.toString());
                assertFalse(h.data.getPsbt().isFinalized());
            }
            return null;
        });
    }

    /** A valid retained proof for A cannot admit an unprotected Required signature from B. */
    @Test void forgedDerivationCannotHideBehindAnotherRequiredCosignersRetainedProof() throws Exception {
        Fixture f = fixture("RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        PSBT forgedB = ordinarySign(copy(a.signed), f, 1);
        forgeDerivation(forgedB, f, 1);
        PSBT forgedBoth = copy(forgedB);
        forgeDerivation(forgedBoth, f, 0);
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(a.signed, f.psbt, a.completion.getVerifiedSignatures());
                assertEquals(1, h.observer.merges, h.alerts.toString());
                h.assertRejectedUnchanged(forgedB, a.signed, Set.of());
                String first = h.alerts.toString();
                h.alerts.clear();
                h.assertRejectedUnchanged(forgedBoth, a.signed, Set.of());
                System.out.println("F1 bound: forged B only -> " + first + " ; forged A and B -> " + h.alerts);
                assertTrue(first.contains("REQUIRED_PROOF_MISSING"), first);
                assertTrue(h.alerts.toString().contains("REQUIRED_PROOF_MISSING"), h.alerts.toString());
            }
            return null;
        });
    }

    // ---------------------------------------------------------------------------------------------
    // F1b: the addendum's alternative A1 fix ("evaluate a copy after addKeyPathInformation") only
    //      back-fills inputs whose derivation map is entirely empty.
    // ---------------------------------------------------------------------------------------------
    @Test void authoritativeAttributionRejectsFullPartialStripAndForgery() throws Exception {
        Fixture f = fixture("OR");
        PSBT signed = ordinarySign(ordinarySign(copy(f.psbt), f, 0), f, 1);
        ECKey bKey = ECKey.fromPublicOnly(childKey(f.privateSigners.get(1)).getPubKey());

        PSBT full = copy(signed);
        full.getPsbtInputs().getFirst().getDerivedPublicKeys().clear();
        PSBT partial = copy(signed);
        partial.getPsbtInputs().getFirst().getDerivedPublicKeys().remove(bKey);
        PSBT forged = copy(signed);
        forgeDerivation(forged, f, 1);

        Map<String, PSBT> cases = new LinkedHashMap<>();
        cases.put("full-strip", full);
        cases.put("partial-strip (B only)", partial);
        cases.put("forged B", forged);
        Map<String, AntiExfilPolicy.ProvenanceStatus> after = new LinkedHashMap<>();
        for(Map.Entry<String, PSBT> entry : cases.entrySet()) {
            PSBT psbt = entry.getValue();
            AntiExfilPolicy.ProvenanceStatus before = AntiExfilPolicy.evaluateSignatureProvenance(f.wallet, psbt, Set.of());
            psbt.addKeyPathInformation(f.wallet);
            AntiExfilPolicy.ProvenanceStatus status = AntiExfilPolicy.evaluateSignatureProvenance(f.wallet, psbt, Set.of());
            after.put(entry.getKey(), status);
            System.out.println("F1b " + entry.getKey() + ": before=" + before + " afterAddKeyPathInformation=" + status
                    + " derivs=" + psbt.getPsbtInputs().getFirst().getDerivedPublicKeys().size()
                    + " hasRequiredSignature(getSignedKeystores)=" + AntiExfilPolicy.hasRequiredSignature(f.wallet, psbt));
            assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, before);
            assertTrue(AntiExfilPolicy.hasRequiredSignature(f.wallet, psbt));
        }
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, after.get("full-strip"));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, after.get("partial-strip (B only)"));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, after.get("forged B"));
    }

    // ---------------------------------------------------------------------------------------------
    // E1: erratum class "invalid finalized Optional signature" on the current stack.
    // ---------------------------------------------------------------------------------------------

    /** Merge path (handled by upstream verifyFinalizedSignatures at bdc8029): rejected. */
    @Test void finalizedInvalidOptionalSignatureMergeIsRejected() throws Exception {
        Fixture f = fixture("OO");
        PSBT finalized = invalidOptionalFinalized(f);
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.assertRejectedUnchanged(finalized, f.psbt, Set.of());
                System.out.println("E1 merge path: alerts=" + h.alerts);
                assertTrue(h.alerts.toString().contains("Invalid PSBT"), h.alerts.toString());
            }
            return null;
        });
    }

    /** Fresh import (no unfinalized matching tab): the only check is PSBT.verifySignatures(), which skips final fields. */
    @Test void finalizedInvalidOptionalSignatureFreshImportPredicates() throws Exception {
        Fixture f = fixture("OO");
        PSBT finalized = invalidOptionalFinalized(f);
        String witness = verifyFinalizedIfAvailable(copy(f.psbt), finalized);
        System.out.println("E1 upstream verifyFinalizedSignatures on the same PSBT: " + witness);
        assertTrue(witness.startsWith("invalid") || witness.equals("n/a"), witness);
        // AppController.addTransactionTab (8-arg) runs exactly these two checks before opening a new tab.
        finalized.verifySignatures();
        finalized.verifySigHashes();
        TransactionData data = new TransactionData("fresh import", finalized);
        data.setSigningWallet(f.wallet);
        AntiExfilPolicy.ProvenanceStatus status = AntiExfilPolicy.evaluatePsbtEgress(data);
        System.out.println("E1 fresh-import predicates OO: verifySignatures=ok verifySigHashes=ok evaluatePsbtEgress=" + status);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, status);

        // RO: A Required with a real protected proof, B Optional with an invalid signature.
        Fixture ro = fixture("RO");
        Run a = complete(ro.psbt, ro.privateSigners.get(0), ro.wallet.getKeystores().get(0));
        PSBT roFinalized = copy(a.signed);
        ECKey bKey = childKey(ro.privateSigners.get(1));
        roFinalized.getPsbtInputs().getFirst().getPartialSignatures().put(ECKey.fromPublicOnly(bKey.getPubKey()),
                bKey.sign(Sha256Hash.ZERO_HASH, SigHash.ALL, TransactionSignature.Type.ECDSA));
        ro.wallet.finalise(roFinalized);
        roFinalized = copy(roFinalized);
        TransactionData roData = new TransactionData("fresh import RO", roFinalized, a.completion.getVerifiedSignatures());
        roData.setSigningWallet(ro.wallet);
        AntiExfilPolicy.ProvenanceStatus roStatus = AntiExfilPolicy.evaluatePsbtEgress(roData);
        System.out.println("E1 fresh-import predicates RO (input has a Required participant): " + roStatus);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_RETURN_UNATTRIBUTABLE, roStatus);
    }

    /** Fresh import through the real event path into a new tab (no open tab holds this transaction). */
    @Test void finalizedInvalidOptionalSignatureOpensNewTabOnFreshImport() throws Exception {
        Fixture f = fixture("OO");
        PSBT finalized = invalidOptionalFinalized(f);
        PSBT unrelated = copy(f.psbt);
        unrelated.getTransaction().setLocktime(12345);
        PSBT unrelatedTab = copy(unrelated);
        fx(() -> {
            try(Harness h = new Harness(f.wallet, unrelatedTab)) {
                int before = h.tabs.getTabs().size();
                Throwable failure = null;
                try {
                    h.post(finalized, null, Set.of());
                } catch(Throwable t) { failure = t; }
                System.out.println("E1 event path: tabsBefore=" + before + " tabsAfter=" + h.tabs.getTabs().size()
                        + " alerts=" + h.alerts + " eventErrors=" + h.eventErrors + " failure=" + failure);
                Tab opened = h.tabs.getTabs().size() > before ? h.tabs.getTabs().getLast() : null;
                if(opened != null) {
                    TransactionData openedData = ((TransactionTabData)opened.getUserData()).getTransactionData();
                    System.out.println("E1 event path: new tab finalized=" + openedData.getPsbt().isFinalized()
                            + " signingWallet=" + openedData.getSigningWallet());
                }
                h.eventErrors.clear();
            }
            return null;
        });
    }

    // ---------------------------------------------------------------------------------------------
    // F1-GUI: the same in-tab scan with the real headers.fxml / HeadersController bound to the tab,
    //         then the real "Finalize Transaction" handler, then the Broadcast gate.
    // ---------------------------------------------------------------------------------------------
    static class Ctl extends HeadersController {
        final List<String> errors = new ArrayList<>();
        @Override boolean confirmProtectedFinalization() { return true; }
        @Override void protectedCompletionError(String message) { errors.add(message); }
    }

    @Test void guiInTabScanForgedRequiredDerivation() throws Exception { gui(true); }
    @Test void guiInTabScanRequiredControl() throws Exception { gui(false); }

    private void gui(boolean forge) throws Exception {
        Fixture f = fixture("OR");
        PSBT aReturn = ordinarySign(copy(f.psbt), f, 0);
        PSBT bReturn = ordinarySign(copy(aReturn), f, 1);
        if(forge) forgeDerivation(bReturn, f, 1);
        String label = forge ? "F1-GUI forged" : "F1-GUI control";
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                Field config = Config.class.getDeclaredField("INSTANCE");
                config.setAccessible(true);
                Object previousConfig = config.get(null);
                config.set(null, new Config());
                List<Integer> connects = new ArrayList<>();
                Object connectWatcher = new Object() {
                    @Subscribe public void connect(RequestConnectEvent event) { connects.add(1); }
                };
                EventManager.get().register(connectWatcher);
                try {
                    FXMLLoader loader = new FXMLLoader(OctSixReviewTest.class.getResource("headers.fxml"));
                    Ctl c = new Ctl();
                    loader.setControllerFactory(type -> c);
                    Parent root = loader.load();
                    Map<String, Object> ns = loader.getNamespace();
                    h.tab.setContent(root);
                    c.setModel(new HeadersForm(h.data));
                    h.stage.show();
                    root.applyCss();
                    root.layout();
                    EventManager.get().post(new OpenWalletsEvent(h.stage, List.of()) {
                        @Override public Map<Wallet, Storage> getWalletsMap() {
                            Map<Wallet, Storage> m = new LinkedHashMap<>(); m.put(f.wallet, null); return m;
                        }
                    });
                    // First cosigner (Optional) via the in-tab Scan QR event, exactly as HeadersController.scanPSBT posts it.
                    h.post(aReturn, h.data.getPsbt(), Set.of());
                    // Second cosigner (Required) via the in-tab Scan QR event.
                    h.post(bReturn, h.data.getPsbt(), Set.of());
                    System.out.println(label + " after in-tab scans: " + ui(h, ns) + " alerts=" + h.alerts);
                    Node boxNode = (Node)ns.get("protectedCompletionBox");
                    String boxText = boxNode instanceof VBox vbox && !vbox.getChildren().isEmpty()
                            && vbox.getChildren().getFirst() instanceof Label l ? l.getText() : String.valueOf(boxNode);
                    System.out.println(label + " protectedCompletionBox label='" + boxText + "' visible=" + boxNode.isVisible());
                    c.finalizeProtectedTransaction(null);
                    Method require = HeadersController.class.getDeclaredMethod("requirePermittedProvenance", String.class);
                    require.setAccessible(true);
                    int alertsBefore = h.alerts.size();
                    boolean broadcastAllowed = (Boolean)require.invoke(c, "broadcast");
                    System.out.println(label + " after Finalize: " + ui(h, ns) + " controllerErrors=" + c.errors
                            + " requirePermittedProvenance(broadcast)=" + broadcastAllowed
                            + " newAlerts=" + h.alerts.subList(alertsBefore, h.alerts.size()));
                    assertEquals(1, h.observer.merges);
                    assertTrue(h.alerts.toString().contains("REQUIRED_PROOF_MISSING"), h.alerts.toString());
                    assertFalse(h.data.getPsbt().isFinalized());
                    assertEquals(1, h.data.getPsbt().getPsbtInputs().getFirst().getPartialSignatures().size());
                    assertFalse(c.errors.isEmpty(), "Finalize refused: only the Optional signature is present");
                    assertTrue(connects.isEmpty(), "no network connect requested");
                } finally {
                    EventManager.get().unregister(connectWatcher);
                    config.set(null, previousConfig);
                }
                h.eventErrors.clear();
            }
            return null;
        });
    }

    private static String ui(Harness h, Map<String, Object> ns) {
        java.util.function.Function<String, Node> n = id -> (Node)ns.get(id);
        return "boundWallet=" + (h.data.getSigningWallet() == null ? null : h.data.getSigningWallet().getName())
                + " finalized=" + h.data.getPsbt().isFinalized()
                + " partialSigs=" + (h.data.getPsbt().isFinalized() ? "final" : String.valueOf(h.data.getPsbt().getPsbtInputs().getFirst().getPartialSignatures().size()))
                + " status=" + HeadersController.evaluateTransactionProvenance(h.data)
                + " warningVisible=" + n.apply("provenanceWarning").isVisible()
                + " broadcastBoxVisible=" + n.apply("broadcastButtonBox").isVisible()
                + " broadcastDisabled=" + n.apply("broadcastButton").isDisabled()
                + " viewFinalDisabled=" + n.apply("viewFinalButton").isDisabled()
                + " savePsbtDisabled=" + n.apply("savePsbtButton").isDisabled()
                + " signedKeystoresShown=" + h.data.getSignatureKeystoreMap().values().stream()
                .map(k -> k.getKeyDerivation().getMasterFingerprint() + ":" + k.getAntiExfilPolicy()).toList();
    }

    // ---------------------------------------------------------------------------------------------
    // helpers (patterned on SequentialProtectedCompletionTest)
    // ---------------------------------------------------------------------------------------------

    /** PSBT.verifyFinalizedSignatures exists from upstream Drongo 22d2c90 (in bdc8029, not in 948f586). */
    private static String verifyFinalizedIfAvailable(PSBT base, PSBT finalized) {
        try {
            Method m = PSBT.class.getMethod("verifyFinalizedSignatures", PSBT.class);
            m.invoke(base, finalized);
            return "valid";
        } catch(NoSuchMethodException e) {
            return "n/a";
        } catch(java.lang.reflect.InvocationTargetException e) {
            return "invalid: " + e.getCause().getMessage();
        } catch(IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }

    private PSBT invalidOptionalFinalized(Fixture f) throws Exception {
        PSBT finalized = ordinarySign(copy(f.psbt), f, 0);
        ECKey b = childKey(f.privateSigners.get(1));
        finalized.getPsbtInputs().getFirst().getPartialSignatures().put(ECKey.fromPublicOnly(b.getPubKey()),
                b.sign(Sha256Hash.ZERO_HASH, SigHash.ALL, TransactionSignature.Type.ECDSA));
        f.wallet.finalise(finalized);
        assertTrue(finalized.isFinalized());
        return copy(finalized);
    }

    static PSBT ordinarySign(PSBT psbt, Fixture f, int signer) throws Exception {
        ECKey key = childKey(f.privateSigners.get(signer));
        PSBTInput input = psbt.getPsbtInputs().getFirst();
        input.getPartialSignatures().put(ECKey.fromPublicOnly(key.getPubKey()),
                key.sign(input.getSigningHash(), SigHash.ALL, TransactionSignature.Type.ECDSA));
        return psbt;
    }

    static void forgeDerivation(PSBT psbt, Fixture f, int signer) throws Exception {
        ECKey pub = ECKey.fromPublicOnly(childKey(f.privateSigners.get(signer)).getPubKey());
        PSBTInput input = psbt.getPsbtInputs().getFirst();
        KeyDerivation real = input.getDerivedPublicKeys().get(pub);
        assertNotNull(real, "fixture carries the real derivation");
        input.getDerivedPublicKeys().put(pub, new KeyDerivation(FORGED_FINGERPRINT, real.getDerivationPath()));
    }

    private static List<String> signedBy(Wallet wallet, PSBT psbt) {
        List<String> out = new ArrayList<>();
        wallet.getSignedKeystores(psbt).values().forEach(map -> map.values().forEach(k ->
                out.add(k.getKeyDerivation().getMasterFingerprint() + ":" + k.getAntiExfilPolicy())));
        return out;
    }

    static Fixture fixture(String policies) throws Exception {
        JsonObject vector;
        try(var reader = new InputStreamReader(OctSixReviewTest.class.getResourceAsStream(
                "/com/sparrowwallet/sparrow/io/protocol-v1-mixed-provenance-vector.json"), StandardCharsets.UTF_8)) {
            vector = JsonParser.parseReader(reader).getAsJsonObject();
        }
        List<Keystore> signers = new ArrayList<>();
        for(String name : List.of("signer_a", "signer_b")) {
            JsonObject signer = vector.getAsJsonObject(name);
            signers.add(Keystore.fromSeed(new DeterministicSeed(signer.get("mnemonic").getAsString(), "", 0,
                    DeterministicSeed.Type.BIP39), PolicyType.MULTI_HD,
                    KeyDerivation.parsePath(signer.get("account_derivation").getAsString())));
        }
        Wallet wallet = new Wallet("public deterministic regression");
        for(int i = 0; i < 2; i++) {
            Keystore publicSigner = signers.get(i).copy();
            publicSigner.setSeed(null);
            publicSigner.setMasterPrivateExtendedKey(null);
            publicSigner.setSource(KeystoreSource.HW_AIRGAPPED);
            publicSigner.setLabel("Signer " + i);
            publicSigner.setWalletModel(i == 1 ? WalletModel.KERN : WalletModel.SEEDSIGNER);
            publicSigner.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);
            publicSigner.setAntiExfilPolicy(policies.charAt(i) == 'R'
                    ? AntiExfilKeystorePolicy.REQUIRED : AntiExfilKeystorePolicy.OPTIONAL);
            wallet.getKeystores().add(publicSigner);
        }
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        PSBT psbt = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()), false);
        psbt.getPsbtInputs().getFirst().getPartialSignatures().clear();
        psbt = copy(psbt);
        wallet.checkWallet();
        assertTrue(wallet.canSign(psbt), "real wallet attribution must apply");
        assertEquals(2, psbt.getPsbtInputs().getFirst().getDerivedPublicKeys().size());
        return new Fixture(wallet, psbt, signers);
    }

    private Run complete(PSBT original, Keystore privateSigner, Keystore publicSigner) throws Exception {
        int id = ++ceremony;
        Path session = temporary.resolve("ceremony-" + id + ".aexs");
        Path journal = temporary.resolve("ceremony-" + id + ".aexj");
        Method create = AntiExfilCoordinator.class.getDeclaredMethod("create", Path.class, Path.class,
                byte[].class, Keystore.class, AntiExfilNetwork.class, boolean.class, SecureRandom.class);
        create.setAccessible(true);
        AntiExfilCoordinator coordinator = (AntiExfilCoordinator)create.invoke(null, session, journal,
                original.getForExport().serialize(), publicSigner, AntiExfilNetwork.TESTNET4, false,
                new DeterministicRandom(id));
        AntiExfilMessage commit = AntiExfilCodec.decode(coordinator.getHostCommitMessage());
        BigInteger nonce = BigInteger.valueOf(1000L + id);
        byte[] opening = ECKey.fromPrivate(nonce).getPubKey();
        List<AntiExfilSlot> openings = commit.getSlots().stream().map(slot -> slot(slot, opening, null)).toList();
        byte[] revealed = coordinator.acceptOpenings(AntiExfilCodec.encode(message(commit,
                AntiExfilStage.SIGNER_OPENINGS, openings)));
        AntiExfilMessage reveal = AntiExfilCodec.decode(revealed);
        ECKey privateKey = childKey(privateSigner);
        List<AntiExfilSlot> signatures = new ArrayList<>();
        for(AntiExfilSlot slot : reveal.getSlots()) {
            BigInteger tweak = new BigInteger(1, Utils.taggedHash("s2c/ecdsa/point",
                    Utils.concat(opening, slot.getHostRandomness())));
            BigInteger k = nonce.add(tweak).mod(N);
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(ECKey.fromPrivate(k).getPubKey(), 1, 33)).mod(N);
            BigInteger s = k.modInverse(N).multiply(new BigInteger(1, slot.getMessageHash())
                    .add(r.multiply(privateKey.getPrivKey()))).mod(N);
            if(s.compareTo(N.shiftRight(1)) > 0) s = N.subtract(s);
            byte[] compact = Utils.concat(Utils.bigIntegerToBytes(r, 32), Utils.bigIntegerToBytes(s, 32));
            signatures.add(slot(slot, opening, compact));
        }
        AntiExfilCoordinator.Completion completion = coordinator.complete(AntiExfilCodec.encode(
                message(commit, AntiExfilStage.SIGNER_SIGNATURES, signatures)));
        return new Run(completion, new PSBT(completion.getSignedPsbt(), false));
    }

    private static ECKey childKey(Keystore signer) throws MnemonicException {
        return signer.getExtendedMasterPrivateKey().getKey(KeyDerivation.parsePath(
                signer.getKeyDerivation().getDerivationPath() + "/0/0"));
    }
    private static AntiExfilSlot slot(AntiExfilSlot source, byte[] opening, byte[] signature) {
        return new AntiExfilSlot(source.getInputIndex(), source.getSighashType(), source.getSignerPublicKey(),
                source.getMessageHash(), source.getCommitment(), opening, null, signature);
    }
    private static AntiExfilMessage message(AntiExfilMessage source, AntiExfilStage stage, List<AntiExfilSlot> slots) {
        return new AntiExfilMessage(source.getNetwork(), stage, source.getSessionId(), source.getPsbtDigest(), slots);
    }
    static PSBT copy(PSBT psbt) throws Exception { return new PSBT(psbt.serialize(), false); }
    static <T> T fx(Callable<T> callable) throws Exception {
        FutureTask<T> task = new FutureTask<>(callable);
        Platform.runLater(task);
        try {
            return task.get(60, TimeUnit.SECONDS);
        } catch(ExecutionException e) {
            if(e.getCause() instanceof Exception ex) throw ex;
            if(e.getCause() instanceof Error err) throw err;
            throw e;
        }
    }
    record Fixture(Wallet wallet, PSBT psbt, List<Keystore> privateSigners) {}
    private record Run(AntiExfilCoordinator.Completion completion, PSBT signed) {}
    private static final class DeterministicRandom extends SecureRandom {
        private final int id;
        private int call;
        DeterministicRandom(int id) { this.id = id; }
        @Override public void nextBytes(byte[] bytes) { Arrays.fill(bytes, (byte)(id * 3 + ++call)); }
    }
    public static final class Observer {
        int merges;
        int finalizations;
        @Subscribe public void combined(PSBTCombinedEvent event) { merges++; }
        @Subscribe public void finalized(PSBTFinalizedEvent event) { finalizations++; }
    }
    static final class Harness implements AutoCloseable {
        final AppController controller = new AppController();
        final Stage stage = new Stage();
        final TabPane tabs;
        final Tab tab = new Tab();
        final TransactionData data;
        final Observer observer = new Observer();
        final List<String> alerts = new ArrayList<>();
        final List<Throwable> eventErrors = new ArrayList<>();
        final Field eventBusField;
        final Object previousEventBus;
        final Field servicesField;
        final Object previousServices;
        Harness(Wallet wallet, PSBT original) throws Exception {
            eventBusField = EventManager.class.getDeclaredField("SINGLETON");
            eventBusField.setAccessible(true);
            previousEventBus = eventBusField.get(null);
            servicesField = AppServices.class.getDeclaredField("INSTANCE");
            servicesField.setAccessible(true);
            previousServices = servicesField.get(null);
            eventBusField.set(null, new EventBus((error, context) -> eventErrors.add(error)));
            AppServices.initialize(null, new InteractionServices() {
                @Override public Optional<ButtonType> showAlert(String title, String content,
                        Alert.AlertType type, Node graphic, ButtonType... buttons) {
                    alerts.add(title + ": " + content);
                    return Optional.of(ButtonType.OK);
                }
                @Override public Optional<String> requestPassphrase(String walletName, Keystore signer) {
                    throw new AssertionError("No real secrets may be requested");
                }
            });
            EventManager.get().unregister(AppServices.get());
            Field windows = AppServices.class.getDeclaredField("walletWindows");
            windows.setAccessible(true);
            @SuppressWarnings("unchecked") Map<Window, List<WalletTabData>> map =
                    (Map<Window, List<WalletTabData>>)windows.get(AppServices.get());
            map.put(stage, List.of(new WalletTabData(TabData.TabType.WALLET, null) {
                @Override public Wallet getWallet() { return wallet; }
                @Override public Storage getStorage() { return null; }
            }));
            data = new TransactionData("regression", original);
            data.setSigningWallet(wallet);
            tab.setGraphic(new Label("regression"));
            tab.setUserData(new TransactionTabData(TabData.TabType.TRANSACTION, null, data));
            tabs = new TabPane(tab);
            stage.setScene(new Scene(tabs));
            Field field = AppController.class.getDeclaredField("tabs");
            field.setAccessible(true);
            field.set(controller, tabs);
            EventManager.get().register(controller);
            EventManager.get().register(observer);
        }
        void post(PSBT signed, PSBT context, Set<VerifiedAntiExfilSignature> proofs) {
            EventManager.get().post(new ViewPSBTEvent(stage, null, null, signed, context,
                    TransactionView.HEADERS, null, proofs));
        }
        void assertRejectedUnchanged(PSBT incoming, PSBT context, Set<VerifiedAntiExfilSignature> proofs) {
            byte[] before = data.getPsbt().serialize();
            Set<VerifiedAntiExfilSignature> retained = Set.copyOf(data.getVerifiedAntiExfilSignatures());
            int merges = observer.merges;
            int finalizations = observer.finalizations;
            int tabCount = tabs.getTabs().size();
            post(incoming, context, proofs);
            assertEquals(merges, observer.merges, alerts.toString());
            assertEquals(finalizations, observer.finalizations);
            assertEquals(tabCount, tabs.getTabs().size());
            assertArrayEquals(before, data.getPsbt().serialize());
            assertEquals(retained, data.getVerifiedAntiExfilSignatures());
            assertFalse(alerts.isEmpty(), "the rejected return must be reported");
        }
        @Override public void close() throws Exception {
            EventManager.get().unregister(controller);
            EventManager.get().unregister(observer);
            stage.close();
            servicesField.set(null, previousServices);
            eventBusField.set(null, previousEventBus);
            assertTrue(eventErrors.isEmpty(), eventErrors.toString());
        }
    }
}
