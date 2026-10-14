package com.sparrowwallet.sparrow.transaction;

import com.google.common.eventbus.EventBus;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator;
import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.antiexfil.VerifiedAntiExfilSignature;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.psbt.PSBTOutput;
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

import java.io.File;
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
 * A1: a Required keystore's signature must not escape protected-signing policy because the returned PSBT
 * omits (or relabels) its BIP32 derivations. Attribution has to come from the bound wallet, the way
 * Wallet.getSignedKeystores already attributes it, on every route: the tab quarantine and egress gates,
 * fresh File/QR/drag-drop imports, and the cross-window ViewPSBTEvent admission check.
 * Testnet4 public fixtures only; nothing connects or broadcasts.
 */
class AntiExfilAttributionRegressionTest {
    private static final String SS_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    @TempDir Path temp;
    private static String previousHome;
    private Network previousNetwork;
    private Object previousServices;
    private Object previousEventBus;
    private JsonObject vector;
    private byte[] signed;
    private Set<VerifiedAntiExfilSignature> proofA;
    private Alerts alerts;
    private final List<Throwable> eventErrors = new CopyOnWriteArrayList<>();
    private final List<Stage> stages = new ArrayList<>();
    private final List<HeadersController> controllers = new ArrayList<>();

    @BeforeAll static void toolkit() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        try { Platform.startup(ready::countDown); } catch(IllegalStateException alreadyStarted) { ready.countDown(); }
        assertTrue(ready.await(10, TimeUnit.SECONDS));
        Platform.setImplicitExit(false);
        previousHome = System.getProperty("sparrow.home");
        System.setProperty("sparrow.home", Files.createTempDirectory("sparrow-a1-regression-home-").toString());
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
        alerts = new Alerts();
        AppServices.initialize(null, alerts);
        EventManager.get().unregister(AppServices.get()); // never dispatch to networking services

        try(var reader = new InputStreamReader(getClass().getResourceAsStream(
                "/com/sparrowwallet/sparrow/io/protocol-v1-mixed-provenance-vector.json"), StandardCharsets.UTF_8)) {
            vector = JsonParser.parseReader(reader).getAsJsonObject();
        }
        signed = Utils.hexToBytes(vector.get("signed_psbt_hex").getAsString());
        // Signer A's genuine protocol proof for the vector's signed PSBT (signer B signed ordinarily).
        Method create = AntiExfilCoordinator.class.getDeclaredMethod("create", Path.class, Path.class, byte[].class,
                Keystore.class, AntiExfilNetwork.class, boolean.class, SecureRandom.class);
        create.setAccessible(true);
        AntiExfilCoordinator coordinator = (AntiExfilCoordinator)create.invoke(null, temp.resolve("a.aexs"),
                temp.resolve("a.aexj"), Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()),
                watchOnly(vector.getAsJsonObject("signer_a"), AntiExfilKeystorePolicy.REQUIRED, KeystoreSource.HW_AIRGAPPED),
                AntiExfilNetwork.TESTNET4, false, new SecureRandom() {
                    int call;
                    @Override public void nextBytes(byte[] bytes) { Arrays.fill(bytes, call++ == 0 ? (byte)'m' : (byte)0xa1); }
                });
        coordinator.acceptOpenings(Utils.hexToBytes(vector.get("message_2_hex").getAsString()));
        AntiExfilCoordinator.Completion completion = coordinator.complete(Utils.hexToBytes(vector.get("message_4_hex").getAsString()));
        assertArrayEquals(signed, completion.getSignedPsbt());
        proofA = completion.getVerifiedSignatures();
        assertEquals(1, proofA.size());
    }

    @AfterEach void cleanup() throws Exception {
        fx(() -> { controllers.forEach(HeadersController::close); stages.forEach(Stage::close); return null; });
        set(AppServices.class, null, "INSTANCE", previousServices);
        set(EventManager.class, null, "SINGLETON", previousEventBus);
        Network.set(previousNetwork);
        assertTrue(eventErrors.isEmpty(), eventErrors.toString());
    }

    // ------------------------------------------------------------------ policy predicate

    // Independent Codex review: strongest policy must survive unsigned and valid-proof states too.
    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void codexRequiredWalletWinsForUnsignedPsbt() throws Exception {
        Wallet optional = multisig(AntiExfilKeystorePolicy.OPTIONAL, AntiExfilKeystorePolicy.OPTIONAL);
        Wallet required = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL);
        PSBT unsigned = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()), false);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(required, unsigned, Set.of()));
        assertSame(required, HeadersController.selectPsbtPolicyWallet(List.of(optional, required), unsigned, Set.of()));
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void codexRequiredWalletWinsWithValidProof() throws Exception {
        Wallet optional = multisig(AntiExfilKeystorePolicy.OPTIONAL, AntiExfilKeystorePolicy.OPTIONAL);
        Wallet required = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL);
        PSBT protectedReturn = new PSBT(signed, false);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(required, protectedReturn, proofA));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(optional, protectedReturn, proofA));
        assertSame(required, HeadersController.selectPsbtPolicyWallet(List.of(optional, required), protectedReturn, proofA));
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void unsignedWalletSelectionAndRefreshKeepRequiredAuthority() throws Exception {
        Wallet optional = multisig(AntiExfilKeystorePolicy.OPTIONAL, AntiExfilKeystorePolicy.OPTIONAL);
        Wallet required = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL);
        PSBT unsigned = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()), false);
        Fixture f = freshImport(unsigned, Set.of(), optional, required);
        fx(() -> {
            assertSame(required, ((ComboBox<?>)f.node("signingWallet")).getValue());
            // Selecting a convenience duplicate is not an explicit edit of the Required keystore policy.
            EventManager.get().post(new com.sparrowwallet.sparrow.event.FinalizeTransactionEvent(unsigned, optional));
            assertSame(required, f.data.getSigningWallet());
            return null;
        });
        postWallets(f, optional); // the Required wallet was closed
        fx(() -> { assertSame(required, f.data.getSigningWallet()); return null; });
        // A deliberate edit of the authoritative keystore's policy is honored on refresh.
        required.getKeystores().getFirst().setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
        postWallets(f, optional, required);
        fx(() -> { assertSame(optional, ((ComboBox<?>)f.node("signingWallet")).getValue()); return null; });
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void replacementSettingsEventUpdatesTheBoundAuthorityByStorageIdentity() throws Exception {
        Wallet required = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL);
        PSBT unsigned = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()), false);
        Fixture f = freshImport(unsigned, required);
        Storage storage = new Storage(new java.io.File(temp.toFile(), "replacement-wallet.mv.db"));
        Wallet replacement = required.copy();
        fx(() -> {
            f.data.getAvailableWallets().put(required, storage);
            EventManager.get().post(new com.sparrowwallet.sparrow.event.WalletAddressesChangedEvent(
                    replacement, required.copy(), storage.getWalletId(required)));
            assertSame(replacement, f.data.getSigningWallet());
            assertTrue(AntiExfilPolicy.requiresProtectedSigning(f.data.getSigningWallet()));
            Wallet old = replacement.copy();
            replacement.getKeystores().getFirst().setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
            EventManager.get().post(new com.sparrowwallet.sparrow.event.KeystoreAntiExfilPoliciesChangedEvent(
                    replacement, old, storage.getWalletId(replacement), replacement.getKeystores()));
            assertSame(replacement, f.data.getSigningWallet());
            assertFalse(AntiExfilPolicy.requiresProtectedSigning(f.data.getSigningWallet()));
            assertTrue(f.node("antiExfilButton").isVisible()); // Optional compatible wallets still offer protected signing.
            return null;
        });
    }

    @org.junit.jupiter.api.Disabled("Historical durable Required/proof authority retired; new optional-policy and RAM tests replace this expectation")
    @Test void validProofWalletBindingSurvivesOptionalDuplicateRefresh() throws Exception {
        Wallet optional = multisig(AntiExfilKeystorePolicy.OPTIONAL, AntiExfilKeystorePolicy.OPTIONAL);
        Wallet required = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL);
        Fixture f = freshImport(new PSBT(signed, false), proofA, optional, required);
        fx(() -> {
            assertSame(required, f.data.getSigningWallet());
            assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, HeadersController.evaluateTransactionProvenance(f.data));
            return null;
        });
        postWallets(f, required, optional);
        postWallets(f, optional, required);
        postWallets(f); // no open wallets: retain policy authority, but quarantine the active tab
        fx(() -> {
            assertNull(f.data.getSigningWallet());
            assertFalse(f.node("protectedCompletionBox").isVisible());
            return null;
        });
        postWallets(f, optional);
        fx(() -> {
            assertSame(required, f.data.getSigningWallet());
            assertEquals(proofA, f.data.getVerifiedAntiExfilSignatures());
            return null;
        });
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void policySelectionKeepsRequiredEvenWhenProofIsInvalidAndHonorsStrongerDuplicate() throws Exception {
        Wallet optional = multisig(AntiExfilKeystorePolicy.OPTIONAL, AntiExfilKeystorePolicy.OPTIONAL);
        Wallet required = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL);
        Wallet bothRequired = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.REQUIRED);
        PSBT changed = new PSBT(signed, false);
        changed.getTransaction().setLocktime(12345);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.INVALID_PROVENANCE,
                AntiExfilPolicy.evaluateSignatureProvenance(optional, changed, proofA));
        assertSame(required, HeadersController.selectPsbtPolicyWallet(List.of(optional, required), changed, proofA));
        PSBT unsigned = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()), false);
        assertSame(bothRequired, HeadersController.selectPsbtPolicyWallet(List.of(optional, required, bothRequired), unsigned, Set.of()));
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void incomparableRequiredPoliciesFailClosedUntilSupersetWalletOpens() throws Exception {
        Wallet requiredA = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL);
        Wallet requiredB = multisig(AntiExfilKeystorePolicy.OPTIONAL, AntiExfilKeystorePolicy.REQUIRED);
        Wallet requiredBoth = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.REQUIRED);
        PSBT unsigned = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()), false);
        assertNull(HeadersController.selectPsbtPolicyWallet(List.of(requiredA, requiredB), unsigned, Set.of()));
        assertNull(HeadersController.selectPsbtPolicyWallet(List.of(requiredB, requiredA), unsigned, Set.of()));
        Fixture f = freshImport(unsigned, Set.of(), requiredA, requiredB);
        fx(() -> {
            assertNull(f.data.getSigningWallet());
            assertTrue(f.node("signButton").isDisabled());
            assertTrue(f.node("finalizeTransaction").isDisabled());
            return null;
        });
        postWallets(f, requiredA, requiredB, requiredBoth);
        fx(() -> {
            assertSame(requiredBoth, ((ComboBox<?>)f.node("signingWallet")).getValue());
            assertFalse(f.node("finalizeTransaction").isDisabled());
            return null;
        });
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void strippedPartialRequiredReturnIsNotPermitted() throws Exception {
        for(AntiExfilKeystorePolicy policyB : List.of(AntiExfilKeystorePolicy.OPTIONAL, AntiExfilKeystorePolicy.REQUIRED)) {
            Wallet wallet = multisig(AntiExfilKeystorePolicy.REQUIRED, policyB);
            PSBT stripped = strip(new PSBT(signed, false));
            assertImportable(stripped);
            assertTrue(stripped.getPsbtInputs().stream().allMatch(input -> input.getDerivedPublicKeys().isEmpty()));
            assertTrue(wallet.canSign(stripped), "the Required wallet still binds the stripped return by script");
            assertTrue(AntiExfilPolicy.hasRequiredSignature(wallet, stripped));

            assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                    AntiExfilPolicy.evaluateSignatureProvenance(wallet, stripped, Set.of()), "B=" + policyB);
            TransactionData tab = new TransactionData("stripped", stripped);
            tab.setSigningWallet(wallet);
            assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, AntiExfilPolicy.evaluatePsbtEgress(tab));
            assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, HeadersController.evaluateTransactionProvenance(tab));
            assertEquals(0, stripped.getPsbtInputs().getFirst().getDerivedPublicKeys().size(), "evaluation must not mutate the PSBT");
        }
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void strippedFinalizedRequiredReturnIsNotPermitted() throws Exception {
        for(AntiExfilKeystorePolicy policyB : List.of(AntiExfilKeystorePolicy.OPTIONAL, AntiExfilKeystorePolicy.REQUIRED)) {
            Wallet wallet = multisig(AntiExfilKeystorePolicy.REQUIRED, policyB);
            PSBT finalized = new PSBT(signed, false);
            wallet.finalise(finalized);
            PSBT stripped = strip(finalized);
            assertTrue(stripped.isFinalized());
            assertImportable(stripped);

            assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                    AntiExfilPolicy.evaluateSignatureProvenance(wallet, stripped, Set.of()), "B=" + policyB);
            TransactionData tab = new TransactionData("stripped-final", stripped);
            tab.setSigningWallet(wallet);
            assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, HeadersController.evaluateTransactionProvenance(tab));
        }
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void truncatedOrRelabelledRequiredDerivationIsNotTrusted() throws Exception {
        Wallet wallet = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL);
        String fingerprintA = wallet.getKeystores().getFirst().getKeyDerivation().getMasterFingerprint();

        // Only signer A's (Required) derivation removed; signer B's (Optional) entry kept.
        PSBT truncated = new PSBT(signed, false);
        truncated.getPsbtInputs().getFirst().getDerivedPublicKeys().entrySet()
                .removeIf(entry -> entry.getValue().getMasterFingerprint().equals(fingerprintA));
        truncated = reparse(truncated);
        assertEquals(1, truncated.getPsbtInputs().getFirst().getDerivedPublicKeys().size());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, truncated, Set.of()));

        // Signer A's entry relabelled with a foreign fingerprint, so it no longer derives from A's xpub.
        PSBT relabelled = new PSBT(signed, false);
        for(Map.Entry<ECKey, KeyDerivation> entry : relabelled.getPsbtInputs().getFirst().getDerivedPublicKeys().entrySet()) {
            if(entry.getValue().getMasterFingerprint().equals(fingerprintA)) {
                entry.setValue(new KeyDerivation("deadbeef", entry.getValue().getDerivationPath()));
            }
        }
        relabelled = reparse(relabelled);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, relabelled, Set.of()));
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void unattributableSignatureOnRequiredInputFailsClosed() throws Exception {
        Wallet wallet = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL);
        PSBT foreign = strip(new PSBT(signed, false));
        PSBTInput input = foreign.getPsbtInputs().getFirst();
        input.getPartialSignatures().clear();
        ECKey stranger = ECKey.fromPrivate(BigInteger.valueOf(0x5eed));
        input.getPartialSignatures().put(ECKey.fromPublicOnly(stranger.getPubKey()),
                stranger.sign(input.getSigningHash(), SigHash.ALL, TransactionSignature.Type.ECDSA));
        foreign = reparse(foreign);
        assertImportable(foreign);

        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_RETURN_UNATTRIBUTABLE,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, foreign, Set.of()));
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void seedSignerTrimmedSingleSigReturnIsNotPermitted() throws Exception {
        SingleSig s = singleSig(AntiExfilKeystorePolicy.REQUIRED);
        PSBT received = new PSBT(s.trimmed(), false);
        assertNull(received.getPsbtInputs().getFirst().getUtxo());
        assertTrue(received.getPsbtInputs().getFirst().getDerivedPublicKeys().isEmpty());
        PSBT imported = backfill(received, s.host());
        assertImportable(imported);
        assertTrue(s.host().canSign(imported));

        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(s.host(), imported, Set.of()));
        TransactionData tab = new TransactionData("seedsigner-trim", imported);
        tab.setSigningWallet(s.host());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, AntiExfilPolicy.evaluatePsbtEgress(tab));
        s.host().finalise(imported);
        assertTrue(imported.isFinalized());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(s.host(), imported, Set.of()));
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void strippedRequiredReturnWithMatchingProofIsAttributedThroughTheWallet() throws Exception {
        // Decision: a proof matches the exact signer identity, input, outpoint, key, digest and signature, so once the
        // wallet attributes the signer the return is as good as one that kept its derivations. The bound wallet is a
        // stronger source of the key's path than the PSBT; the base code rejected this as INVALID_PROVENANCE only
        // because it could attribute nothing.
        Wallet mixed = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL);
        PSBT stripped = strip(new PSBT(signed, false));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(mixed, new PSBT(signed, false), proofA), "control with derivations");
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, AntiExfilPolicy.evaluateSignatureProvenance(mixed, stripped, proofA));
        assertEquals(proofA, AntiExfilPolicy.retainMatchingProofs(mixed, stripped, proofA));

        PSBT finalized = new PSBT(signed, false);
        mixed.finalise(finalized);
        PSBT strippedFinal = strip(finalized);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, AntiExfilPolicy.evaluateSignatureProvenance(mixed, strippedFinal, proofA));
        assertEquals(proofA, AntiExfilPolicy.retainMatchingProofs(mixed, strippedFinal, proofA));

        // Signer B's ordinary signature is still caught once B is Required; a proof covers only its own signature.
        Wallet both = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.REQUIRED);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, AntiExfilPolicy.evaluateSignatureProvenance(both, stripped, proofA));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, AntiExfilPolicy.evaluateSignatureProvenance(both, strippedFinal, proofA));
    }

    /** Guard (passes before and after the fix): ordinary Optional-only returns are unaffected by stripping. */
    @Test void optionalOnlyStrippedReturnStaysPermitted() throws Exception {
        Wallet wallet = multisig(AntiExfilKeystorePolicy.OPTIONAL, AntiExfilKeystorePolicy.OPTIONAL);
        PSBT stripped = strip(new PSBT(signed, false));
        PSBT finalized = new PSBT(signed, false);
        wallet.finalise(finalized);
        for(PSBT psbt : List.of(stripped, strip(finalized))) {
            assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, AntiExfilPolicy.evaluateSignatureProvenance(wallet, psbt, Set.of()));
            TransactionData tab = new TransactionData("optional", psbt);
            tab.setSigningWallet(wallet);
            assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, HeadersController.evaluateTransactionProvenance(tab));
        }
        SingleSig s = singleSig(AntiExfilKeystorePolicy.OPTIONAL);
        PSBT imported = backfill(new PSBT(s.trimmed(), false), s.host());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, AntiExfilPolicy.evaluateSignatureProvenance(s.host(), imported, Set.of()));
    }

    // ------------------------------------------------------------------ fresh import: real headers.fxml + HeadersController

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void freshImportOfStrippedRequiredReturnOpensReadOnly() throws Exception {
        Wallet wallet = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL);
        PSBT finalized = new PSBT(signed, false);
        wallet.finalise(finalized);
        SingleSig s = singleSig(AntiExfilKeystorePolicy.REQUIRED);
        Map<String, Object[]> cases = new LinkedHashMap<>();
        cases.put("multisig partial", new Object[]{strip(new PSBT(signed, false)), wallet});
        cases.put("multisig finalized", new Object[]{strip(finalized), wallet});
        cases.put("seedsigner trimmed", new Object[]{backfill(new PSBT(s.trimmed(), false), s.host()), s.host()});
        for(Map.Entry<String, Object[]> c : cases.entrySet()) {
            PSBT psbt = (PSBT)c.getValue()[0];
            Wallet bound = (Wallet)c.getValue()[1];
            Fixture f = freshImport(psbt, bound);
            int alertsBefore = alerts.size();
            fx(() -> {
                assertSame(bound, f.data.getSigningWallet(), c.getKey() + ": the real openWallets binds the Required wallet");
                assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                        HeadersController.evaluateTransactionProvenance(f.data), c.getKey());
                assertTrue(f.node("provenanceWarning").isVisible(), c.getKey() + ": read-only warning");
                assertFalse(f.node("protectedCompletionBox").isVisible(), c.getKey() + ": no 'Protected signatures verified' label");
                for(String id : List.of("savePsbtButton", "showPsbtButton", "broadcastButton", "viewFinalButton",
                        "finalizeProtectedButton", "payjoinButton")) {
                    assertTrue(f.node(id).isDisabled(), c.getKey() + ": " + id + " must be disabled");
                }
                assertFalse(f.controller.extractTransaction(), c.getKey() + ": View Final refused at click time");
                return null;
            });
            if(psbt.isFinalized()) {
                assertTrue(alerts.since(alertsBefore).stream().anyMatch(a -> a.startsWith("Protected signature rejected")
                        && a.contains("REQUIRED_PROOF_MISSING")), alerts.toString());
            }
        }
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void sameWindowFreshImportThroughAppControllerOpensQuarantinedTab() throws Exception {
        // File > Open Transaction in the window that holds the wallet: the real AppController.addTransactionTab
        // back-fills the UTXO and opens a tab with no admission check, so the tab's own gate must hold.
        SingleSig s = singleSig(AntiExfilKeystorePolicy.REQUIRED);
        Windows w = windows(s.host());
        try {
            TransactionTabData opened = fx(() -> {
                Method open = AppController.class.getDeclaredMethod("addTransactionTab", String.class, File.class, PSBT.class);
                open.setAccessible(true);
                open.invoke(w.walletWindow, "seedsigner-return.psbt", null, new PSBT(s.trimmed(), false));
                assertEquals(1, w.walletTabs.getTabs().size(), "the fresh import opens a tab: " + alerts);
                w.walletStage.show(); w.walletTabs.applyCss(); w.walletTabs.layout(); // attach the tab content
                return (TransactionTabData)w.walletTabs.getTabs().getFirst().getUserData();
            });
            fx(() -> {
                PSBT psbt = opened.getPsbt();
                assertNotNull(psbt.getPsbtInputs().getFirst().getUtxo(), "UTXO back-filled from the wallet history");
                assertTrue(psbt.getPsbtInputs().getFirst().getDerivedPublicKeys().isEmpty());
                EventManager.get().post(new OpenWalletsEvent(w.walletStage, List.of()) {
                    @Override public Map<Wallet, Storage> getWalletsMap() {
                        Map<Wallet, Storage> wallets = new LinkedHashMap<>(); wallets.put(s.host(), null); return wallets;
                    }
                    @Override public List<Wallet> getWallets() { return List.of(s.host()); }
                });
                assertSame(s.host(), opened.getTransactionData().getSigningWallet());
                assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                        HeadersController.evaluateTransactionProvenance(opened.getTransactionData()));
                assertFalse(psbt.isFinalized());
                return null;
            });
        } finally {
            fx(() -> { w.close(); return null; });
        }
    }

    // ------------------------------------------------------------------ cross-window forward: AppController.viewPSBT

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void crossWindowForwardOfStrippedRequiredReturnIsRejected() throws Exception {
        Wallet wallet = multisig(AntiExfilKeystorePolicy.REQUIRED, AntiExfilKeystorePolicy.OPTIONAL);
        PSBT finalized = new PSBT(signed, false);
        wallet.finalise(finalized);
        SingleSig s = singleSig(AntiExfilKeystorePolicy.REQUIRED);
        assertForwardRejected(wallet, strip(new PSBT(signed, false)), "multisig partial");
        assertForwardRejected(wallet, strip(finalized), "multisig finalized");
        // Exactly the bytes SeedSigner returns: no UTXO and no derivations. AppController.addTransactionTab
        // back-fills the UTXO from the open wallet's history before routing it to the wallet's window.
        assertForwardRejected(s.host(), new PSBT(s.trimmed(), false), "seedsigner trimmed");
    }

    private void assertForwardRejected(Wallet wallet, PSBT incoming, String name) throws Exception {
        Windows w = windows(wallet);
        int alertsBefore = alerts.size();
        fx(() -> {
            // File > Open Transaction (or QR/drag-drop) in a window that does not hold the wallet.
            Method open = AppController.class.getDeclaredMethod("addTransactionTab", String.class, File.class, PSBT.class);
            open.setAccessible(true);
            open.invoke(w.importing, name, null, incoming);
            return null;
        });
        List<String> raised = alerts.since(alertsBefore);
        assertEquals(1, w.forwarded.size(), name + ": the import must be forwarded to the wallet window");
        assertEquals(0, w.walletTabs.getTabs().size(), name + ": no tab may open in the wallet window. alerts=" + raised);
        assertEquals(0, w.importTabs.getTabs().size(), name);
        assertTrue(raised.stream().anyMatch(a -> a.startsWith("Protected signature rejected") && a.contains("REQUIRED_PROOF_MISSING")),
                name + ": " + raised);
        fx(() -> { w.close(); return null; });
    }

    // ------------------------------------------------------------------ fixtures

    private record SingleSig(Wallet host, byte[] trimmed) {}

    /** P2WPKH single-sig whose return is in SeedSigner PSBTParser.trim() shape (unsigned tx plus partial_sigs only). */
    private SingleSig singleSig(AntiExfilKeystorePolicy policy) throws Exception {
        Keystore secret = Keystore.fromSeed(new DeterministicSeed(SS_MNEMONIC, "", 0, DeterministicSeed.Type.BIP39),
                PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
        Wallet signer = new Wallet("ss-signer");
        signer.setPolicyType(PolicyType.SINGLE_HD); signer.setScriptType(ScriptType.P2WPKH);
        signer.getKeystores().add(secret);
        signer.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, signer.getKeystores(), 1));
        Address address = signer.getFreshNode(KeyPurpose.RECEIVE).getAddress();

        byte[] previous = new byte[32]; Arrays.fill(previous, (byte)0x33);
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
        assertTrue(psbt.isSigned());
        PSBT trimmed = new PSBT(psbt.getTransaction());
        trimmed.getPsbtInputs().getFirst().getPartialSignatures().putAll(psbt.getPsbtInputs().getFirst().getPartialSignatures());

        Wallet host = new Wallet("ss-host-" + policy);
        host.setPolicyType(PolicyType.SINGLE_HD); host.setScriptType(ScriptType.P2WPKH);
        Keystore watch = Keystore.fromSeed(new DeterministicSeed(SS_MNEMONIC, "", 0, DeterministicSeed.Type.BIP39),
                PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
        publicOnly(watch, WalletModel.SEEDSIGNER, policy, KeystoreSource.HW_AIRGAPPED);
        host.getKeystores().add(watch);
        host.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, host.getKeystores(), 1));
        host.checkWallet();
        // The host wallet's history holds the funding transaction, which is what the import back-fill reads.
        host.updateTransactions(Map.of(funding.getTxId(), new BlockTransaction(funding.getTxId(), 100, new Date(), 0L, funding)));
        return new SingleSig(host, trimmed.serialize());
    }

    /** The UTXO back-fill AppController.addTransactionTab(String, File, PSBT, Set) applies to a fresh import. */
    private static PSBT backfill(PSBT psbt, Wallet wallet) {
        for(PSBTInput input : psbt.getPsbtInputs()) {
            if(input.getUtxo() == null) {
                BlockTransaction blockTransaction = wallet.getWalletTransaction(input.getInput().getOutpoint().getHash());
                input.setNonWitnessUtxo(blockTransaction.getTransaction());
                ScriptType type = input.getScriptType();
                if(type != null && Arrays.asList(ScriptType.WITNESS_TYPES).contains(type)) {
                    input.setWitnessUtxo(blockTransaction.getTransaction().getOutputs().get((int)input.getInput().getOutpoint().getIndex()));
                    input.setNonWitnessUtxo(null);
                }
            }
        }
        return psbt;
    }

    private Wallet multisig(AntiExfilKeystorePolicy policyA, AntiExfilKeystorePolicy policyB) throws Exception {
        Wallet wallet = new Wallet("ms-" + policyA + "-" + policyB);
        wallet.getKeystores().add(watchOnly(vector.getAsJsonObject("signer_a"), policyA, KeystoreSource.HW_AIRGAPPED));
        wallet.getKeystores().add(watchOnly(vector.getAsJsonObject("signer_b"), policyB, KeystoreSource.HW_AIRGAPPED));
        wallet.setPolicyType(PolicyType.MULTI_HD); wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        wallet.checkWallet();
        return wallet;
    }

    private static Keystore watchOnly(JsonObject signer, AntiExfilKeystorePolicy policy, KeystoreSource source) throws Exception {
        Keystore keystore = Keystore.fromSeed(new DeterministicSeed(signer.get("mnemonic").getAsString(), "", 0,
                DeterministicSeed.Type.BIP39), PolicyType.MULTI_HD, KeyDerivation.parsePath(signer.get("account_derivation").getAsString()));
        publicOnly(keystore, WalletModel.KERN, policy, source);
        return keystore;
    }

    private static void publicOnly(Keystore keystore, WalletModel model, AntiExfilKeystorePolicy policy, KeystoreSource source) {
        keystore.setSeed(null); keystore.setMasterPrivateExtendedKey(null); keystore.setSource(source);
        keystore.setLabel(keystore.getKeyDerivation().getMasterFingerprint());
        keystore.setWalletModel(model); keystore.setAntiExfilProfile(AntiExfilProfile.AEXT_V1); keystore.setAntiExfilPolicy(policy);
    }

    /** Removes global xpubs and all input/output BIP32 derivations, then re-parses as an import would. */
    private static PSBT strip(PSBT psbt) throws Exception {
        PSBT copy = reparse(psbt);
        copy.getExtendedPublicKeys().clear();
        for(PSBTInput input : copy.getPsbtInputs()) input.getDerivedPublicKeys().clear();
        for(PSBTOutput output : copy.getPsbtOutputs()) output.getDerivedPublicKeys().clear();
        return reparse(copy);
    }

    private static PSBT reparse(PSBT psbt) throws Exception {
        return new PSBT(psbt.serialize(), false);
    }

    /** The checks AppController.addTransactionTab runs before opening a fresh tab. */
    private static void assertImportable(PSBT psbt) {
        assertDoesNotThrow(() -> { PSBT copy = reparse(psbt); copy.verifySignatures(); copy.verifySigHashes(); });
    }

    record Fixture(HeadersController controller, TransactionData data, Stage stage, Map<String, Object> namespace) {
        Node node(String id) { return (Node)namespace.get(id); }
    }

    /** Mirrors AppController's fresh tab: TransactionData(name, psbt) with no wallet, then the real openWallets binding. */
    private Fixture freshImport(PSBT psbt, Wallet wallet) throws Exception {
        return freshImport(psbt, Set.of(), wallet);
    }

    private Fixture freshImport(PSBT psbt, Set<VerifiedAntiExfilSignature> proofs, Wallet... wallets) throws Exception {
        Fixture f = fx(() -> {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("headers.fxml"));
            Parent root = loader.load();
            HeadersController controller = loader.getController();
            assertSame(HeadersController.class, controller.getClass());
            Stage stage = new Stage(); stage.setScene(new Scene(root, 1100, 900));
            TransactionData data = new TransactionData("fresh-import", psbt);
            data.addVerifiedAntiExfilSignatures(proofs);
            controller.setModel(new HeadersForm(data));
            stage.show(); root.applyCss(); root.layout();
            stages.add(stage); controllers.add(controller);
            return new Fixture(controller, data, stage, loader.getNamespace());
        });
        postWallets(f, wallets);
        return f;
    }

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

    private final class Windows {
        final Stage walletStage = new Stage();
        final Stage importStage = new Stage();
        final TabPane walletTabs = new TabPane();
        final TabPane importTabs = new TabPane();
        final AppController walletWindow = new AppController();
        final AppController importing = new AppController();
        final List<Object> forwarded = new ArrayList<>();
        final Object forwardCounter = new Object() {
            @com.google.common.eventbus.Subscribe public void forwarded(com.sparrowwallet.sparrow.event.ViewPSBTEvent event) { forwarded.add(event); }
        };

        void close() throws Exception {
            EventManager.get().unregister(walletWindow);
            EventManager.get().unregister(forwardCounter);
            walletWindows().remove(walletStage);
            walletStage.close(); importStage.close();
        }
    }

    private Windows windows(Wallet wallet) throws Exception {
        return fx(() -> {
            Windows w = new Windows();
            w.walletStage.setScene(new Scene(w.walletTabs));
            w.importStage.setScene(new Scene(w.importTabs));
            set(AppController.class, w.walletWindow, "tabs", w.walletTabs);
            set(AppController.class, w.importing, "tabs", w.importTabs);
            walletWindows().put(w.walletStage, List.of(new WalletTabData(TabData.TabType.WALLET, null) {
                @Override public Wallet getWallet() { return wallet; }
                @Override public Storage getStorage() { return null; }
            }));
            EventManager.get().register(w.walletWindow); // only the wallet window listens, as in the app
            EventManager.get().register(w.forwardCounter);
            return w;
        });
    }

    @SuppressWarnings("unchecked")
    private static Map<Window, List<WalletTabData>> walletWindows() throws Exception {
        Field windows = AppServices.class.getDeclaredField("walletWindows");
        windows.setAccessible(true);
        return (Map<Window, List<WalletTabData>>)windows.get(AppServices.get());
    }

    static final class Alerts implements InteractionServices {
        private final List<String> alerts = new CopyOnWriteArrayList<>();
        @Override public Optional<ButtonType> showAlert(String title, String content, Alert.AlertType type, Node graphic, ButtonType... buttons) {
            alerts.add(title + ": " + content);
            return Optional.of(ButtonType.NO);
        }
        @Override public Optional<String> requestPassphrase(String walletName, Keystore keystore) {
            throw new AssertionError("No secrets may be requested");
        }
        int size() { return alerts.size(); }
        List<String> since(int index) { return List.copyOf(alerts.subList(index, alerts.size())); }
        @Override public String toString() { return alerts.toString(); }
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
