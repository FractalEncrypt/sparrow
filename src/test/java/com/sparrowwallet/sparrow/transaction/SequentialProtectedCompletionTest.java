package com.sparrowwallet.sparrow.transaction;

import com.google.common.eventbus.Subscribe;
import com.google.common.eventbus.EventBus;
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
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.*;
import com.sparrowwallet.sparrow.event.PSBTCombinedEvent;
import com.sparrowwallet.sparrow.event.PSBTFinalizedEvent;
import com.sparrowwallet.sparrow.event.ViewPSBTEvent;
import com.sparrowwallet.sparrow.io.Storage;
import javafx.application.Platform;
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
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** Real coordinators and actual
 * EventBus -> AppController.viewPSBT -> addTransactionTab -> handleTransactionMerge.
 * Only the signer hardware/optical exchange and dialogs are simulated.
 * The sequential matrix always requires acceptance through the actual event path.
 */
public class SequentialProtectedCompletionTest {
    private static final BigInteger N = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    // Public BIP39 test vector (entropy ffff..ff). Used only for the 2-of-3 reserve cosigner,
    // which must carry a distinct master fingerprint from A and B. The reserve never signs.
    private static final String RESERVE_MNEMONIC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    @TempDir Path temporary;
    private int ceremony;
    private static Network previousNetwork;
    private static String previousSparrowHome;

    @BeforeAll static void startFx() throws Exception {
        previousNetwork = Network.get();
        previousSparrowHome = System.getProperty("sparrow.home");
        System.setProperty("sparrow.home", Files.createTempDirectory("sparrow-proof-regression-home-").toString());
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

    @TestFactory Stream<DynamicTest> sequentialCompletionMatrix() {
        List<DynamicTest> tests = new ArrayList<>();
        for(int size : List.of(2, 3)) {
            for(boolean reversed : List.of(false, true)) {
                for(String policies : List.of("RR", "RO", "OR")) {
                    String name = "2-of-" + size + " " + (reversed ? "B-then-A" : "A-then-B") + " policies=" + policies;
                    tests.add(DynamicTest.dynamicTest(name, () -> sequential(size, reversed, policies)));
                }
            }
        }
        return tests.stream();
    }

    private void sequential(int size, boolean reversed, String policies) throws Exception {
        Fixture f = fixture(size, policies);
        int first = reversed ? 1 : 0;
        int second = 1 - first;
        Run a = complete(f.psbt, f.privateSigners.get(first), f.wallet.getKeystores().get(first));
        Run b = complete(a.signed, f.privateSigners.get(second), f.wallet.getKeystores().get(second));
        assertFalse(a.completion.isBroadcast());
        assertFalse(b.completion.isBroadcast());
        assertNotEquals(a.completion.getVerifiedSignatures(), b.completion.getVerifiedSignatures());
        assertEquals(2, b.signed.getPsbtInputs().getFirst().getPartialSignatures().size());
        b.signed.verifySignatures();
        Set<VerifiedAntiExfilSignature> union = union(a, b);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(f.wallet, b.signed, union));
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(a, f.psbt);
                assertEquals(1, h.observer.merges);
                assertEquals(a.completion.getVerifiedSignatures(), h.data.getVerifiedAntiExfilSignatures());
                h.post(b, a.signed);
                assertEquals(2, h.observer.merges, "both valid protected completions should reach merge");
                assertEquals(2, h.data.getPsbt().getPsbtInputs().getFirst().getPartialSignatures().size());
                assertEquals(union, h.data.getVerifiedAntiExfilSignatures());
                assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, AntiExfilPolicy.evaluatePsbtEgress(h.data));
            }
            return null;
        });
    }

    @Test void independentlySignedPartialUsesRetainedProofs() throws Exception {
        Fixture f = fixture(2, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run b = complete(f.psbt, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(a, f.psbt);
                h.post(b, f.psbt);
                assertEquals(2, h.observer.merges);
                assertEquals(union(a, b), h.data.getVerifiedAntiExfilSignatures());
                h.data.getPsbt().verifySignatures();
                assertTrue(h.alerts.isEmpty(), h.alerts.toString());
            }
            return null;
        });
    }

    @Test void finalizedReturnRetainsBothCeremonyProofs() throws Exception {
        Fixture f = fixture(2, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run b = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        PSBT finalized = copy(b.signed);
        f.wallet.finalise(finalized);
        assertTrue(finalized.isFinalized());
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(a, f.psbt);
                h.post(finalized, a.signed, b.completion.getVerifiedSignatures());
                assertEquals(1, h.observer.merges);
                assertEquals(1, h.observer.finalizations);
                assertTrue(h.data.getPsbt().isFinalized());
                assertEquals(union(a, b), h.data.getVerifiedAntiExfilSignatures());
                assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, AntiExfilPolicy.evaluatePsbtEgress(h.data));
                assertTrue(h.alerts.isEmpty(), h.alerts.toString());
            }
            return null;
        });
    }

    @Test void finalizedReturnWithoutSecondProofIsRejectedBeforeMutation() throws Exception {
        Fixture f = fixture(2, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run b = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        PSBT finalized = copy(b.signed);
        f.wallet.finalise(finalized);
        assertRejected(f, a, finalized, a.signed, Set.of());
    }

    @Test void unmatchedReturnCannotBorrowAnOpenTabsProofs() throws Exception {
        Fixture f = fixture(2, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run b = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        PSBT other = copy(a.signed);
        other.getTransaction().setLocktime(12345);
        fx(() -> {
            try(Harness h = new Harness(f.wallet, other)) {
                h.data.replaceVerifiedAntiExfilSignatures(a.completion.getVerifiedSignatures());
                h.assertRejectedUnchanged(b.signed, null, b.completion.getVerifiedSignatures());
                assertTrue(h.alerts.toString().contains("REQUIRED_PROOF_MISSING"), h.alerts.toString());
            }
            return null;
        });
    }

    @Test void proofsFromAnotherTransactionTabCannotAuthorizeReturn() throws Exception {
        rejectWithoutBorrowingProofs(false);
    }

    @Test void proofsFromAnotherMatchingTabCannotAuthorizeReturn() throws Exception {
        rejectWithoutBorrowingProofs(true);
    }

    @Test void reversedMatchingTabsCannotChangeTheRejection() throws Exception {
        rejectWithoutBorrowingProofs(true, true, false);
    }

    @Test void duplicateTabsWithDifferentPoliciesAreRejectedInEitherOrder() throws Exception {
        for(boolean reversed : List.of(false, true)) rejectWithoutBorrowingProofs(true, reversed, true);
    }

    private void rejectWithoutBorrowingProofs(boolean sameTransaction) throws Exception {
        rejectWithoutBorrowingProofs(sameTransaction, false, false);
    }

    private void rejectWithoutBorrowingProofs(boolean sameTransaction, boolean reversed, boolean optionalOther) throws Exception {
        Fixture f = fixture(2, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run b = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(a, f.psbt);
                h.data.replaceVerifiedAntiExfilSignatures(Set.of());
                PSBT other = copy(a.signed);
                if(!sameTransaction) other.getTransaction().setLocktime(12345);
                TransactionData otherData = new TransactionData("other", other, a.completion.getVerifiedSignatures());
                Wallet otherWallet = f.wallet.copy();
                if(optionalOther) otherWallet.getKeystores().forEach(keystore ->
                        keystore.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL));
                otherData.setSigningWallet(otherWallet);
                Tab otherTab = new Tab();
                otherTab.setGraphic(new Label("other"));
                otherTab.setUserData(new TransactionTabData(TabData.TabType.TRANSACTION, null, otherData));
                h.tabs.getTabs().add(reversed ? 0 : 1, otherTab);
                byte[] otherBefore = other.serialize();
                h.assertRejectedUnchanged(b.signed, a.signed, b.completion.getVerifiedSignatures());
                assertArrayEquals(otherBefore, other.serialize());
                assertEquals(a.completion.getVerifiedSignatures(), otherData.getVerifiedAntiExfilSignatures());
                if(sameTransaction) assertTrue(h.alerts.toString().contains("Multiple Matching Transactions"), h.alerts.toString());
            }
            return null;
        });
    }

    @Test void nullPsbtEventIsReportedWithoutMutationOrSubscriberException() throws Exception {
        Fixture f = fixture(2, "RR");
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.assertRejectedUnchanged(null, f.psbt, Set.of());
                assertTrue(h.alerts.toString().contains("Invalid PSBT"), h.alerts.toString());
            }
            return null;
        });
    }

    @Test void ordinaryCrossTabScanUsesDestinationWalletAndRetainedProofs() throws Exception {
        Fixture f = fixture(2, "RO");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        PSBT ordinary = copy(a.signed);
        ECKey b = childKey(f.privateSigners.get(1));
        ordinary.getPsbtInputs().getFirst().getPartialSignatures().put(ECKey.fromPublicOnly(b.getPubKey()),
                b.sign(ordinary.getPsbtInputs().getFirst().getSigningHash(), SigHash.ALL, TransactionSignature.Type.ECDSA));
        PSBT scanOrigin = copy(f.psbt);
        scanOrigin.getTransaction().setLocktime(12345);
        for(boolean stricterWalletFirst : List.of(false, true)) {
            fx(() -> {
                try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                    h.post(a, f.psbt);
                    TransactionData originData = new TransactionData("scan origin", copy(scanOrigin));
                    originData.setSigningWallet(f.wallet);
                    Tab originTab = new Tab();
                    originTab.setGraphic(new Label("scan origin"));
                    originTab.setUserData(new TransactionTabData(TabData.TabType.TRANSACTION, null, originData));
                    h.tabs.getTabs().add(originTab);
                    h.tabs.getSelectionModel().select(originTab);
                    byte[] originBefore = originData.getPsbt().serialize();
                    Wallet stricterWallet = f.wallet.copy();
                    stricterWallet.getKeystores().forEach(keystore -> keystore.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED));
                    h.setOpenWallets(stricterWalletFirst ? List.of(stricterWallet, f.wallet) : List.of(f.wallet, stricterWallet));
                    h.post(ordinary, scanOrigin, Set.of());
                    assertEquals(2, h.observer.merges);
                    assertEquals(a.completion.getVerifiedSignatures(), h.data.getVerifiedAntiExfilSignatures());
                    assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, AntiExfilPolicy.evaluatePsbtEgress(h.data));
                    assertArrayEquals(originBefore, originData.getPsbt().serialize());
                    assertTrue(h.alerts.isEmpty(), h.alerts.toString());
                }
                return null;
            });
        }
    }

    @Test void finalizedInvalidOptionalSignatureIsRejectedBeforeMutation() throws Exception {
        Fixture f = fixture(2, "OO");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        PSBT finalized = copy(a.signed);
        ECKey b = childKey(f.privateSigners.get(1));
        finalized.getPsbtInputs().getFirst().getPartialSignatures().put(ECKey.fromPublicOnly(b.getPubKey()),
                b.sign(Sha256Hash.ZERO_HASH, SigHash.ALL, TransactionSignature.Type.ECDSA));
        f.wallet.finalise(finalized);
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(a, f.psbt);
                h.assertRejectedUnchanged(finalized, a.signed, Set.of());
                assertFalse(h.data.getPsbt().isFinalized());
                assertTrue(h.alerts.toString().contains("Invalid PSBT"), h.alerts.toString());
            }
            return null;
        });
    }

    @Test void completionForAnotherWindowIsIgnored() throws Exception {
        Fixture f = fixture(2, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run b = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(a, f.psbt);
                byte[] before = h.data.getPsbt().serialize();
                Stage otherWindow = new Stage();
                try {
                    EventManager.get().post(new ViewPSBTEvent(otherWindow, null, null, b.signed, a.signed,
                            TransactionView.HEADERS, null, b.completion.getVerifiedSignatures()));
                    assertEquals(1, h.observer.merges);
                    assertArrayEquals(before, h.data.getPsbt().serialize());
                    assertEquals(a.completion.getVerifiedSignatures(), h.data.getVerifiedAntiExfilSignatures());
                    assertTrue(h.alerts.isEmpty());
                } finally { otherWindow.close(); }
            }
            return null;
        });
    }

    @Test void mismatchedCeremonyContextCannotReuseRetainedProofs() throws Exception {
        Fixture f = fixture(2, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run b = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        PSBT different = copy(a.signed);
        different.getTransaction().setLocktime(12345);
        // Supply both proofs so the former early gate alone would permit the incoming PSBT.
        assertRejected(f, a, b.signed, different, union(a, b));
    }

    @Test void mergeWithoutSigningWalletIsQuarantined() throws Exception {
        Fixture f = fixture(2, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run b = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(a, f.psbt);
                h.data.setSigningWallet(null);
                h.assertRejectedUnchanged(b.signed, a.signed, b.completion.getVerifiedSignatures());
            }
            return null;
        });
    }

    @Test void proofsAreEvaluatedAgainstTheMatchingTabsWallet() throws Exception {
        Fixture f = fixture(3, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run b = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        Wallet otherWallet = f.wallet.copy();
        otherWallet.getKeystores().removeFirst();
        otherWallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH,
                otherWallet.getKeystores(), 2));
        otherWallet.checkWallet();
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(a, f.psbt);
                h.data.setSigningWallet(otherWallet);
                h.assertRejectedUnchanged(b.signed, a.signed, b.completion.getVerifiedSignatures());
            }
            return null;
        });
    }

    @Test void invalidOptionalSignatureIsRejectedBeforeMutation() throws Exception {
        Fixture f = fixture(2, "RO");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        PSBT invalid = copy(a.signed);
        ECKey b = childKey(f.privateSigners.get(1));
        invalid.getPsbtInputs().getFirst().getPartialSignatures().put(ECKey.fromPublicOnly(b.getPubKey()),
                b.sign(Sha256Hash.ZERO_HASH, SigHash.ALL, TransactionSignature.Type.ECDSA));
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(a, f.psbt);
                h.assertRejectedUnchanged(invalid, a.signed, Set.of());
                assertTrue(h.alerts.toString().contains("Invalid PSBT"), h.alerts.toString());
            }
            return null;
        });
    }

    private void assertRejected(Fixture f, Run a, PSBT incoming, PSBT context,
                                Set<VerifiedAntiExfilSignature> proofs) throws Exception {
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(a, f.psbt);
                h.assertRejectedUnchanged(incoming, context, proofs);
            }
            return null;
        });
    }

    @Test void ordinaryRequiredSignatureWithoutProofIsRejectedAtEventBoundary() throws Exception {
        Fixture f = fixture(2, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        PSBT ordinary = copy(a.signed);
        ECKey b = childKey(f.privateSigners.get(1));
        ordinary.getPsbtInputs().getFirst().getPartialSignatures().put(ECKey.fromPublicOnly(b.getPubKey()),
                b.sign(ordinary.getPsbtInputs().getFirst().getSigningHash(), SigHash.ALL,
                        TransactionSignature.Type.ECDSA));
        assertRejected(f, a, ordinary, a.completion.getVerifiedSignatures(), "REQUIRED_PROOF_MISSING");
    }

    @Test void proofForDifferentSignatureOfSameSignerCannotAuthorizeReturn() throws Exception {
        Fixture f = fixture(2, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run oldB = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        Run newB = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        assertNotEquals(oldB.completion.getVerifiedSignatures(), newB.completion.getVerifiedSignatures());
        Set<VerifiedAntiExfilSignature> stale = new LinkedHashSet<>(a.completion.getVerifiedSignatures());
        stale.addAll(oldB.completion.getVerifiedSignatures());
        assertRejected(f, a, newB.signed, stale, "REQUIRED_PROOF_MISSING");
    }

    @Test void transactionMutationInvalidatesProofsAtEventBoundary() throws Exception {
        Fixture f = fixture(2, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run b = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        PSBT mutated = copy(b.signed);
        mutated.getTransaction().setLocktime(12345);
        assertTrue(AntiExfilPolicy.retainMatchingProofs(f.wallet, mutated, union(a, b)).isEmpty());
        assertRejected(f, a, mutated, union(a, b), "REQUIRED_PROOF_MISSING");
    }

    @Test void unrelatedProofIsInvalidEvenWhenRequiredSignaturesAreCovered() throws Exception {
        Fixture f = fixture(2, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run b = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        PSBT different = copy(f.psbt);
        different.getTransaction().setLocktime(12345);
        Run foreign = complete(different, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        Set<VerifiedAntiExfilSignature> proofs = union(a, b);
        proofs.addAll(foreign.completion.getVerifiedSignatures());
        assertRejected(f, a, b.signed, proofs, "INVALID_PROVENANCE");
    }

    @Test void restoreRevalidatesBothCeremoniesAndRejectsCorruptedSession() throws Exception {
        Fixture f = fixture(3, "RR");
        Run a = complete(f.psbt, f.privateSigners.get(0), f.wallet.getKeystores().get(0));
        Run b = complete(a.signed, f.privateSigners.get(1), f.wallet.getKeystores().get(1));
        Path root = temporary.resolve("restore");
        Path journals = temporary.resolve("restore-journals");
        Files.createDirectories(journals);
        for(Run run : List.of(a, b)) {
            String identity = Utils.bytesToHex(AntiExfilCoordinator.getWalletKeyIdentity(run.signer));
            Path directory = root.resolve(identity);
            Files.createDirectories(directory);
            Files.copy(run.session, directory.resolve("complete.aexs"));
            Files.copy(run.journal, journals.resolve(identity + ".aexj"));
        }
        Set<VerifiedAntiExfilSignature> restored = AntiExfilProvenanceStore.resolve(root, journals, f.wallet, b.signed);
        assertEquals(union(a, b), restored);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(f.wallet, b.signed, restored));
        PSBT changed = copy(b.signed);
        changed.getTransaction().setLocktime(12345);
        assertTrue(AntiExfilProvenanceStore.resolve(root, journals, f.wallet, changed).isEmpty());
        String identity = Utils.bytesToHex(AntiExfilCoordinator.getWalletKeyIdentity(b.signer));
        Path savedB = root.resolve(identity).resolve("complete.aexs");
        byte[] corrupt = Files.readAllBytes(savedB);
        corrupt[corrupt.length - 1] ^= 1;
        Files.write(savedB, corrupt);
        assertEquals(a.completion.getVerifiedSignatures(),
                AntiExfilProvenanceStore.resolve(root, journals, f.wallet, b.signed));
    }

    private void assertRejected(Fixture f, Run a, PSBT incoming, Set<VerifiedAntiExfilSignature> proofs,
                                String status) throws Exception {
        fx(() -> {
            try(Harness h = new Harness(f.wallet, copy(f.psbt))) {
                h.post(a, f.psbt);
                byte[] before = h.data.getPsbt().serialize();
                h.post(incoming, a.signed, proofs);
                assertEquals(1, h.observer.merges);
                assertTrue(h.alerts.toString().contains(status), h.alerts.toString());
                assertArrayEquals(before, h.data.getPsbt().serialize());
                assertEquals(a.completion.getVerifiedSignatures(), h.data.getVerifiedAntiExfilSignatures());
            }
            return null;
        });
    }

    private Fixture fixture(int size, String policies) throws Exception {
        JsonObject vector;
        try(var reader = new InputStreamReader(getClass().getResourceAsStream(
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
        if(size == 3) signers.add(Keystore.fromSeed(new DeterministicSeed(
                RESERVE_MNEMONIC, "", 0,
                DeterministicSeed.Type.BIP39), PolicyType.MULTI_HD, KeyDerivation.parsePath("m/48'/1'/2'/2'")));
        Wallet wallet = new Wallet("public deterministic regression");
        for(int i = 0; i < size; i++) {
            Keystore publicSigner = signers.get(i).copy();
            publicSigner.setSeed(null);
            publicSigner.setMasterPrivateExtendedKey(null);
            publicSigner.setSource(KeystoreSource.HW_AIRGAPPED);
            publicSigner.setLabel("Signer " + i);
            publicSigner.setWalletModel(i == 1 ? WalletModel.KERN : WalletModel.SEEDSIGNER);
            publicSigner.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);
            publicSigner.setAntiExfilPolicy(i >= 2 || policies.charAt(i) == 'R'
                    ? AntiExfilKeystorePolicy.REQUIRED : AntiExfilKeystorePolicy.OPTIONAL);
            wallet.getKeystores().add(publicSigner);
        }
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        PSBT psbt = new PSBT(Utils.hexToBytes(vector.get("original_psbt_hex").getAsString()), false);
        psbt.getPsbtInputs().getFirst().getPartialSignatures().clear();
        if(size == 3) {
            ECKey c = childKey(signers.get(2));
            psbt.getPsbtInputs().getFirst().getDerivedPublicKeys().put(ECKey.fromPublicOnly(c.getPubKey()),
                    new KeyDerivation(signers.get(2).getKeyDerivation().getMasterFingerprint(),
                            signers.get(2).getKeyDerivation().getDerivationPath() + "/0/0"));
            Script witness = ScriptType.MULTISIG.getOutputScript(2,
                    psbt.getPsbtInputs().getFirst().getDerivedPublicKeys().keySet());
            psbt.getPsbtInputs().getFirst().setWitnessScript(witness);
            psbt.getPsbtInputs().getFirst().setWitnessUtxo(new TransactionOutput(null, 100000,
                    ScriptType.P2WSH.getOutputScript(witness)));
        }
        psbt = copy(psbt);
        wallet.checkWallet();
        assertTrue(wallet.canSign(psbt), "real wallet attribution must apply");
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
            assertArrayEquals(privateKey.getPubKey(), slot.getSignerPublicKey());
            BigInteger tweak = new BigInteger(1, Utils.taggedHash("s2c/ecdsa/point",
                    Utils.concat(opening, slot.getHostRandomness())));
            BigInteger n = N;
            assertTrue(tweak.compareTo(n) < 0);
            BigInteger k = nonce.add(tweak).mod(n);
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(ECKey.fromPrivate(k).getPubKey(), 1, 33)).mod(n);
            BigInteger s = k.modInverse(n).multiply(new BigInteger(1, slot.getMessageHash())
                    .add(r.multiply(privateKey.getPrivKey()))).mod(n);
            if(s.compareTo(N.shiftRight(1)) > 0) s = n.subtract(s);
            byte[] compact = Utils.concat(Utils.bigIntegerToBytes(r, 32), Utils.bigIntegerToBytes(s, 32));
            assertTrue(AntiExfilCrypto.verify(slot.getSignerPublicKey(), slot.getMessageHash(),
                    slot.getHostRandomness(), opening, compact));
            signatures.add(slot(slot, opening, compact));
        }
        AntiExfilCoordinator.Completion completion = coordinator.complete(AntiExfilCodec.encode(
                message(commit, AntiExfilStage.SIGNER_SIGNATURES, signatures)));
        assertEquals(completion.getVerifiedSignatures(), AntiExfilCoordinator.load(session, journal, publicSigner)
                .getCompletedResult().getVerifiedSignatures());
        return new Run(completion, new PSBT(completion.getSignedPsbt(), false), publicSigner, session, journal);
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
    private static PSBT copy(PSBT psbt) throws Exception { return new PSBT(psbt.serialize(), false); }
    private static Set<VerifiedAntiExfilSignature> union(Run a, Run b) {
        Set<VerifiedAntiExfilSignature> proofs = new LinkedHashSet<>(a.completion.getVerifiedSignatures());
        proofs.addAll(b.completion.getVerifiedSignatures());
        return proofs;
    }
    private static <T> T fx(Callable<T> callable) throws Exception {
        FutureTask<T> task = new FutureTask<>(callable);
        Platform.runLater(task);
        return task.get(25, TimeUnit.SECONDS);
    }
    private record Fixture(Wallet wallet, PSBT psbt, List<Keystore> privateSigners) {}
    private record Run(AntiExfilCoordinator.Completion completion, PSBT signed, Keystore signer,
                       Path session, Path journal) {}
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
    private static final class Harness implements AutoCloseable {
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
            // Keep wallet lookup and dialog services; never dispatch service/network events.
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
            stage.setScene(new Scene(tabs)); // No window is shown, no application initialize() or services start.
            Field field = AppController.class.getDeclaredField("tabs");
            field.setAccessible(true);
            field.set(controller, tabs);
            EventManager.get().register(controller);
            EventManager.get().register(observer);
        }
        void post(Run run, PSBT context) { post(run.signed, context, run.completion.getVerifiedSignatures()); }
        void setOpenWallets(List<Wallet> wallets) throws Exception {
            Field windows = AppServices.class.getDeclaredField("walletWindows");
            windows.setAccessible(true);
            @SuppressWarnings("unchecked") Map<Window, List<WalletTabData>> map =
                    (Map<Window, List<WalletTabData>>)windows.get(AppServices.get());
            map.put(stage, wallets.stream().map(wallet -> new WalletTabData(TabData.TabType.WALLET, null) {
                @Override public Wallet getWallet() { return wallet; }
                @Override public Storage getStorage() { return null; }
            }).map(walletTab -> (WalletTabData)walletTab).toList());
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
            assertEquals(merges, observer.merges);
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
