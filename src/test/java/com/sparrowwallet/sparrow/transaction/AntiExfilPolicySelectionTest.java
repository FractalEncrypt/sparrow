package com.sparrowwallet.sparrow.transaction;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.antiexfil.AntiExfilPsbt;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator;
import com.sparrowwallet.drongo.antiexfil.VerifiedAntiExfilSignature;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionInput;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.BlockTransaction;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AntiExfilPolicySelectionTest {
    @Test
    void requiredCompatibleSignerCannotSilentlyFallBackToOptionalSigner() {
        Wallet wallet = new Wallet("test");
        Keystore required = compatible("Required", WalletModel.SPECTER_DIY, AntiExfilKeystorePolicy.REQUIRED);
        Keystore optional = compatible("Optional", WalletModel.SEEDSIGNER, AntiExfilKeystorePolicy.OPTIONAL);
        Keystore unsupported = compatible("Unsupported", WalletModel.PASSPORT, AntiExfilKeystorePolicy.UNSUPPORTED);
        wallet.getKeystores().addAll(List.of(required, optional, unsupported));

        assertEquals(List.of(required), HeadersController.getAntiExfilKeystores(wallet));

        required.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
        assertEquals(List.of(required, optional), HeadersController.getAntiExfilKeystores(wallet));
    }

    @Test
    void returnedRequiredSignatureNeedsProtectedProvenance() {
        Keystore required = compatible("Required", WalletModel.SPECTER_DIY, AntiExfilKeystorePolicy.REQUIRED);
        Keystore optional = compatible("Optional", WalletModel.SEEDSIGNER, AntiExfilKeystorePolicy.OPTIONAL);
        AttributedWallet wallet = new AttributedWallet(required);

        assertTrue(AntiExfilPolicy.requiresProtectedSigning(wallet));
        assertTrue(AntiExfilPolicy.hasRequiredSignature(wallet, (PSBT)null));
        wallet.signer = optional;
        assertFalse(AntiExfilPolicy.hasRequiredSignature(wallet, (PSBT)null));
        required.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
        assertFalse(AntiExfilPolicy.requiresProtectedSigning(wallet));
    }

    @Test
    void unattributableSignedReturnFailsClosedForExpectedRequiredSigner() {
        Keystore required = compatible("Required", WalletModel.SEEDSIGNER, AntiExfilKeystorePolicy.REQUIRED);
        Keystore optional = compatible("Optional", WalletModel.SPECTER_DIY, AntiExfilKeystorePolicy.OPTIONAL);

        assertTrue(AntiExfilPolicy.violatesRequiredPolicy(List.of(required), List.of(), true));
        assertFalse(AntiExfilPolicy.violatesRequiredPolicy(List.of(required), List.of(), false));
        assertFalse(AntiExfilPolicy.violatesRequiredPolicy(List.of(optional), List.of(), true));
        assertFalse(AntiExfilPolicy.violatesRequiredPolicy(List.of(required, optional), List.of(optional), true));
        assertTrue(AntiExfilPolicy.violatesRequiredPolicy(List.of(required, optional), List.of(required), true));
    }

    @Test
    void protectedSigningExportsCanonicalV0FromInternalV2() throws Exception {
        JsonObject vector;
        try(InputStreamReader reader = new InputStreamReader(getClass().getResourceAsStream(
                "/com/sparrowwallet/sparrow/io/protocol-v1-semantic-psbt-vector.json"), StandardCharsets.UTF_8)) {
            vector = JsonParser.parseReader(reader).getAsJsonObject();
        }
        byte[] canonicalV0 = Utils.hexToBytes(vector.get("psbt_hex").getAsString());
        PSBT internal = new PSBT(canonicalV0, false);
        internal.convertVersion(2);

        assertEquals(2, internal.getVersion());
        byte[] exported = HeadersController.getAntiExfilPsbtBytes(internal);
        assertNull(AntiExfilPsbt.parseCanonicalV0(exported).getVersion());
        assertArrayEquals(canonicalV0, exported);
    }

    @Test
    void mixedRequiredMultisigRejectsOrdinarySignatureNotCoveredByProof(@TempDir Path temporary) throws Exception {
        JsonObject vector = mixedVector();
        JsonObject signerA = vector.getAsJsonObject("signer_a");
        JsonObject signerB = vector.getAsJsonObject("signer_b");
        Keystore requiredA = signingKeystore("Required A", signerA, AntiExfilKeystorePolicy.REQUIRED);
        Keystore requiredB = signingKeystore("Required B", signerB, AntiExfilKeystorePolicy.REQUIRED);
        Wallet wallet = new Wallet("mixed");
        wallet.getKeystores().addAll(List.of(requiredA, requiredB));
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH,
                wallet.getKeystores(), 2));
        byte[] original = Utils.hexToBytes(vector.get("original_psbt_hex").getAsString());
        PSBT signed = new PSBT(Utils.hexToBytes(vector.get("signed_psbt_hex").getAsString()), false);
        AntiExfilCoordinator coordinator = createDeterministic(temporary.resolve("proof.aexs"),
                temporary.resolve("proof.aexj"), original, requiredA);
        coordinator.acceptOpenings(Utils.hexToBytes(vector.get("message_2_hex").getAsString()));
        VerifiedAntiExfilSignature proofA = coordinator
                .complete(Utils.hexToBytes(vector.get("message_4_hex").getAsString()))
                .getVerifiedSignatures().iterator().next();
        assertArrayEquals(Utils.hexToBytes(vector.get("protected_signature_a_compact").getAsString()),
                proofA.getCompactSignature());

        Wallet onlyAPrivate = wallet.copy();
        onlyAPrivate.getKeystores().get(1).setSeed(null);
        onlyAPrivate.getKeystores().get(1).setMasterPrivateExtendedKey(null);
        assertTrue(HeadersController.violatesRequiredSoftwareSigning(wallet, onlyAPrivate,
                new PSBT(original, false)));
        requiredA.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
        assertFalse(HeadersController.violatesRequiredSoftwareSigning(wallet, onlyAPrivate,
                new PSBT(original, false)));
        requiredA.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED);

        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, signed, Set.of(proofA)));

        requiredB.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, signed, Set.of(proofA)));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, signed, Set.of()));

        requiredB.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED);
        wallet.finalise(signed);
        assertTrue(signed.isFinalized());
        assertNotEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, signed, Set.of(proofA)));
        TransactionData finalizedTab = new TransactionData("finalized", signed, Set.of(proofA));
        finalizedTab.setSigningWallet(wallet);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                HeadersController.evaluateTransactionProvenance(finalizedTab));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, null, signed.extractTransaction(), Set.of(proofA)));
    }

    @Test
    void reloadsOnlyRevalidatedMatchingProofsAndIgnoresUntrustedIndex(@TempDir Path temporary) throws Exception {
        JsonObject vector = mixedVector();
        Keystore signerA = signingKeystore("Required A", vector.getAsJsonObject("signer_a"),
                AntiExfilKeystorePolicy.REQUIRED);
        Keystore signerB = signingKeystore("Required B", vector.getAsJsonObject("signer_b"),
                AntiExfilKeystorePolicy.REQUIRED);
        Wallet wallet = new Wallet("mixed");
        wallet.getKeystores().addAll(List.of(signerA, signerB));
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH,
                wallet.getKeystores(), 2));
        byte[] original = Utils.hexToBytes(vector.get("original_psbt_hex").getAsString());
        PSBT signed = new PSBT(Utils.hexToBytes(vector.get("signed_psbt_hex").getAsString()), false);
        Path walletRoot = temporary.resolve("sessions");
        Path journals = temporary.resolve("journals");
        String identity = Utils.bytesToHex(AntiExfilCoordinator.getWalletKeyIdentity(signerA));
        Path session = walletRoot.resolve(identity).resolve(vector.get("original_psbt_sha256").getAsString() + ".aexs");
        Path journal = journals.resolve(identity + ".aexj");
        AntiExfilCoordinator coordinator = createDeterministic(session, journal, original, signerA);
        coordinator.acceptOpenings(Utils.hexToBytes(vector.get("message_2_hex").getAsString()));
        coordinator.complete(Utils.hexToBytes(vector.get("message_4_hex").getAsString()));

        Files.writeString(walletRoot.resolve("provenance-v1.index"),
                Utils.bytesToHex(Sha256Hash.hash(signed.serialize())) + " ../../outside.aexs\n",
                StandardCharsets.UTF_8);
        Set<VerifiedAntiExfilSignature> resolved = AntiExfilProvenanceStore.resolve(
                walletRoot, journals, wallet, signed);
        assertEquals(1, resolved.size());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, signed, resolved));

        signerB.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
        wallet.finalise(signed);
        assertTrue(signed.isFinalized());
        Set<VerifiedAntiExfilSignature> resolvedFinalized = AntiExfilProvenanceStore.resolve(
                walletRoot, journals, wallet, signed);
        assertEquals(1, resolvedFinalized.size());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, signed, resolvedFinalized));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, signed, Set.of()));

        byte[] corrupt = Files.readAllBytes(session);
        corrupt[corrupt.length - 1] ^= 1;
        Files.write(session, corrupt);
        assertTrue(AntiExfilProvenanceStore.resolve(walletRoot, journals, wallet, signed).isEmpty());
    }

    @Test
    void rawTransactionQuarantineRequiresPositiveCompleteOptionalAttribution() throws Exception {
        Transaction transaction = finalizedMixedTransaction();
        Keystore optionalA = compatible("Optional A", WalletModel.SEEDSIGNER, AntiExfilKeystorePolicy.OPTIONAL);
        Keystore optionalB = compatible("Optional B", WalletModel.SEEDSIGNER, AntiExfilKeystorePolicy.OPTIONAL);
        Keystore required = compatible("Required", WalletModel.SEEDSIGNER, AntiExfilKeystorePolicy.REQUIRED);
        Wallet partialWallet = new RawAttributedWallet(List.of(optionalA));
        Wallet permittedWallet = new RawAttributedWallet(List.of(optionalA, optionalB));
        Wallet requiredWallet = new RawAttributedWallet(List.of(optionalA, required));

        assertEquals(AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE,
                AntiExfilPolicy.evaluateRawTransactionProvenance(null, transaction));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE,
                AntiExfilPolicy.evaluateRawTransactionProvenance(partialWallet, transaction));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateRawTransactionProvenance(permittedWallet, transaction));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateRawTransactionProvenance(requiredWallet, transaction));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.INVALID_PROVENANCE,
                AntiExfilPolicy.evaluateRawTransactionProvenance(new RawAttributedWallet(), transaction));
        assertNull(HeadersController.selectRawTransactionPolicyWallet(List.of(partialWallet), transaction));
        assertEquals(permittedWallet, HeadersController.selectRawTransactionPolicyWallet(
                List.of(partialWallet, permittedWallet), transaction));
        assertEquals(requiredWallet, HeadersController.selectRawTransactionPolicyWallet(
                List.of(permittedWallet, requiredWallet), transaction));
        assertEquals(requiredWallet, HeadersController.selectRawTransactionPolicyWallet(
                List.of(requiredWallet, permittedWallet), transaction));

        TransactionData tab = new TransactionData("raw", transaction);
        tab.setSigningWallet(permittedWallet);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                HeadersController.getRawTransactionProvenance(tab));
        tab.setSigningWallet(requiredWallet);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                HeadersController.getRawTransactionProvenance(tab));
        tab.setSigningWallet(null);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE,
                HeadersController.getRawTransactionProvenance(tab));
    }

    @Test
    void internalSweepExemptionIsLocalEphemeralAndDigestBound() throws Exception {
        Transaction transaction = finalizedMixedTransaction();
        TransactionData internalSweep = new TransactionData("sweep", transaction,
                TransactionData.Origin.INTERNAL_SWEEP, 114L);

        assertTrue(internalSweep.hasValidInternalSweepOrigin());
        assertEquals(114L, internalSweep.getInternalSweepFee());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                HeadersController.getRawTransactionProvenance(internalSweep));
        assertTrue(HeadersController.shouldDisableViewFinal(internalSweep,
                AntiExfilPolicy.ProvenanceStatus.PERMITTED));

        Transaction reopened = new Transaction(transaction.bitcoinSerialize());
        TransactionData savedAndReopened = new TransactionData("reopened", reopened);
        TransactionData crossWindow = new TransactionData("forwarded", new Transaction(transaction.bitcoinSerialize()));
        assertFalse(savedAndReopened.hasValidInternalSweepOrigin());
        assertFalse(crossWindow.hasValidInternalSweepOrigin());
        assertTrue(HeadersController.shouldInitializeSignedRawTransactionControls(savedAndReopened));
        assertTrue(HeadersController.shouldDisableViewFinal(savedAndReopened,
                AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE,
                HeadersController.getRawTransactionProvenance(savedAndReopened));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE,
                HeadersController.getRawTransactionProvenance(crossWindow));

        //Reference fetching may attach display metadata to an external raw transaction,
        //but that metadata is not wallet-policy attribution and must grant no authority.
        savedAndReopened.setBlockTransaction(new BlockTransaction(reopened.getTxId(), 0, null, null, reopened));
        assertFalse(HeadersController.shouldInitializeSignedRawTransactionControls(savedAndReopened));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE,
                HeadersController.getRawTransactionProvenance(savedAndReopened));

        transaction.setVersion(transaction.getVersion() + 1);
        assertFalse(internalSweep.hasValidInternalSweepOrigin());
        assertNull(internalSweep.getInternalSweepFee());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE,
                HeadersController.getRawTransactionProvenance(internalSweep));
    }

    private Transaction finalizedMixedTransaction() throws Exception {
        JsonObject vector = mixedVector();
        Wallet wallet = new Wallet("mixed");
        wallet.getKeystores().addAll(List.of(
                signingKeystore("A", vector.getAsJsonObject("signer_a"), AntiExfilKeystorePolicy.OPTIONAL),
                signingKeystore("B", vector.getAsJsonObject("signer_b"), AntiExfilKeystorePolicy.OPTIONAL)));
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH,
                wallet.getKeystores(), 2));
        PSBT signed = new PSBT(Utils.hexToBytes(vector.get("signed_psbt_hex").getAsString()), false);
        wallet.finalise(signed);
        return signed.extractTransaction();
    }

    private static Keystore compatible(String label, WalletModel model, AntiExfilKeystorePolicy policy) {
        Keystore keystore = new Keystore(label);
        keystore.setWalletModel(model);
        keystore.setAntiExfilPolicy(policy);
        return keystore;
    }

    private static Keystore signingKeystore(String label, JsonObject signer, AntiExfilKeystorePolicy policy) throws Exception {
        DeterministicSeed seed = new DeterministicSeed(signer.get("mnemonic").getAsString(), "", 0,
                DeterministicSeed.Type.BIP39);
        Keystore keystore = Keystore.fromSeed(seed, PolicyType.MULTI_HD,
                KeyDerivation.parsePath(signer.get("account_derivation").getAsString()));
        keystore.setLabel(label);
        keystore.setAntiExfilPolicy(policy);
        return keystore;
    }

    private JsonObject mixedVector() throws Exception {
        try(InputStreamReader reader = new InputStreamReader(getClass().getResourceAsStream(
                "/com/sparrowwallet/sparrow/io/protocol-v1-mixed-provenance-vector.json"), StandardCharsets.UTF_8)) {
            return JsonParser.parseReader(reader).getAsJsonObject();
        }
    }

    private static AntiExfilCoordinator createDeterministic(Path session, Path journal, byte[] original,
                                                             Keystore signer) throws Exception {
        java.lang.reflect.Method create = AntiExfilCoordinator.class.getDeclaredMethod("create",
                Path.class, Path.class, byte[].class, Keystore.class,
                com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork.class, boolean.class, SecureRandom.class);
        create.setAccessible(true);
        return (AntiExfilCoordinator)create.invoke(null, session, journal, original, signer,
                com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork.TESTNET4, false, new MixedVectorRandom());
    }

    private static byte[] repeat(byte value) {
        byte[] bytes = new byte[32];
        java.util.Arrays.fill(bytes, value);
        return bytes;
    }

    private static final class MixedVectorRandom extends SecureRandom {
        private int call;

        @Override
        public void nextBytes(byte[] bytes) {
            Arrays.fill(bytes, call++ == 0 ? (byte)'m' : (byte)0xa1);
        }
    }

    private static final class AttributedWallet extends Wallet {
        private Keystore signer;

        private AttributedWallet(Keystore signer) {
            super("test");
            this.signer = signer;
            getKeystores().add(signer);
        }

        @Override
        public Map<PSBTInput, Map<TransactionSignature, Keystore>> getSignedKeystores(PSBT psbt) {
            Map<TransactionSignature, Keystore> signatures = new LinkedHashMap<>();
            signatures.put(null, signer);
            Map<PSBTInput, Map<TransactionSignature, Keystore>> inputs = new LinkedHashMap<>();
            inputs.put(null, signatures);
            return inputs;
        }
    }

    private static final class RawAttributedWallet extends Wallet {
        private final List<Keystore> signers;
        private final boolean fail;

        private RawAttributedWallet(List<Keystore> signers) {
            super("raw");
            this.signers = signers;
            this.fail = false;
        }

        private RawAttributedWallet() {
            super("raw");
            this.signers = List.of();
            this.fail = true;
        }

        @Override
        public Map<TransactionInput, Map<TransactionSignature, Keystore>> getSignedKeystores(Transaction transaction) {
            if(fail) throw new IllegalStateException("attribution failed");
            List<TransactionSignature> signatures = transaction.getInputs().getFirst().getWitness().getSignatures();
            Map<TransactionSignature, Keystore> attributed = new LinkedHashMap<>();
            for(int i = 0; i < signers.size(); i++) {
                attributed.put(signatures.get(i), signers.get(i));
            }
            return Map.of(transaction.getInputs().getFirst(), attributed);
        }
    }
}
