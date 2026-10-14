package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator;
import com.sparrowwallet.drongo.antiexfil.VerifiedAntiExfilSignature;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionInput;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.protocol.TransactionWitness;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.drongo.wallet.WalletNode;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class AntiExfilPolicy {
    private AntiExfilPolicy() {
    }

    public static boolean requiresProtectedSigning(Wallet wallet) {
        return false; // No global Required/provenance enforcement in the RAM-only design.
    }

    public static ProvenanceStatus evaluatePsbtEgress(TransactionData transactionData) {
        if(transactionData == null || transactionData.getPsbt() == null) return ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE;
        return validateFinalizedSignatures(transactionData.getPsbt());
    }

    private static ProvenanceStatus validateFinalizedSignatures(PSBT psbt) {
        try {
            psbt.verifySignatures();
            return psbt.verifyKnownFinalizedSignatures()
                    ? ProvenanceStatus.PERMITTED : ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE;
        } catch(Exception exception) {
            return ProvenanceStatus.INVALID_PROVENANCE;
        }
    }

    public static boolean hasRequiredSignature(Wallet wallet, PSBT psbt) {
        return wallet.getSignedKeystores(psbt).values().stream()
                .flatMap(signatures -> signatures.values().stream())
                .anyMatch(Keystore::isAntiExfilRequired);
    }

    public static boolean hasRequiredSignature(Wallet wallet, Transaction transaction) {
        return wallet.getSignedKeystores(transaction).values().stream()
                .flatMap(signatures -> signatures.values().stream())
                .anyMatch(Keystore::isAntiExfilRequired);
    }

    public static ProvenanceStatus evaluateSignatureProvenance(Wallet wallet, PSBT psbt,
                                                                Set<VerifiedAntiExfilSignature> proofs) {
        if(psbt == null) return ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE;
        // The active coordinator verifies the AE transcript before producing a result.
        // Import/egress uses ordinary Bitcoin validation; transient badges never authorize it.
        return validateFinalizedSignatures(psbt);
    }

    public static Set<VerifiedAntiExfilSignature> retainMatchingProofs(Wallet wallet, PSBT psbt,
                                                                       Collection<VerifiedAntiExfilSignature> proofs) {
        if(wallet == null || psbt == null || proofs == null || proofs.isEmpty()) return Collections.emptySet();
        Set<VerifiedAntiExfilSignature> availableProofs = Set.copyOf(proofs);
        Set<VerifiedAntiExfilSignature> matching = new HashSet<>();
        try {
            psbt = withWalletDerivations(wallet, psbt, availableProofs);
            for(int inputIndex = 0; inputIndex < psbt.getPsbtInputs().size(); inputIndex++) {
                PSBTInput input = psbt.getPsbtInputs().get(inputIndex);
                for(Map.Entry<ECKey, TransactionSignature> signatureEntry : input.getPartialSignatures().entrySet()) {
                    Keystore signer = attributeSigner(wallet, input, signatureEntry.getKey());
                    if(signer == null) continue;
                    VerifiedAntiExfilSignature proof = findMatchingProof(availableProofs, signer, input,
                            inputIndex, signatureEntry.getKey(), signatureEntry.getValue());
                    if(proof != null) matching.add(proof);
                }
                // Mirror provenance evaluation per input, including final fields in a mixed-finalized PSBT.
                for(TransactionSignature signature : getFinalInputSignatures(input)) {
                    AttributedFinalSignature attributed = attributeFinalSignature(wallet, input, signature);
                    if(attributed == null) continue;
                    VerifiedAntiExfilSignature proof = findMatchingProof(availableProofs,
                            attributed.signer(), input, inputIndex, attributed.publicKey(), signature);
                    if(proof != null) matching.add(proof);
                }
            }
        } catch(Exception ignored) {
            return Collections.emptySet();
        }
        return Set.copyOf(matching);
    }

    public static ProvenanceStatus evaluateSignatureProvenance(Wallet wallet, PSBT contextPsbt,
                                                                Transaction transaction,
                                                                Set<VerifiedAntiExfilSignature> proofs) {
        if(contextPsbt == null || transaction == null) return ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE;
        // Context and transaction mutation checks remain in the ordinary handlers.
        return validateFinalizedSignatures(contextPsbt);
    }

    public static ProvenanceStatus evaluateRawTransactionProvenance(Wallet wallet, Transaction transaction) {
        return transaction == null ? ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE : ProvenanceStatus.PERMITTED;
    }

    private static AttributedFinalSignature attributeFinalSignature(Wallet wallet, PSBTInput input,
                                                                      TransactionSignature signature) {
        // A reopened or synthetic PSBT may have no wallet transaction-history nodes. Attribute
        // final signatures from the authoritative PSBT derivations and signing digest instead.
        AttributedFinalSignature attributed = null;
        byte[] messageHash = input.getSigningHash().getBytes();
        for(Map.Entry<ECKey, KeyDerivation> derivation : input.getDerivedPublicKeys().entrySet()) {
            Keystore signer = attributeSigner(wallet, input, derivation.getKey());
            if(signer == null || !signature.verify(messageHash, derivation.getKey())) continue;
            if(attributed != null && (!attributed.signer().equals(signer)
                    || !Arrays.equals(attributed.publicKey().getPubKey(), derivation.getKey().getPubKey()))) {
                return null;
            }
            attributed = new AttributedFinalSignature(signer, derivation.getKey());
        }
        return attributed;
    }

    private static int countFinalSignatures(Transaction transaction) {
        if(transaction == null) return 0;
        return transaction.getInputs().stream().mapToInt(input -> getFinalSignatures(input).size()).sum();
    }

    private static List<TransactionSignature> getFinalSignatures(TransactionInput input) {
        Set<TransactionSignature> signatures = new LinkedHashSet<>();
        if(input.hasWitness()) signatures.addAll(input.getWitness().getSignatures());
        signatures.addAll(input.getScriptSig().getSignatures());
        return new ArrayList<>(signatures);
    }

    private static List<TransactionSignature> getFinalInputSignatures(PSBTInput input) {
        Set<TransactionSignature> signatures = new LinkedHashSet<>();
        TransactionWitness witness = input.getFinalScriptWitness();
        if(witness != null) signatures.addAll(witness.getSignatures());
        Script scriptSig = input.getFinalScriptSig();
        if(scriptSig != null) signatures.addAll(scriptSig.getSignatures());
        return new ArrayList<>(signatures);
    }

    private static VerifiedAntiExfilSignature findMatchingProof(Set<VerifiedAntiExfilSignature> proofs,
                                                                 Keystore signer, PSBTInput input, int inputIndex,
                                                                 ECKey publicKey, TransactionSignature signature) {
        byte[] walletIdentity = AntiExfilCoordinator.getWalletKeyIdentity(signer);
        byte[] outpoint = input.getInput().getOutpoint().bitcoinSerialize();
        byte[] messageHash = input.getSigningHash().getBytes();
        for(VerifiedAntiExfilSignature proof : proofs) {
            if(proof.getInputIndex() == inputIndex
                    && proof.getSighashType() == Byte.toUnsignedLong(signature.sighashFlags)
                    && Arrays.equals(proof.getWalletKeyIdentity(), walletIdentity)
                    && Arrays.equals(proof.getOutpoint(), outpoint)
                    && Arrays.equals(proof.getSignerPublicKey(), publicKey.getPubKey())
                    && Arrays.equals(proof.getMessageHash(), messageHash)
                    && signature.equals(asTransactionSignature(proof))) {
                return proof;
            }
        }
        return null;
    }

    private static TransactionSignature asTransactionSignature(VerifiedAntiExfilSignature proof) {
        byte[] compact = proof.getCompactSignature();
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(compact, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(compact, 32, 64));
        return new TransactionSignature(new ECDSASignature(r, s), SigHash.ALL);
    }

    /**
     * Returns a copy of the PSBT whose inputs carry the BIP32 derivations of every keystore of the wallet node
     * that the input's UTXO script belongs to. A returned PSBT may omit, truncate or relabel its derivations
     * (SeedSigner's trimmed output carries none), so attribution must not depend on what the PSBT chose to keep.
     * Derivations are still verified against the keystore xpubs by attributeSigner before they attribute anything.
     * Without a Required keystore or a proof to match, attribution cannot change the result, so the PSBT is used as is.
     */
    private static PSBT withWalletDerivations(Wallet wallet, PSBT psbt, Collection<VerifiedAntiExfilSignature> proofs) {
        if(!requiresProtectedSigning(wallet) && (proofs == null || proofs.isEmpty())) return psbt;
        if(wallet.getPolicyType() == PolicyType.SINGLE_SP) return psbt;
        PSBT copy = psbt.copy();
        Map<PSBTInput, WalletNode> signingNodes = wallet.getSigningNodes(copy);
        for(PSBTInput input : copy.getPsbtInputs()) {
            WalletNode node = signingNodes.get(input);
            Wallet nodeWallet = node == null ? null : node.getWallet();
            if(nodeWallet == null || nodeWallet.getScriptType() == null || nodeWallet.getScriptType() == ScriptType.P2TR) continue;
            for(Keystore keystore : nodeWallet.getKeystores()) {
                if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) continue;
                ECKey publicKey = nodeWallet.getScriptType().getOutputKey(nodeWallet.getPolicyType(), keystore.getPubKey(node));
                input.getDerivedPublicKeys().put(publicKey, keystore.getKeyDerivation().extend(node.getDerivation()));
            }
        }
        return copy;
    }

    private static Keystore attributeSigner(Wallet wallet, PSBTInput input, ECKey publicKey) {
        KeyDerivation derivation = input.getDerivedPublicKeys().get(publicKey);
        if(derivation == null) return null;
        Keystore attributed = null;
        for(Keystore keystore : wallet.getKeystores()) {
            if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) continue;
            if(attributeSignerForDerivation(keystore, publicKey, derivation)) {
                if(attributed != null) return null;
                attributed = keystore;
            }
        }
        return attributed;
    }

    private static boolean attributeSignerForDerivation(Keystore keystore, ECKey publicKey,
                                                         KeyDerivation derivation) {
        ECKey expected = keystore.getPubKeyForDerivation(derivation);
        return expected != null && Arrays.equals(expected.getPubKey(), publicKey.getPubKey());
    }

    private static boolean hasRequiredParticipant(Wallet wallet, PSBTInput input) {
        return input.getDerivedPublicKeys().keySet().stream()
                .map(publicKey -> attributeSigner(wallet, input, publicKey))
                .anyMatch(keystore -> keystore != null && keystore.isAntiExfilRequired());
    }

    public static boolean violatesRequiredPolicy(Wallet wallet, PSBT contextPsbt, PSBT returnedPsbt) {
        Collection<Keystore> expectedSigners = getExpectedSigners(wallet, contextPsbt);
        Collection<Keystore> attributedSigners = wallet.getSignedKeystores(returnedPsbt).values().stream()
                .flatMap(signatures -> signatures.values().stream())
                .toList();
        return violatesRequiredPolicy(expectedSigners, attributedSigners, returnedPsbt.hasSignatures());
    }

    public static boolean violatesRequiredPolicy(Wallet wallet, PSBT contextPsbt, Transaction returnedTransaction) {
        Collection<Keystore> expectedSigners = getExpectedSigners(wallet, contextPsbt);
        Collection<Keystore> attributedSigners = wallet.getSignedKeystores(returnedTransaction).values().stream()
                .flatMap(signatures -> signatures.values().stream())
                .toList();
        return violatesRequiredPolicy(expectedSigners, attributedSigners, hasSignatures(returnedTransaction));
    }

    static boolean violatesRequiredPolicy(Collection<Keystore> expectedSigners,
                                           Collection<Keystore> attributedSigners,
                                           boolean hasSignatures) {
        boolean requiredSignerExpected = expectedSigners.stream().anyMatch(Keystore::isAntiExfilRequired);
        if(!requiredSignerExpected || !hasSignatures) return false;

        if(attributedSigners.stream().anyMatch(Keystore::isAntiExfilRequired)) return true;

        // A finalized hardware-wallet return commonly omits the PSBT metadata required for
        // signature attribution. Required policy must fail closed in that case. A positively
        // attributed optional signer remains permitted in a mixed-policy wallet.
        return attributedSigners.isEmpty();
    }

    private static Collection<Keystore> getExpectedSigners(Wallet wallet, PSBT contextPsbt) {
        if(contextPsbt == null) return Collections.emptyList();
        return wallet.getSigningKeystores(contextPsbt);
    }

    private static boolean hasSignatures(Transaction transaction) {
        if(transaction == null) return false;
        for(TransactionInput input : transaction.getInputs()) {
            try {
                if(input.hasWitness() && !input.getWitness().getSignatures().isEmpty()) return true;
                if(!input.getScriptSig().getSignatures().isEmpty()) return true;
            } catch(RuntimeException ignored) {
                // Unknown signing material cannot be safely accepted for a required signer.
                if(input.hasWitness() || input.getScriptSig().getProgram().length > 0) return true;
            }
        }
        return false;
    }

    private record AttributedFinalSignature(Keystore signer, ECKey publicKey) {
    }

    public enum ProvenanceStatus {
        PERMITTED,
        REQUIRED_PROOF_MISSING,
        REQUIRED_RETURN_UNATTRIBUTABLE,
        POLICY_CONTEXT_UNAVAILABLE,
        INVALID_PROVENANCE
    }
}
