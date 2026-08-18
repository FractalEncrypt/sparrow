package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator;
import com.sparrowwallet.drongo.antiexfil.VerifiedAntiExfilSignature;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.SigHash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionInput;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Wallet;

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
        return wallet != null && wallet.getKeystores().stream().anyMatch(Keystore::isAntiExfilRequired);
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
        if(psbt.isFinalized()) {
            try {
                return evaluateSignatureProvenance(wallet, psbt, psbt.extractTransaction(), proofs);
            } catch(Exception exception) {
                return ProvenanceStatus.INVALID_PROVENANCE;
            }
        }
        Set<VerifiedAntiExfilSignature> availableProofs = proofs == null ? Collections.emptySet() : Set.copyOf(proofs);
        if(wallet == null) {
            return psbt.hasSignatures() ? ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE : ProvenanceStatus.PERMITTED;
        }

        Set<VerifiedAntiExfilSignature> matchedProofs = new HashSet<>();
        try {
            for(int inputIndex = 0; inputIndex < psbt.getPsbtInputs().size(); inputIndex++) {
                PSBTInput input = psbt.getPsbtInputs().get(inputIndex);
                for(Map.Entry<ECKey, TransactionSignature> signatureEntry : input.getPartialSignatures().entrySet()) {
                    Keystore signer = attributeSigner(wallet, input, signatureEntry.getKey());
                    if(signer == null) {
                        if(hasRequiredParticipant(wallet, input)) {
                            return ProvenanceStatus.REQUIRED_RETURN_UNATTRIBUTABLE;
                        }
                        continue;
                    }
                    VerifiedAntiExfilSignature matching = findMatchingProof(availableProofs, signer, input,
                            inputIndex, signatureEntry.getKey(), signatureEntry.getValue());
                    if(matching != null) matchedProofs.add(matching);
                    if(signer.isAntiExfilRequired() && matching == null) {
                        return ProvenanceStatus.REQUIRED_PROOF_MISSING;
                    }
                }
            }
        } catch(RuntimeException exception) {
            return ProvenanceStatus.INVALID_PROVENANCE;
        }

        return matchedProofs.containsAll(availableProofs)
                ? ProvenanceStatus.PERMITTED
                : ProvenanceStatus.INVALID_PROVENANCE;
    }

    public static Set<VerifiedAntiExfilSignature> retainMatchingProofs(Wallet wallet, PSBT psbt,
                                                                       Collection<VerifiedAntiExfilSignature> proofs) {
        if(wallet == null || psbt == null || proofs == null || proofs.isEmpty()) return Collections.emptySet();
        Set<VerifiedAntiExfilSignature> matching = new HashSet<>();
        try {
            if(psbt.isFinalized()) {
                Transaction transaction = psbt.extractTransaction();
                for(int inputIndex = 0; inputIndex < psbt.getPsbtInputs().size(); inputIndex++) {
                    PSBTInput input = psbt.getPsbtInputs().get(inputIndex);
                    for(TransactionSignature signature : getFinalSignatures(transaction.getInputs().get(inputIndex))) {
                        AttributedFinalSignature attributed = attributeFinalSignature(wallet, input, signature);
                        if(attributed == null) continue;
                        VerifiedAntiExfilSignature proof = findMatchingProof(Set.copyOf(proofs),
                                attributed.signer(), input, inputIndex, attributed.publicKey(), signature);
                        if(proof != null) matching.add(proof);
                    }
                }
            } else {
                for(int inputIndex = 0; inputIndex < psbt.getPsbtInputs().size(); inputIndex++) {
                    PSBTInput input = psbt.getPsbtInputs().get(inputIndex);
                    for(Map.Entry<ECKey, TransactionSignature> signatureEntry : input.getPartialSignatures().entrySet()) {
                        Keystore signer = attributeSigner(wallet, input, signatureEntry.getKey());
                        if(signer == null) continue;
                        VerifiedAntiExfilSignature proof = findMatchingProof(Set.copyOf(proofs), signer, input,
                                inputIndex, signatureEntry.getKey(), signatureEntry.getValue());
                        if(proof != null) matching.add(proof);
                    }
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
        if(wallet == null || contextPsbt == null || transaction == null) {
            return hasSignatures(transaction) ? ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE : ProvenanceStatus.PERMITTED;
        }
        Set<VerifiedAntiExfilSignature> availableProofs = proofs == null ? Collections.emptySet() : Set.copyOf(proofs);
        Set<VerifiedAntiExfilSignature> matchedProofs = new HashSet<>();
        boolean attributedAny = false;
        try {
            if(transaction.getInputs().size() != contextPsbt.getPsbtInputs().size()) {
                return ProvenanceStatus.INVALID_PROVENANCE;
            }
            for(int inputIndex = 0; inputIndex < contextPsbt.getPsbtInputs().size(); inputIndex++) {
                PSBTInput contextInput = contextPsbt.getPsbtInputs().get(inputIndex);
                for(TransactionSignature signature : getFinalSignatures(transaction.getInputs().get(inputIndex))) {
                    AttributedFinalSignature attributed = attributeFinalSignature(wallet, contextInput, signature);
                    if(attributed == null) {
                        if(hasRequiredParticipant(wallet, contextInput)) {
                            return ProvenanceStatus.REQUIRED_RETURN_UNATTRIBUTABLE;
                        }
                        continue;
                    }
                    attributedAny = true;
                    VerifiedAntiExfilSignature matching = findMatchingProof(availableProofs,
                            attributed.signer(), contextInput, inputIndex, attributed.publicKey(), signature);
                    if(matching != null) matchedProofs.add(matching);
                    if(attributed.signer().isAntiExfilRequired() && matching == null) {
                        return ProvenanceStatus.REQUIRED_PROOF_MISSING;
                    }
                }
            }
            if(hasSignatures(transaction) && !attributedAny
                    && contextPsbt.getPsbtInputs().stream().anyMatch(input -> hasRequiredParticipant(wallet, input))) {
                return ProvenanceStatus.REQUIRED_RETURN_UNATTRIBUTABLE;
            }
        } catch(RuntimeException exception) {
            return ProvenanceStatus.INVALID_PROVENANCE;
        }
        return matchedProofs.containsAll(availableProofs)
                ? ProvenanceStatus.PERMITTED
                : ProvenanceStatus.INVALID_PROVENANCE;
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

    private static List<TransactionSignature> getFinalSignatures(TransactionInput input) {
        Set<TransactionSignature> signatures = new LinkedHashSet<>();
        if(input.hasWitness()) signatures.addAll(input.getWitness().getSignatures());
        signatures.addAll(input.getScriptSig().getSignatures());
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
