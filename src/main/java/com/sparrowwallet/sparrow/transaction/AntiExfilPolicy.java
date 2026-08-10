package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionInput;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Wallet;

import java.util.Collection;
import java.util.Collections;

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
}
