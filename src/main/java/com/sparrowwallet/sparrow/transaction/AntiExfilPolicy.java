package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Wallet;

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
}
