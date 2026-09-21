package com.sparrowwallet.sparrow.event;

import com.sparrowwallet.drongo.wallet.Keystore;

/**
 * This event is used to indicate the animation for signing a keystore is complete
 */
public class KeystoreSignedEvent {
    private final Keystore keystore;
    private final Object transactionContext;

    public KeystoreSignedEvent(Keystore keystore) {
        this(keystore, null);
    }

    public KeystoreSignedEvent(Keystore keystore, Object transactionContext) {
        this.keystore = keystore;
        this.transactionContext = transactionContext;
    }

    public Object getTransactionContext() {
        return transactionContext;
    }

    public Keystore getKeystore() {
        return keystore;
    }
}
