package com.sparrowwallet.sparrow.wallet;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Wallet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeystoreControllerImportTest {
    private static final String FIRST_XPUB = "xpub6DM7CYgaTMdMbhTcLTUWmNUE5WLXK5hx8ZMa4sRw8qYJPqtqKYiKnwsmT8A6AijDVAUZRivdBnXdR8QE7Y9vVnqvzPL3fXCmu1WtCRLdAoz";
    private static final String SECOND_XPUB = "xpub6EMVvcTUbaABdaPLaVWE72CjcN72URa5pKK1knrKLz1hKaDwUkgddc3832a8MHEpLyuow7MfjMRomt2iMtwPH4pWrFLft4JsquHjeZfKsYp";

    @Test
    void rejectsImportedXpubAlreadyUsedByAnotherCosigner() {
        Wallet wallet = new Wallet();
        Keystore first = keystore("First", FIRST_XPUB);
        Keystore current = new Keystore("Second");
        wallet.getKeystores().add(first);
        wallet.getKeystores().add(current);

        assertTrue(KeystoreController.duplicatesAnotherKeystore(wallet, current, keystore("Imported", FIRST_XPUB)));
        assertFalse(KeystoreController.duplicatesAnotherKeystore(wallet, current, keystore("Imported", SECOND_XPUB)));
    }

    @Test
    void allowsReimportingTheCurrentKeystore() {
        Wallet wallet = new Wallet();
        Keystore current = keystore("Current", FIRST_XPUB);
        wallet.getKeystores().add(current);

        assertFalse(KeystoreController.duplicatesAnotherKeystore(wallet, current, keystore("Imported", FIRST_XPUB)));
    }

    private static Keystore keystore(String label, String xpub) {
        Keystore keystore = new Keystore(label);
        keystore.setExtendedPublicKey(ExtendedKey.fromDescriptor(xpub));
        return keystore;
    }
}
