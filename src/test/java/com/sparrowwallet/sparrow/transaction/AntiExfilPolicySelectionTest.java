package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AntiExfilPolicySelectionTest {
    @Test
    void requiredSeedSignerCannotSilentlyFallBackToOptionalSigner() {
        Wallet wallet = new Wallet("test");
        Keystore required = seedSigner("Required", true);
        Keystore optional = seedSigner("Optional", false);
        wallet.getKeystores().addAll(List.of(required, optional));

        assertEquals(List.of(required), HeadersController.getAntiExfilKeystores(wallet));

        required.setAntiExfilRequired(false);
        assertEquals(List.of(required, optional), HeadersController.getAntiExfilKeystores(wallet));
    }

    @Test
    void returnedRequiredSignatureNeedsProtectedProvenance() {
        Keystore required = seedSigner("Required", true);
        Keystore optional = seedSigner("Optional", false);
        AttributedWallet wallet = new AttributedWallet(required);

        assertTrue(AntiExfilPolicy.hasRequiredSignature(wallet, (PSBT)null));
        wallet.signer = optional;
        assertFalse(AntiExfilPolicy.hasRequiredSignature(wallet, (PSBT)null));
    }

    private static Keystore seedSigner(String label, boolean required) {
        Keystore keystore = new Keystore(label);
        keystore.setWalletModel(WalletModel.SEEDSIGNER);
        keystore.setAntiExfilRequired(required);
        return keystore;
    }

    private static final class AttributedWallet extends Wallet {
        private Keystore signer;

        private AttributedWallet(Keystore signer) {
            super("test");
            this.signer = signer;
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
}
