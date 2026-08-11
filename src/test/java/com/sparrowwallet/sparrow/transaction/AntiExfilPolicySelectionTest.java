package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
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

    private static Keystore compatible(String label, WalletModel model, AntiExfilKeystorePolicy policy) {
        Keystore keystore = new Keystore(label);
        keystore.setWalletModel(model);
        keystore.setAntiExfilPolicy(policy);
        return keystore;
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
}
