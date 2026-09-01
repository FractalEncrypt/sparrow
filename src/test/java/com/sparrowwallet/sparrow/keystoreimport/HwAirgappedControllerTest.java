package com.sparrowwallet.sparrow.keystoreimport;

import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.wallet.WalletModel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HwAirgappedControllerTest {
    @Test
    void exposesKernForSingleSignatureAndMultisigWallets() {
        assertEquals(1, countKern(PolicyType.SINGLE_HD));
        assertEquals(1, countKern(PolicyType.SINGLE_SP));
        assertEquals(1, countKern(PolicyType.MULTI_HD));
    }

    private static long countKern(PolicyType policyType) {
        return HwAirgappedController.fileImportersFor(policyType).stream()
                .filter(importer -> importer.getWalletModel() == WalletModel.KERN)
                .count();
    }
}
