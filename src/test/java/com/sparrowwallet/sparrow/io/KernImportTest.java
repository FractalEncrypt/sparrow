package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.AntiExfilProfile;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.WalletModel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class KernImportTest extends IoTest {
    @Test
    void specterCompatibleQrImportsAsKernOptionalAext() throws ImportException {
        Network.set(Network.TESTNET);
        try {
            Keystore keystore = new Kern().getKeystore(PolicyType.SINGLE_HD, ScriptType.P2WPKH,
                    getInputStream("specter-diy-keystore.txt"), null);
            assertEquals(WalletModel.KERN, keystore.getWalletModel());
            assertEquals("Kern", keystore.getLabel());
            assertEquals(AntiExfilKeystorePolicy.OPTIONAL, keystore.getAntiExfilPolicy());
            assertEquals(AntiExfilProfile.AEXT_V1, keystore.getAntiExfilProfile());
        } finally {
            Network.set(Network.MAINNET);
        }
    }
}
