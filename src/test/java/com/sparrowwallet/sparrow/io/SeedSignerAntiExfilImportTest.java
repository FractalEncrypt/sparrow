package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.WalletModel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SeedSignerAntiExfilImportTest extends IoTest {
    @Test
    void seedSignerImportDefaultsToOptionalWithoutChangingBrand() throws ImportException {
        Network.set(Network.TESTNET);
        try {
            Keystore keystore = new SeedSigner().getKeystore(PolicyType.SINGLE_HD, ScriptType.P2WPKH,
                    getInputStream("specter-diy-keystore.txt"), null);
            assertEquals(WalletModel.SEEDSIGNER, keystore.getWalletModel());
            assertEquals(AntiExfilKeystorePolicy.OPTIONAL, keystore.getAntiExfilPolicy());
        } finally {
            Network.set(Network.MAINNET);
        }
    }
}
