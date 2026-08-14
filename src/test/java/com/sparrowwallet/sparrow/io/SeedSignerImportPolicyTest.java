package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.KeystoreSource;
import com.sparrowwallet.drongo.wallet.WalletModel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SeedSignerImportPolicyTest {
    @Test
    void declaresOptionalProtectedSigningForEveryImportTransport() {
        assertEquals(AntiExfilKeystorePolicy.OPTIONAL, new SeedSigner().getDefaultAntiExfilPolicy());
        assertEquals(AntiExfilKeystorePolicy.UNSUPPORTED, new SpecterDIY().getDefaultAntiExfilPolicy());
    }

    @Test
    void decodedSeedSignerQrReceivesOptionalProtectedSigningPolicy() {
        Keystore keystore = new SeedSigner().applyScannedKeystoreMetadata(new Keystore());

        assertEquals(KeystoreSource.HW_AIRGAPPED, keystore.getSource());
        assertEquals(WalletModel.SEEDSIGNER, keystore.getWalletModel());
        assertEquals(AntiExfilKeystorePolicy.OPTIONAL, keystore.getAntiExfilPolicy());
    }

    @Test
    void decodedQrFromUnconfiguredImporterRemainsUnsupported() {
        Keystore keystore = new SpecterDIY().applyScannedKeystoreMetadata(new Keystore());

        assertEquals(WalletModel.SPECTER_DIY, keystore.getWalletModel());
        assertEquals(AntiExfilKeystorePolicy.UNSUPPORTED, keystore.getAntiExfilPolicy());
    }
}
