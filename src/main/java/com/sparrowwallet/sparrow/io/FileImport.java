package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.KeystoreSource;

import java.io.File;

public interface FileImport extends ImportExport {
    boolean isEncrypted(File file);

    default AntiExfilKeystorePolicy getDefaultAntiExfilPolicy() {
        return AntiExfilKeystorePolicy.UNSUPPORTED;
    }

    default Keystore applyScannedKeystoreMetadata(Keystore keystore) {
        keystore.setSource(KeystoreSource.HW_AIRGAPPED);
        keystore.setWalletModel(getWalletModel());
        keystore.setAntiExfilPolicy(getDefaultAntiExfilPolicy());
        return keystore;
    }
}
