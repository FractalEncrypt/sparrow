package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.AntiExfilProfile;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;

import java.io.InputStream;

/** Kern's Specter-DIY-compatible xpub QR importer with explicit AEXT identity. */
public class Kern extends SpecterDIY {
    @Override
    public Keystore getKeystore(PolicyType policyType, ScriptType scriptType, InputStream inputStream,
                                String password) throws ImportException {
        Keystore keystore = super.getKeystore(policyType, scriptType, inputStream, password);
        keystore.setAntiExfilPolicy(getDefaultAntiExfilPolicy());
        keystore.setAntiExfilProfile(getDefaultAntiExfilProfile());
        return keystore;
    }

    @Override
    public AntiExfilKeystorePolicy getDefaultAntiExfilPolicy() {
        return AntiExfilKeystorePolicy.OPTIONAL;
    }

    @Override
    public AntiExfilProfile getDefaultAntiExfilProfile() {
        return AntiExfilProfile.AEXT_V1;
    }

    @Override
    public String getName() {
        return "Kern";
    }

    @Override
    public String getKeystoreImportDescription(int account) {
        return "Load the seed on Kern, export its account xpub QR, and scan it here. Protected signing uses Kern's experimental two-round AEXT QR profile on test networks.";
    }

    @Override
    public WalletModel getWalletModel() {
        return WalletModel.KERN;
    }

    @Override
    public boolean isFileFormatAvailable() {
        return false;
    }
}
