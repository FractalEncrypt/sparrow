package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;

import java.io.InputStream;

public class SeedSigner extends SpecterDIY {
    @Override
    public Keystore getKeystore(PolicyType policyType, ScriptType scriptType, InputStream inputStream, String password) throws ImportException {
        Keystore keystore = super.getKeystore(policyType, scriptType, inputStream, password);
        keystore.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
        return keystore;
    }

    @Override
    public String getName() {
        return "SeedSigner";
    }

    @Override
    public String getKeystoreImportDescription(int account) {
        return "Import QR created on your SeedSigner by selecting Export Xpub in the Seeds menu once you have entered your seed.";
    }

    @Override
    public WalletModel getWalletModel() {
        return WalletModel.SEEDSIGNER;
    }

    @Override
    public boolean isFileFormatAvailable() {
        return false;
    }
}
