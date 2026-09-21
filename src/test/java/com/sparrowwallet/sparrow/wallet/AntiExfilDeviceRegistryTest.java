package com.sparrowwallet.sparrow.wallet;

import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.AntiExfilProfile;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.WalletModel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AntiExfilDeviceRegistryTest {
    @Test
    void onlyReviewedModelAndProfilePairsOfferRequired() {
        assertFalse(AntiExfilDeviceRegistry.supportsRequired(null));
        for(WalletModel model : WalletModel.values()) {
            for(AntiExfilProfile profile : AntiExfilProfile.values()) {
                Keystore key = new Keystore("registry test");
                key.setWalletModel(model);
                key.setAntiExfilProfile(profile);
                key.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
                boolean expected = (model == WalletModel.KERN || model == WalletModel.SEEDSIGNER)
                        && profile == AntiExfilProfile.AEXT_V1;
                assertEquals(expected, AntiExfilDeviceRegistry.supportsRequired(key), model + "/" + profile);
                assertEquals(AntiExfilKeystorePolicy.OPTIONAL, key.getAntiExfilPolicy(), "capability checks must not promote wallet policy");
            }
        }
    }
}
