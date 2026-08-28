package com.sparrowwallet.sparrow.wallet;

import com.sparrowwallet.drongo.wallet.AntiExfilProfile;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.WalletModel;

import java.util.Map;

/** Reviewed model/profile capabilities; model identity alone never selects carriage. */
public final class AntiExfilDeviceRegistry {
    public record Capability(AntiExfilProfile profile, boolean requiredVerified) {}

    private static final Map<WalletModel, Capability> VERIFIED = Map.of(
            WalletModel.SEEDSIGNER, new Capability(AntiExfilProfile.AEXT_V1, true),
            WalletModel.KERN, new Capability(AntiExfilProfile.AEXT_V1, false)
    );

    private AntiExfilDeviceRegistry() {}

    public static Capability capability(Keystore keystore) {
        if(keystore == null) {
            return null;
        }
        Capability capability = VERIFIED.get(keystore.getWalletModel());
        return capability != null && capability.profile() == keystore.getAntiExfilProfile()
                ? capability : null;
    }

    public static boolean supportsRequired(Keystore keystore) {
        Capability capability = capability(keystore);
        return capability != null && capability.requiredVerified();
    }
}
