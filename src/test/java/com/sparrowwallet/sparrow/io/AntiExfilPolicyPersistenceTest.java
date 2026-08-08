package com.sparrowwallet.sparrow.io;

import com.google.gson.Gson;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.WalletModel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AntiExfilPolicyPersistenceTest {
    @Test
    void jsonRoundTripAndLegacyDefault() {
        Keystore keystore = new Keystore("SeedSigner");
        keystore.setWalletModel(WalletModel.SEEDSIGNER);
        keystore.setAntiExfilRequired(true);

        Gson gson = JsonPersistence.getGson();
        String json = gson.toJson(keystore, Keystore.class);
        assertTrue(json.contains("\"antiExfilRequired\": true"));

        Keystore restored = gson.fromJson(json, Keystore.class);
        assertTrue(restored.isAntiExfilRequired());
        assertEquals(WalletModel.SEEDSIGNER, restored.getWalletModel());

        Keystore legacy = gson.fromJson("{\"label\":\"SeedSigner\",\"walletModel\":\"SEEDSIGNER\"}", Keystore.class);
        assertFalse(legacy.isAntiExfilRequired());
    }
}
