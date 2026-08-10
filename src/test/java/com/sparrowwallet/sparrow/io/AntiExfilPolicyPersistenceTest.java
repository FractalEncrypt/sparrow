package com.sparrowwallet.sparrow.io;

import com.google.gson.Gson;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.WalletModel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AntiExfilPolicyPersistenceTest {
    @Test
    void jsonRoundTripAndLegacyDefault() {
        Keystore keystore = new Keystore("SeedSigner");
        keystore.setWalletModel(WalletModel.SEEDSIGNER);
        keystore.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED);

        Gson gson = JsonPersistence.getGson();
        String json = gson.toJson(keystore, Keystore.class);
        assertTrue(json.contains("\"antiExfilPolicy\": \"REQUIRED\""));
        assertFalse(json.contains("antiExfilRequired"));

        Keystore restored = gson.fromJson(json, Keystore.class);
        assertTrue(restored.isAntiExfilRequired());
        assertEquals(AntiExfilKeystorePolicy.REQUIRED, restored.getAntiExfilPolicy());
        assertEquals(WalletModel.SEEDSIGNER, restored.getWalletModel());

        Keystore legacy = gson.fromJson("{\"label\":\"SeedSigner\",\"walletModel\":\"SEEDSIGNER\"}", Keystore.class);
        assertEquals(AntiExfilKeystorePolicy.OPTIONAL, legacy.getAntiExfilPolicy());

        Keystore legacyRequired = gson.fromJson("{\"label\":\"SeedSigner\",\"walletModel\":\"SEEDSIGNER\",\"antiExfilRequired\":true}", Keystore.class);
        assertEquals(AntiExfilKeystorePolicy.REQUIRED, legacyRequired.getAntiExfilPolicy());

        Keystore legacyOther = gson.fromJson("{\"label\":\"Specter\",\"walletModel\":\"SPECTER_DIY\"}", Keystore.class);
        assertEquals(AntiExfilKeystorePolicy.UNSUPPORTED, legacyOther.getAntiExfilPolicy());
    }
}
