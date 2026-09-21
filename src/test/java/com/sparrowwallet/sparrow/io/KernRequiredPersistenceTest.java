package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.crypto.Argon2KeyDeriver;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.wallet.AntiExfilDeviceRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class KernRequiredPersistenceTest {
    @TempDir Path temporary;

    @Test
    void availabilityDoesNotPromoteNewLegacyOrOptionalPolicy() {
        Keystore fresh = new Keystore("Kern");
        fresh.setWalletModel(WalletModel.KERN);
        fresh.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);
        assertTrue(AntiExfilDeviceRegistry.supportsRequired(fresh));
        assertEquals(AntiExfilKeystorePolicy.UNSUPPORTED, fresh.getAntiExfilPolicy());
        fresh.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
        assertTrue(AntiExfilDeviceRegistry.supportsRequired(fresh));
        assertEquals(AntiExfilKeystorePolicy.OPTIONAL, fresh.getAntiExfilPolicy());
        Keystore legacy = JsonPersistence.getGson().fromJson(
                "{\"label\":\"Kern\",\"walletModel\":\"KERN\",\"antiExfilProfile\":\"aext-v1\"}", Keystore.class);
        assertEquals(AntiExfilKeystorePolicy.UNSUPPORTED, legacy.getAntiExfilPolicy());
    }

    @Test
    void jsonReloadPreservesEveryPolicyWithoutCoercion() {
        for(AntiExfilKeystorePolicy policy : AntiExfilKeystorePolicy.values()) {
            Keystore kern = new Keystore("Kern");
            kern.setWalletModel(WalletModel.KERN);
            kern.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);
            kern.setAntiExfilPolicy(policy);
            Keystore restored = JsonPersistence.getGson().fromJson(
                    JsonPersistence.getGson().toJson(kern, Keystore.class), Keystore.class);
            assertEquals(WalletModel.KERN, restored.getWalletModel());
            assertEquals(AntiExfilProfile.AEXT_V1, restored.getAntiExfilProfile());
            assertEquals(policy, restored.getAntiExfilPolicy());
        }
    }

    @Test
    void databaseReopenAndSecondSaveRetainRequiredKernAndPublicOnlyKeys() throws Exception {
        Wallet wallet = new Wallet("Gate6 test wallet");
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(ScriptType.P2WPKH);
        Keystore kern = new Keystore("Kern");
        kern.setSource(KeystoreSource.HW_AIRGAPPED);
        kern.setWalletModel(WalletModel.KERN);
        kern.setKeyDerivation(new KeyDerivation("60bcd3a7", "m/84'/0'/3'"));
        // Existing public-only database test fixture, never a physical wallet.
        kern.setExtendedPublicKey(ExtendedKey.fromDescriptor("xpub6BrhGFTWPd3DXo8s2BPxHHzCmBCyj8QvamcEUaq8EDwnwXpvvcU9LzpJqENHcqHkqwTn2vPhynGVoEqj3PAB3NxnYZrvCsSfoCniJKaggdy"));
        kern.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);
        kern.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED);
        wallet.getKeystores().add(kern);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, wallet.getKeystores(), null));
        Storage created = new Storage(PersistenceType.DB, temporary.resolve("Kern.mv.db").toFile());
        try {
            created.setKeyDeriver(new Argon2KeyDeriver());
            created.setEncryptionPubKey(Storage.NO_PASSWORD_KEY);
            created.saveWallet(wallet);
        } finally {
            created.closeAndWait();
        }
        for(int round = 0; round < 2; round++) {
            Storage reopened = new Storage(PersistenceType.DB, created.getWalletFile());
            try {
                Wallet restored = reopened.loadUnencryptedWallet().getWallet();
                Keystore key = restored.getKeystores().getFirst();
                assertEquals(WalletModel.KERN, key.getWalletModel());
                assertEquals(AntiExfilProfile.AEXT_V1, key.getAntiExfilProfile());
                assertEquals(AntiExfilKeystorePolicy.REQUIRED, key.getAntiExfilPolicy());
                assertTrue(AntiExfilDeviceRegistry.supportsRequired(key));
                assertFalse(key.hasPrivateKey());
                assertEquals(kern.getExtendedPublicKey(), key.getExtendedPublicKey());
                reopened.saveWallet(restored);
            } finally {
                reopened.closeAndWait();
            }
        }
    }
}
