package com.sparrowwallet.sparrow.wallet;

import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.WalletModel;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class KeystoreFxmlAntiExfilTest {
    @BeforeAll
    static void startJavaFx() throws InterruptedException {
        CountDownLatch started = new CountDownLatch(1);
        try {
            Platform.startup(started::countDown);
        } catch(IllegalStateException alreadyStarted) {
            started.countDown();
        }
        assertTrue(started.await(10, TimeUnit.SECONDS));
    }

    @Test
    void keystoreViewLoadsAntiExfilPolicy() throws InterruptedException {
        URL resource = getClass().getResource("keystore.fxml");
        assertNotNull(resource);
        AtomicReference<Parent> root = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        CountDownLatch loaded = new CountDownLatch(1);
        Platform.runLater(() -> {
            try {
                root.set(new FXMLLoader(resource).load());
            } catch(Throwable throwable) {
                failure.set(throwable);
            } finally {
                loaded.countDown();
            }
        });
        assertTrue(loaded.await(15, TimeUnit.SECONDS));
        assertNull(failure.get(), failure.get() == null ? null : failure.get().toString());
        assertNotNull(root.get());
        assertNotNull(root.get().lookup("#antiExfilPolicy"));
    }

    @Test
    void requiredPolicyIsOfferedOnlyForVerifiedDeviceModels() {
        Keystore seedSigner = new Keystore("SeedSigner");
        seedSigner.setWalletModel(WalletModel.SEEDSIGNER);
        Keystore passport = new Keystore("Passport");
        passport.setWalletModel(WalletModel.PASSPORT);
        Keystore specter = new Keystore("Specter DIY");
        specter.setWalletModel(WalletModel.SPECTER_DIY);

        assertTrue(KeystoreController.supportsRequiredAntiExfil(seedSigner));
        assertFalse(KeystoreController.supportsRequiredAntiExfil(passport));
        assertFalse(KeystoreController.supportsRequiredAntiExfil(specter));
    }
}
