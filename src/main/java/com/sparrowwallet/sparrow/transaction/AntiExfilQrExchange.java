package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.antiexfil.AntiExfilStage;
import com.sparrowwallet.sparrow.AppServices;
import com.sparrowwallet.sparrow.control.QRDisplayDialog;
import com.sparrowwallet.sparrow.control.QREncoding;
import com.sparrowwallet.sparrow.control.QRScanDialog;
import com.sparrowwallet.sparrow.io.AntiExfilQrCodec;
import com.sparrowwallet.sparrow.io.AntiExfilTransportPackage;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.stage.Window;

import java.util.Optional;

public final class AntiExfilQrExchange implements AntiExfilSigningFlow.Exchange {
    private final Window owner;

    public AntiExfilQrExchange(Window owner) {
        this.owner = owner;
    }

    @Override
    public boolean display(AntiExfilTransportPackage transportPackage) {
        AntiExfilStage stage = transportPackage.getMessage().getStage();
        QRDisplayDialog dialog = new QRDisplayDialog(AntiExfilQrCodec.toUr(transportPackage),
                null, false, true, QREncoding.UR);
        dialog.setTitle("Anti-exfil signing");
        dialog.setHeaderText(stage == AntiExfilStage.HOST_COMMIT
                ? "Step 1 of 2: scan this commitment with SeedSigner"
                : "Step 2 of 2: scan this host reveal with SeedSigner");
        dialog.initOwner(owner);
        Optional<ButtonType> result = dialog.showAndWait();
        return result.isPresent() && result.get().getButtonData() == ButtonBar.ButtonData.OK_DONE;
    }

    @Override
    public Optional<AntiExfilTransportPackage> scan(AntiExfilStage expectedStage, AntiExfilNetwork expectedNetwork) {
        QRScanDialog dialog = new QRScanDialog(AntiExfilTransportPackage.UR_TYPE);
        dialog.setTitle("Anti-exfil signing");
        dialog.setHeaderText(expectedStage == AntiExfilStage.SIGNER_OPENINGS
                ? "Scan SeedSigner nonce openings"
                : "Scan SeedSigner verified signatures");
        dialog.initOwner(owner);
        Optional<QRScanDialog.Result> result = dialog.showAndWait();
        if(result.isEmpty()) return Optional.empty();
        if(result.get().exception != null || result.get().getUr() == null) {
            AppServices.showErrorDialog("Invalid anti-exfil QR",
                    result.get().exception == null ? "Scanner returned no anti-exfil UR" : result.get().exception.getMessage());
            return Optional.empty();
        }
        try {
            return Optional.of(AntiExfilQrCodec.fromUr(result.get().getUr(), expectedStage, expectedNetwork));
        } catch(IllegalArgumentException exception) {
            AppServices.showErrorDialog("Invalid anti-exfil QR", exception.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public AntiExfilSigningFlow.PostRevealAction onPostRevealInterruption() {
        ButtonType retry = new ButtonType("Retry exact session", ButtonBar.ButtonData.YES);
        ButtonType abandon = new ButtonType("Abandon session", ButtonBar.ButtonData.NO);
        Optional<ButtonType> result = AppServices.showWarningDialog(
                "Protected signing is incomplete",
                "The host reveal has already been shown. Retry only this exact transaction and session. "
                        + "Starting fresh challenges after repeated signer failures can create a selective-abort channel.",
                retry, abandon);
        return result.isPresent() && result.get() == retry
                ? AntiExfilSigningFlow.PostRevealAction.RETRY_EXACT
                : AntiExfilSigningFlow.PostRevealAction.ABANDON;
    }
}
