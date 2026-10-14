package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.antiexfil.AntiExfilException;
import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.antiexfil.AntiExfilStage;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.sparrow.AppServices;
import com.sparrowwallet.sparrow.control.QRDisplayDialog;
import com.sparrowwallet.sparrow.control.QREncoding;
import com.sparrowwallet.sparrow.control.QRScanDialog;
import com.sparrowwallet.sparrow.io.AntiExfilQrCodec;
import com.sparrowwallet.sparrow.io.AntiExfilTransportPackage;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.stage.Window;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.function.Consumer;

public final class AntiExfilQrExchange implements AntiExfilSigningFlow.Exchange {
    private static final Logger log = LoggerFactory.getLogger(AntiExfilQrExchange.class);

    private final Window owner;
    private final String signerName;

    public AntiExfilQrExchange(Window owner, String signerName) {
        this.owner = owner;
        this.signerName = signerName;
    }

    @Override
    public boolean display(AntiExfilTransportPackage transportPackage) {
        AntiExfilStage stage = transportPackage.getMessage().getStage();
        recordEvidence("outgoing", transportPackage);
        QRDisplayDialog dialog = new QRDisplayDialog(AntiExfilQrCodec.toUr(transportPackage),
                null, false, true, QREncoding.UR);
        dialog.setTitle("Anti-exfil signing");
        dialog.setHeaderText(displayHeader(stage, signerName));
        dialog.initOwner(owner);
        Optional<ButtonType> result = dialog.showAndWait();
        return result.isPresent() && result.get().getButtonData() == ButtonBar.ButtonData.OK_DONE;
    }

    @Override
    public Optional<AntiExfilTransportPackage> scan(AntiExfilStage expectedStage, AntiExfilNetwork expectedNetwork) {
        QRScanDialog dialog = new QRScanDialog(AntiExfilTransportPackage.UR_TYPE);
        dialog.setTitle("Anti-exfil signing");
        dialog.setHeaderText(scanHeader(expectedStage, signerName));
        dialog.initOwner(owner);
        return decodeScanResult(dialog.showAndWait(), expectedStage, expectedNetwork,
                message -> AppServices.showErrorDialog("Invalid anti-exfil QR", message));
    }

    static Optional<AntiExfilTransportPackage> decodeScanResult(Optional<QRScanDialog.Result> result,
                                                                AntiExfilStage expectedStage,
                                                                AntiExfilNetwork expectedNetwork,
                                                                Consumer<String> transportError) {
        if(result.isEmpty()) return Optional.empty();
        if(result.get().exception instanceof AntiExfilException exception) throw exception;
        if(result.get().exception != null || result.get().getUr() == null) {
            transportError.accept(result.get().exception == null
                    ? "Scanner returned no anti-exfil UR" : result.get().exception.getMessage());
            return Optional.empty();
        }
        // Protocol rejections must reach the signing flow's durable rejection handler.
        AntiExfilTransportPackage transportPackage = AntiExfilQrCodec.fromUr(
                result.get().getUr(), expectedStage, expectedNetwork);
        recordEvidence("incoming", transportPackage);
        return Optional.of(transportPackage);
    }

    static String displayHeader(AntiExfilStage stage, String signerName) {
        return stage == AntiExfilStage.HOST_COMMIT
                ? "Step 1 of 2: scan this commitment with " + signerName
                : "Step 2 of 2: scan this host reveal with " + signerName;
    }

    static String scanHeader(AntiExfilStage stage, String signerName) {
        return stage == AntiExfilStage.SIGNER_OPENINGS
                ? "Scan " + signerName + " nonce openings"
                : "Scan " + signerName + " verified signatures";
    }

    private static void recordEvidence(String direction, AntiExfilTransportPackage transportPackage) {
        // No transcript, encoded payload, randomness, or payload fingerprint is logged.
    }

    @Override
    public AntiExfilSigningFlow.PostRevealAction onPostRevealInterruption() {
        ButtonType retry = new ButtonType("Retry exact session", ButtonBar.ButtonData.YES);
        ButtonType abandon = new ButtonType("Abandon session", ButtonBar.ButtonData.NO);
        Optional<ButtonType> result = AppServices.showWarningDialog(
                "Protected signing is incomplete",
                "The host reveal has already been shown. Retry only this exact transaction and session. "
                        + "The exact retry is available only while this host exchange remains open. Abandoning it or losing host RAM permanently refuses fresh Protected QR challenges for this account history. Show QR remains ordinary signing.",
                retry, abandon);
        return result.isPresent() && result.get() == retry
                ? AntiExfilSigningFlow.PostRevealAction.RETRY_EXACT
                : AntiExfilSigningFlow.PostRevealAction.ABANDON;
    }
}
