package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.Utils;
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
        Optional<QRScanDialog.Result> result = dialog.showAndWait();
        if(result.isEmpty()) return Optional.empty();
        if(result.get().exception != null || result.get().getUr() == null) {
            AppServices.showErrorDialog("Invalid anti-exfil QR",
                    result.get().exception == null ? "Scanner returned no anti-exfil UR" : result.get().exception.getMessage());
            return Optional.empty();
        }
        try {
            AntiExfilTransportPackage transportPackage = AntiExfilQrCodec.fromUr(
                    result.get().getUr(), expectedStage, expectedNetwork);
            recordEvidence("incoming", transportPackage);
            return Optional.of(transportPackage);
        } catch(IllegalArgumentException exception) {
            AppServices.showErrorDialog("Invalid anti-exfil QR", exception.getMessage());
            return Optional.empty();
        }
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
        byte[] canonical = transportPackage.encode();
        log.info("Anti-exfil package direction={} stage={} bytes={} sha256={}", direction,
                transportPackage.getMessage().getStage(), canonical.length,
                Utils.bytesToHex(Sha256Hash.hash(canonical)));
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
