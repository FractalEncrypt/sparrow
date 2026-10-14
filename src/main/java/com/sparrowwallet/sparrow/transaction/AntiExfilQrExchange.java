package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.antiexfil.AntiExfilException;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator;
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
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
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

    static String freshStartText(AntiExfilCoordinator.RecoverySummary summary) {
        return "Start a new exchange for payment " + summary.unsignedTxid() + "?\n\n"
                + "This account has " + summary.unfinishedAfterReveal() + " unfinished exchanges after a possible reveal; "
                + summary.thisPaymentUnfinished() + " concern this payment. "
                + (summary.unknownLegacyHistory() ? "Some earlier history has unknown payment or exposure details. " : "")
                + (summary.unknownPaymentUnfinished() > 0 ? summary.unknownPaymentUnfinished() + " earlier unfinished exchanges have unknown payment identities. " : "") + "\n"
                + "Recorded interruptions: " + readableReasons(summary) + ".\n\n"
                + "A new exchange uses new randomness, including when the payment is unchanged. "
                + "A malicious signer can use repeated attempts to leak information. Investigate unexpected repeated failures."
                + (summary.reasons().getOrDefault("SIGNATURE_REJECTED", 0L) > 0
                ? " A previous response failed cryptographic verification. Investigate the device and software before continuing." : "");
    }
    private static String readableReasons(AntiExfilCoordinator.RecoverySummary summary) {
        return summary.reasons().entrySet().stream().sorted(java.util.Map.Entry.comparingByKey()).map(entry -> {
            String label = switch(entry.getKey()) {
                case "SIGNATURE_REJECTED" -> "response failed verification";
                case "USER_ABANDONED" -> "user ended exchange";
                case "TRANSPORT_FAILED" -> "scan or transport interrupted";
                case "SIGNER_CANCELLED" -> "signer cancelled";
                case "OWNER_LOST_UNVERIFIED" -> "previous exchange owner absent";
                case "HOST_EXCHANGE_CLOSED" -> "host exchange closed";
                default -> "earlier unresolved exchange";
            };
            return label + ": " + entry.getValue();
        }).collect(java.util.stream.Collectors.joining("; "));
    }
    static boolean confirmFreshStart(AntiExfilCoordinator.RecoverySummary summary, Window owner) {
        ButtonType cancel = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);
        ButtonType start = new ButtonType("Start new exchange", ButtonBar.ButtonData.YES);
        return decision("Start signing again?", freshStartText(summary), owner, cancel, start)
                .filter(button -> button == start).isPresent();
    }
    private static Optional<ButtonType> decision(String title, String content, Window owner, ButtonType safeDefault, ButtonType other) {
        Alert dialog = new Alert(Alert.AlertType.WARNING, content, safeDefault, other);
        dialog.setTitle(title); dialog.setHeaderText(title); dialog.initOwner(owner);
        Button safe = (Button)dialog.getDialogPane().lookupButton(safeDefault);
        Button alternative = (Button)dialog.getDialogPane().lookupButton(other);
        alternative.setDefaultButton(false); alternative.setCancelButton(false);
        safe.setDefaultButton(true); safe.setCancelButton(true);
        return dialog.showAndWait();
    }
    @Override
    public AntiExfilSigningFlow.PostRevealAction onPostRevealInterruption() {
        ButtonType retry = new ButtonType("Retry same exchange", ButtonBar.ButtonData.CANCEL_CLOSE);
        ButtonType end = new ButtonType("End exchange", ButtonBar.ButtonData.NO);
        Optional<ButtonType> result = decision(
                "Protected signing is incomplete",
                "Signing has not finished. Retry keeps this exchange unchanged. After Retry, scan the device's final response into Sparrow. "
                        + "Ending discards the active exchange; you can start signing again with new randomness. "
                        + "Repeated signer failures can leak information.", owner, retry, end);
        return result.isPresent() && result.get() == end
                ? AntiExfilSigningFlow.PostRevealAction.ABANDON
                : AntiExfilSigningFlow.PostRevealAction.RETRY_EXACT;
    }
}
