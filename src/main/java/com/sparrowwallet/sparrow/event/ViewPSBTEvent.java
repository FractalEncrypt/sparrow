package com.sparrowwallet.sparrow.event;

import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.antiexfil.VerifiedAntiExfilSignature;
import com.sparrowwallet.sparrow.transaction.TransactionView;
import javafx.stage.Window;

import java.io.File;
import java.util.Set;

public class ViewPSBTEvent {
    private final Window window;
    private final String label;
    private final File file;
    private final PSBT psbt;
    private final PSBT contextPsbt;
    private final TransactionView initialView;
    private final Integer initialIndex;
    private final Set<VerifiedAntiExfilSignature> verifiedAntiExfilSignatures;

    public ViewPSBTEvent(Window window, String label, File file, PSBT psbt) {
        this(window, label, file, psbt, null, TransactionView.HEADERS, null);
    }

    public ViewPSBTEvent(Window window, String label, File file, PSBT psbt, PSBT contextPsbt) {
        this(window, label, file, psbt, contextPsbt, TransactionView.HEADERS, null);
    }

    public ViewPSBTEvent(Window window, String label, File file, PSBT psbt, TransactionView initialView, Integer initialIndex) {
        this(window, label, file, psbt, null, initialView, initialIndex);
    }

    public ViewPSBTEvent(Window window, String label, File file, PSBT psbt, PSBT contextPsbt, TransactionView initialView, Integer initialIndex) {
        this(window, label, file, psbt, contextPsbt, initialView, initialIndex, Set.of());
    }

    public ViewPSBTEvent(Window window, String label, File file, PSBT psbt, PSBT contextPsbt, TransactionView initialView,
                         Integer initialIndex, Set<VerifiedAntiExfilSignature> verifiedAntiExfilSignatures) {
        this.window = window;
        this.label = label;
        this.file = file;
        this.psbt = psbt;
        this.contextPsbt = contextPsbt;
        this.initialView = initialView;
        this.initialIndex = initialIndex;
        this.verifiedAntiExfilSignatures = Set.copyOf(verifiedAntiExfilSignatures);
    }

    public Window getWindow() {
        return window;
    }

    public String getLabel() {
        return label;
    }

    public File getFile() {
        return file;
    }

    public PSBT getPsbt() {
        return psbt;
    }

    public PSBT getContextPsbt() {
        return contextPsbt;
    }

    public TransactionView getInitialView() {
        return initialView;
    }

    public Integer getInitialIndex() {
        return initialIndex;
    }

    public Set<VerifiedAntiExfilSignature> getVerifiedAntiExfilSignatures() {
        return verifiedAntiExfilSignatures;
    }
}
