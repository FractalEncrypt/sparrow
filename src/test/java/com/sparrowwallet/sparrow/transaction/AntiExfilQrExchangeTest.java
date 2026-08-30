package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.antiexfil.AntiExfilStage;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AntiExfilQrExchangeTest {
    @Test
    void labelsTheSelectedSignerModel() {
        assertEquals("Step 1 of 2: scan this commitment with Kern",
                AntiExfilQrExchange.displayHeader(AntiExfilStage.HOST_COMMIT, "Kern"));
        assertEquals("Step 2 of 2: scan this host reveal with Kern",
                AntiExfilQrExchange.displayHeader(AntiExfilStage.HOST_REVEAL, "Kern"));
        assertEquals("Scan Kern nonce openings",
                AntiExfilQrExchange.scanHeader(AntiExfilStage.SIGNER_OPENINGS, "Kern"));
        assertEquals("Scan Kern verified signatures",
                AntiExfilQrExchange.scanHeader(AntiExfilStage.SIGNER_SIGNATURES, "Kern"));
    }
}
