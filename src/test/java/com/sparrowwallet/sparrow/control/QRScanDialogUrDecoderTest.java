package com.sparrowwallet.sparrow.control;

import com.sparrowwallet.hummingbird.UR;
import com.sparrowwallet.hummingbird.URDecoder;
import com.sparrowwallet.hummingbird.UREncoder;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class QRScanDialogUrDecoderTest {
    @Test
    void replacesSingleBufferedFragmentWithNextLiveFountainStream() throws Exception {
        UR staleUr = new UR("aext", "stale previous ceremony".getBytes(StandardCharsets.UTF_8));
        UR liveUr = new UR("aext", "current ceremony with a different checksum and length".getBytes(StandardCharsets.UTF_8));
        UREncoder staleEncoder = new UREncoder(staleUr, 10, 5, 0);
        UREncoder liveEncoder = new UREncoder(liveUr, 10, 5, 0);

        URDecoder decoder = new URDecoder();
        decoder = QRScanDialog.receiveUrPart(decoder, staleEncoder.nextPart());
        assertEquals(1, decoder.getProcessedPartsCount());

        while(decoder.getResult() == null) {
            decoder = QRScanDialog.receiveUrPart(decoder, liveEncoder.nextPart());
        }

        assertEquals("aext", decoder.getResult().ur.getType());
        assertArrayEquals(liveUr.getCborBytes(), decoder.getResult().ur.getCborBytes());
    }
}
