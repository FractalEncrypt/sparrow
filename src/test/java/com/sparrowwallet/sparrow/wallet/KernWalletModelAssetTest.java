package com.sparrowwallet.sparrow.wallet;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KernWalletModelAssetTest {
    @Test
    void kernSvgAssetsUseStandardWalletModelDimensions() throws IOException {
        for(String asset : new String[] {"kern.svg", "kern-invert.svg", "kern-icon.svg", "kern-icon-invert.svg"}) {
            try(InputStream input = getClass().getResourceAsStream("/image/walletmodel/" + asset)) {
                assertNotNull(input, asset + " must exist");
                String svg = new String(input.readAllBytes(), StandardCharsets.UTF_8);
                assertTrue(svg.contains("width=\"50\""), asset + " must be 50 pixels wide");
                assertTrue(svg.contains("height=\"50\""), asset + " must be 50 pixels high");
            }
        }
    }
}
