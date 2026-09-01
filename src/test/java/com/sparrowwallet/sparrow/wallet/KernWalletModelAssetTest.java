package com.sparrowwallet.sparrow.wallet;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KernWalletModelAssetTest {
    @Test
    void kernSvgAssetsUseStandardWalletModelDimensionsAndBounds() throws Exception {
        for(String asset : new String[] {"kern.svg", "kern-invert.svg", "kern-icon.svg", "kern-icon-invert.svg"}) {
            try(InputStream input = getClass().getResourceAsStream("/image/walletmodel/" + asset)) {
                assertNotNull(input, asset + " must exist");
                String svg = new String(input.readAllBytes(), StandardCharsets.UTF_8);
                assertTrue(svg.contains("width=\"50\""), asset + " must be 50 pixels wide");
                assertTrue(svg.contains("height=\"50\""), asset + " must be 50 pixels high");
                assertTrue(svg.contains("viewBox=\"0 0 50 50\""), asset + " must use a 50-by-50 coordinate system");

                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                factory.setNamespaceAware(true);
                Document document = factory.newDocumentBuilder().parse(
                        new ByteArrayInputStream(svg.getBytes(StandardCharsets.UTF_8)));
                NodeList circles = document.getElementsByTagNameNS("*", "circle");
                assertEquals(3, circles.getLength(), asset + " must retain the three-ring Kern mark");
                for(int i = 0; i < circles.getLength(); i++) {
                    Element circle = (Element)circles.item(i);
                    double cx = Double.parseDouble(circle.getAttribute("cx"));
                    double cy = Double.parseDouble(circle.getAttribute("cy"));
                    double radius = Double.parseDouble(circle.getAttribute("r"));
                    double strokeHalf = circle.hasAttribute("stroke-width")
                            ? Double.parseDouble(circle.getAttribute("stroke-width")) / 2.0 : 0.0;
                    assertTrue(cx - radius - strokeHalf >= 0.0 && cx + radius + strokeHalf <= 50.0,
                            asset + " circle must fit the horizontal layout bounds");
                    assertTrue(cy - radius - strokeHalf >= 0.0 && cy + radius + strokeHalf <= 50.0,
                            asset + " circle must fit the vertical layout bounds");
                }
            }
        }
    }
}
