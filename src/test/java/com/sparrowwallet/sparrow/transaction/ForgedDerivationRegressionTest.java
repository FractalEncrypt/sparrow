package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.psbt.PSBT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static com.sparrowwallet.sparrow.transaction.OctSixReviewTest.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Acceptance tests for a fix: these assert the secure behavior and FAIL on bdca6753 and cc760814.
 * A Required keystore's unproven signature must not be accepted because the returned PSBT
 * rewrote, or partly omitted, its PSBT_IN_BIP32_DERIVATION entry.
 */
public class ForgedDerivationRegressionTest {
    @BeforeAll static void start() throws Exception { OctSixReviewTest.startFx(); }
    @AfterAll static void stop() { OctSixReviewTest.restoreGlobalState(); }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void inTabScanSingleSigWithForgedRequiredDerivationIsRejected() throws Exception {
        SingleSig ss = singleSig();
        fx(() -> {
            try(Harness h = new Harness(ss.host(), copy(ss.tabPsbt()))) {
                h.assertRejectedUnchanged(ss.forged(), h.data.getPsbt(), Set.of());
                assertTrue(h.alerts.toString().contains("REQUIRED_"), h.alerts.toString());
            }
            return null;
        });
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void inTabScanWithForgedRequiredDerivationIsRejected() throws Exception {
        Fixture f = fixture("OR");
        PSBT aReturn = ordinarySign(copy(f.psbt()), f, 0);
        PSBT bReturn = ordinarySign(copy(aReturn), f, 1);
        forgeDerivation(bReturn, f, 1);
        fx(() -> {
            try(Harness h = new Harness(f.wallet(), copy(f.psbt()))) {
                h.post(aReturn, f.psbt(), Set.of());
                assertEquals(1, h.observer.merges, h.alerts.toString());
                h.assertRejectedUnchanged(bReturn, aReturn, Set.of());
                assertTrue(h.alerts.toString().contains("REQUIRED_"), h.alerts.toString());
            }
            return null;
        });
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void inTabScanWithAllRequiredDerivationsForgedIsRejected() throws Exception {
        Fixture f = fixture("RR");
        PSBT forged = ordinarySign(ordinarySign(copy(f.psbt()), f, 0), f, 1);
        forgeDerivation(forged, f, 0);
        forgeDerivation(forged, f, 1);
        fx(() -> {
            try(Harness h = new Harness(f.wallet(), copy(f.psbt()))) {
                h.assertRejectedUnchanged(forged, f.psbt(), Set.of());
                assertTrue(h.alerts.toString().contains("REQUIRED_"), h.alerts.toString());
            }
            return null;
        });
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void policyRejectsForgedRequiredDerivationBeforeAndAfterFinalize() throws Exception {
        Fixture f = fixture("OR");
        PSBT forged = ordinarySign(ordinarySign(copy(f.psbt()), f, 0), f, 1);
        forgeDerivation(forged, f, 1);
        assertNotEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(f.wallet(), forged, Set.of()));
        f.wallet().finalise(forged);
        assertNotEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(f.wallet(), forged, Set.of()));
    }

    @org.junit.jupiter.api.Disabled("Historical Required/durable provenance guarantee intentionally retired; see RAM lifecycle and ordinary validation replacement tests")
    @Test void policyRejectsPartiallyStrippedRequiredDerivation() throws Exception {
        Fixture f = fixture("OR");
        PSBT partial = ordinarySign(ordinarySign(copy(f.psbt()), f, 0), f, 1);
        ECKey b = ECKey.fromPublicOnly(partial.getPsbtInputs().getFirst().getPartialSignatures().keySet().stream()
                .filter(key -> f.wallet().getKeystores().get(1).getPubKeyForDerivation(
                        partial.getPsbtInputs().getFirst().getDerivedPublicKeys().get(key)) != null)
                .findFirst().orElseThrow().getPubKey());
        partial.getPsbtInputs().getFirst().getDerivedPublicKeys().remove(b);
        assertEquals(1, partial.getPsbtInputs().getFirst().getDerivedPublicKeys().size());
        assertNotEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(f.wallet(), partial, Set.of()));
    }
}
