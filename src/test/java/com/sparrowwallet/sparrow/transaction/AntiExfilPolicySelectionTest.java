package com.sparrowwallet.sparrow.transaction;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.antiexfil.AntiExfilPsbt;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AntiExfilPolicySelectionTest {
    @Test
    void requiredCompatibleSignerCannotSilentlyFallBackToOptionalSigner() {
        Wallet wallet = new Wallet("test");
        Keystore required = compatible("Required", WalletModel.SPECTER_DIY, AntiExfilKeystorePolicy.REQUIRED);
        Keystore optional = compatible("Optional", WalletModel.SEEDSIGNER, AntiExfilKeystorePolicy.OPTIONAL);
        Keystore unsupported = compatible("Unsupported", WalletModel.PASSPORT, AntiExfilKeystorePolicy.UNSUPPORTED);
        wallet.getKeystores().addAll(List.of(required, optional, unsupported));

        assertEquals(List.of(required), HeadersController.getAntiExfilKeystores(wallet));

        required.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
        assertEquals(List.of(required, optional), HeadersController.getAntiExfilKeystores(wallet));
    }

    @Test
    void returnedRequiredSignatureNeedsProtectedProvenance() {
        Keystore required = compatible("Required", WalletModel.SPECTER_DIY, AntiExfilKeystorePolicy.REQUIRED);
        Keystore optional = compatible("Optional", WalletModel.SEEDSIGNER, AntiExfilKeystorePolicy.OPTIONAL);
        AttributedWallet wallet = new AttributedWallet(required);

        assertTrue(AntiExfilPolicy.requiresProtectedSigning(wallet));
        assertTrue(AntiExfilPolicy.hasRequiredSignature(wallet, (PSBT)null));
        wallet.signer = optional;
        assertFalse(AntiExfilPolicy.hasRequiredSignature(wallet, (PSBT)null));
        required.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
        assertFalse(AntiExfilPolicy.requiresProtectedSigning(wallet));
    }

    @Test
    void unattributableSignedReturnFailsClosedForExpectedRequiredSigner() {
        Keystore required = compatible("Required", WalletModel.SEEDSIGNER, AntiExfilKeystorePolicy.REQUIRED);
        Keystore optional = compatible("Optional", WalletModel.SPECTER_DIY, AntiExfilKeystorePolicy.OPTIONAL);

        assertTrue(AntiExfilPolicy.violatesRequiredPolicy(List.of(required), List.of(), true));
        assertFalse(AntiExfilPolicy.violatesRequiredPolicy(List.of(required), List.of(), false));
        assertFalse(AntiExfilPolicy.violatesRequiredPolicy(List.of(optional), List.of(), true));
        assertFalse(AntiExfilPolicy.violatesRequiredPolicy(List.of(required, optional), List.of(optional), true));
        assertTrue(AntiExfilPolicy.violatesRequiredPolicy(List.of(required, optional), List.of(required), true));
    }

    @Test
    void protectedSigningExportsCanonicalV0FromInternalV2() throws Exception {
        JsonObject vector;
        try(InputStreamReader reader = new InputStreamReader(getClass().getResourceAsStream(
                "/com/sparrowwallet/sparrow/io/protocol-v1-semantic-psbt-vector.json"), StandardCharsets.UTF_8)) {
            vector = JsonParser.parseReader(reader).getAsJsonObject();
        }
        byte[] canonicalV0 = Utils.hexToBytes(vector.get("psbt_hex").getAsString());
        PSBT internal = new PSBT(canonicalV0, false);
        internal.convertVersion(2);

        assertEquals(2, internal.getVersion());
        byte[] exported = HeadersController.getAntiExfilPsbtBytes(internal);
        assertNull(AntiExfilPsbt.parseCanonicalV0(exported).getVersion());
        assertArrayEquals(canonicalV0, exported);
    }

    private static Keystore compatible(String label, WalletModel model, AntiExfilKeystorePolicy policy) {
        Keystore keystore = new Keystore(label);
        keystore.setWalletModel(model);
        keystore.setAntiExfilPolicy(policy);
        return keystore;
    }

    private static final class AttributedWallet extends Wallet {
        private Keystore signer;

        private AttributedWallet(Keystore signer) {
            super("test");
            this.signer = signer;
            getKeystores().add(signer);
        }

        @Override
        public Map<PSBTInput, Map<TransactionSignature, Keystore>> getSignedKeystores(PSBT psbt) {
            Map<TransactionSignature, Keystore> signatures = new LinkedHashMap<>();
            signatures.put(null, signer);
            Map<PSBTInput, Map<TransactionSignature, Keystore>> inputs = new LinkedHashMap<>();
            inputs.put(null, signatures);
            return inputs;
        }
    }
}
