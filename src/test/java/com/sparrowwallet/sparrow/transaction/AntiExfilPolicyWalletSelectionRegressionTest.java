package com.sparrowwallet.sparrow.transaction;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.AntiExfilProfile;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.KeystoreSource;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.drongo.wallet.WalletModel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * A13: the PSBT signing-wallet choice ranked wallets only by keystore source, so a same-key Optional duplicate
 * listed first could win the default binding and show the verified box with zero proofs. The selection must prefer
 * the wallet that enforces the strongest protected-signing policy, like the raw-transaction path already does.
 * Testnet4 public fixture only; nothing connects or broadcasts.
 */
class AntiExfilPolicyWalletSelectionRegressionTest {
    private Network previousNetwork;
    private JsonObject vector;
    private byte[] signed;

    @BeforeEach void setup() throws Exception {
        previousNetwork = Network.get();
        Network.set(Network.TESTNET4);
        try(var reader = new InputStreamReader(getClass().getResourceAsStream(
                "/com/sparrowwallet/sparrow/io/protocol-v1-mixed-provenance-vector.json"), StandardCharsets.UTF_8)) {
            vector = JsonParser.parseReader(reader).getAsJsonObject();
        }
        signed = Utils.hexToBytes(vector.get("signed_psbt_hex").getAsString());
    }

    @AfterEach void restore() {
        Network.set(previousNetwork);
    }

    @Test void requiredWalletWinsOverSameKeyOptionalDuplicate() throws Exception {
        Wallet optionalDuplicate = wallet(AntiExfilKeystorePolicy.OPTIONAL);
        Wallet required = wallet(AntiExfilKeystorePolicy.REQUIRED);
        PSBT psbt = new PSBT(signed, false);

        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(optionalDuplicate, psbt, Set.of()));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(required, psbt, Set.of()));

        //Source-ranked order lists the Optional duplicate first; the policy selector must still choose the Required wallet.
        assertSame(required, HeadersController.selectPsbtPolicyWallet(
                List.of(optionalDuplicate, required), psbt, Set.of()));
    }

    @Test void optionalOnlySetStaysSelectable() throws Exception {
        Wallet optional = wallet(AntiExfilKeystorePolicy.OPTIONAL);
        PSBT psbt = new PSBT(signed, false);
        assertSame(optional, HeadersController.selectPsbtPolicyWallet(List.of(optional), psbt, Set.of()));
    }

    private Wallet wallet(AntiExfilKeystorePolicy policyA) throws Exception {
        Wallet wallet = new Wallet("select-" + policyA);
        wallet.getKeystores().add(signer(vector.getAsJsonObject("signer_a"), policyA));
        wallet.getKeystores().add(signer(vector.getAsJsonObject("signer_b"), AntiExfilKeystorePolicy.OPTIONAL));
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        wallet.checkWallet();
        return wallet;
    }

    private static Keystore signer(JsonObject data, AntiExfilKeystorePolicy policy) throws Exception {
        Keystore keystore = Keystore.fromSeed(new DeterministicSeed(data.get("mnemonic").getAsString(), "", 0,
                DeterministicSeed.Type.BIP39), PolicyType.MULTI_HD,
                KeyDerivation.parsePath(data.get("account_derivation").getAsString()));
        keystore.setSeed(null);
        keystore.setMasterPrivateExtendedKey(null);
        keystore.setSource(KeystoreSource.HW_AIRGAPPED);
        keystore.setLabel(keystore.getKeyDerivation().getMasterFingerprint());
        keystore.setWalletModel(WalletModel.KERN);
        keystore.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);
        keystore.setAntiExfilPolicy(policy);
        return keystore;
    }
}
