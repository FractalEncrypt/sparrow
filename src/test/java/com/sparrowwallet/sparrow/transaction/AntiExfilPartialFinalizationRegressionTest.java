package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionSignature;
import com.sparrowwallet.drongo.protocol.TransactionWitness;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.wallet.AntiExfilKeystorePolicy;
import com.sparrowwallet.drongo.wallet.AntiExfilProfile;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.KeystoreSource;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.drongo.wallet.WalletNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A5: a partially finalized PSBT (some inputs carry final_scriptwitness, the rest do not) is not finalized, so
 * the non-final evaluator used by evaluatePsbtEgress must still attribute signatures held in final_scriptwitness.
 * Before the fix a Required signer's only signature could sit in final_scriptwitness and the tab evaluated
 * PERMITTED. Testnet4 throwaway keys; nothing connects or broadcasts.
 */
class AntiExfilPartialFinalizationRegressionTest {
    private static final String MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    private Network previousNetwork;

    @BeforeEach void setup() {
        previousNetwork = Network.get();
        Network.set(Network.TESTNET4);
    }

    @AfterEach void restore() {
        Network.set(previousNetwork);
    }

    @Test void partiallyFinalizedRequiredInputIsNotPermitted() throws Exception {
        Keystore secret = Keystore.fromSeed(new DeterministicSeed(MNEMONIC, "", 0, DeterministicSeed.Type.BIP39),
                PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
        Wallet signer = new Wallet("partial-signer");
        signer.setPolicyType(PolicyType.SINGLE_HD);
        signer.setScriptType(ScriptType.P2WPKH);
        signer.getKeystores().add(secret);
        signer.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, signer.getKeystores(), 1));

        WalletNode node0 = signer.getFreshNode(KeyPurpose.RECEIVE);
        WalletNode node1 = signer.getFreshNode(KeyPurpose.RECEIVE);
        Transaction funding0 = funding(node0.getAddress(), (byte)0x51);
        Transaction funding1 = funding(node1.getAddress(), (byte)0x52);

        Transaction spend = new Transaction();
        spend.addInput(funding0.getTxId(), 0, new Script(new byte[0]));
        spend.addInput(funding1.getTxId(), 0, new Script(new byte[0]));
        spend.addOutput(180000, node0.getAddress());
        PSBT psbt = new PSBT(spend);
        psbt.getPsbtInputs().get(0).setWitnessUtxo(funding0.getOutputs().getFirst());
        psbt.getPsbtInputs().get(1).setWitnessUtxo(funding1.getOutputs().getFirst());
        psbt.addKeyPathInformation(signer);
        signer.sign(psbt);
        assertEquals(1, psbt.getPsbtInputs().get(0).getPartialSignatures().size());
        assertEquals(1, psbt.getPsbtInputs().get(1).getPartialSignatures().size());

        //Only input 0 is finalized, so isFinalized() stays false and the non-final evaluator runs.
        PSBTInput finalized = psbt.getPsbtInputs().get(0);
        TransactionSignature signature = finalized.getPartialSignatures().values().iterator().next();
        finalized.setFinalScriptWitness(new TransactionWitness(psbt.getTransaction(), signature));
        finalized.getPartialSignatures().clear();
        //Input 1 stays unsigned, so the partial-signature map alone cannot see any Required signature.
        psbt.getPsbtInputs().get(1).getPartialSignatures().clear();
        assertFalse(psbt.isFinalized());
        assertTrue(psbt.getPsbtInputs().get(0).isFinalized());
        assertFalse(psbt.getPsbtInputs().get(1).isFinalized());

        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(host(secret), psbt, Set.of()));
    }

    @Test void fullyUnsignedPartialShapeStaysPermitted() throws Exception {
        //Guard: with every signature removed, the same shape is PERMITTED.
        Keystore secret = Keystore.fromSeed(new DeterministicSeed(MNEMONIC, "", 0, DeterministicSeed.Type.BIP39),
                PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
        Wallet signer = new Wallet("partial-signer-guard");
        signer.setPolicyType(PolicyType.SINGLE_HD);
        signer.setScriptType(ScriptType.P2WPKH);
        signer.getKeystores().add(secret);
        signer.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, signer.getKeystores(), 1));
        WalletNode node0 = signer.getFreshNode(KeyPurpose.RECEIVE);
        Transaction funding0 = funding(node0.getAddress(), (byte)0x53);
        Transaction spend = new Transaction();
        spend.addInput(funding0.getTxId(), 0, new Script(new byte[0]));
        spend.addOutput(90000, node0.getAddress());
        PSBT psbt = new PSBT(spend);
        psbt.getPsbtInputs().getFirst().setWitnessUtxo(funding0.getOutputs().getFirst());
        psbt.addKeyPathInformation(signer);

        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(host(secret), psbt, Set.of()));
    }

    private static Wallet host(Keystore secret) throws Exception {
        Keystore watch = Keystore.fromSeed(new DeterministicSeed(MNEMONIC, "", 0, DeterministicSeed.Type.BIP39),
                PolicyType.SINGLE_HD, KeyDerivation.parsePath("m/84'/1'/0'"));
        watch.setSeed(null);
        watch.setMasterPrivateExtendedKey(null);
        watch.setSource(KeystoreSource.HW_AIRGAPPED);
        watch.setLabel(watch.getKeyDerivation().getMasterFingerprint());
        watch.setWalletModel(WalletModel.SEEDSIGNER);
        watch.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);
        watch.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED);
        Wallet host = new Wallet("partial-host");
        host.setPolicyType(PolicyType.SINGLE_HD);
        host.setScriptType(ScriptType.P2WPKH);
        host.getKeystores().add(watch);
        host.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, host.getKeystores(), 1));
        host.checkWallet();
        return host;
    }

    private static Transaction funding(Address address, byte tag) {
        byte[] previous = new byte[32];
        Arrays.fill(previous, tag);
        Transaction funding = new Transaction();
        funding.addInput(Sha256Hash.wrap(previous), 0, new Script(new byte[0]));
        funding.addOutput(100000, address);
        return funding;
    }
}
