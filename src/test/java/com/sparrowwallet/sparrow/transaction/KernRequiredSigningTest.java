package com.sparrowwallet.sparrow.transaction;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator;
import com.sparrowwallet.drongo.antiexfil.AntiExfilException;
import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.wallet.AntiExfilDeviceRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Software-only regressions using the existing public mixed-signature vector. */
class KernRequiredSigningTest {
    @TempDir Path temporary;
    private JsonObject vector;
    private Wallet wallet;
    private Keystore kern;
    private byte[] original;
    private Path session;
    private Path journal;

    @BeforeEach
    void setup() throws Exception {
        try(InputStreamReader reader = new InputStreamReader(getClass().getResourceAsStream(
                "/com/sparrowwallet/sparrow/io/protocol-v1-mixed-provenance-vector.json"), StandardCharsets.UTF_8)) {
            vector = JsonParser.parseReader(reader).getAsJsonObject();
        }
        kern = signer(vector.getAsJsonObject("signer_a"), WalletModel.KERN, AntiExfilKeystorePolicy.REQUIRED);
        Keystore optional = signer(vector.getAsJsonObject("signer_b"), WalletModel.SEEDSIGNER, AntiExfilKeystorePolicy.OPTIONAL);
        wallet = new Wallet("Kern REQUIRED public test vector");
        wallet.getKeystores().addAll(List.of(kern, optional));
        wallet.setPolicyType(PolicyType.MULTI_HD);
        wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        original = hex("original_psbt_hex");
        session = temporary.resolve("session.aexs");
        journal = temporary.resolve("journal.aexj");
    }

    @Test
    void reviewedKernIsSelectableAndProfileMismatchCannotDowngradeRequiredPolicy() {
        assertTrue(AntiExfilDeviceRegistry.supportsRequired(kern));
        assertTrue(HeadersController.getAntiExfilKeystores(wallet).contains(kern));
        for(AntiExfilProfile profile : AntiExfilProfile.values()) {
            kern.setAntiExfilProfile(profile);
            assertEquals(profile == AntiExfilProfile.AEXT_V1,
                    HeadersController.getAntiExfilKeystores(wallet).contains(kern));
            assertEquals(AntiExfilKeystorePolicy.REQUIRED, kern.getAntiExfilPolicy());
            assertTrue(AntiExfilPolicy.requiresProtectedSigning(wallet));
        }
    }

    @Test
    void validProtectedCompletionAndReloadProvideRequiredProof() throws Exception {
        AntiExfilCoordinator coordinator = coordinator();
        assertArrayEquals(hex("message_1_hex"), coordinator.getHostCommitMessage());
        assertArrayEquals(hex("message_3_hex"), coordinator.acceptOpenings(hex("message_2_hex")));
        AntiExfilCoordinator.Completion completed = coordinator.complete(hex("message_4_hex"));
        PSBT signed = new PSBT(completed.getSignedPsbt(), false);
        assertFalse(completed.isBroadcast());
        assertFalse(signed.isFinalized());
        assertEquals(1, completed.getVerifiedSignatures().size());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, signed, completed.getVerifiedSignatures()));
        AntiExfilCoordinator reloaded = AntiExfilCoordinator.load(session, journal, kern);
        assertEquals(AntiExfilCoordinator.Phase.COMPLETE, reloaded.getStatus().getPhase());
        assertEquals(completed.getVerifiedSignatures(), reloaded.getCompletedResult().getVerifiedSignatures());
        assertArrayEquals(completed.getSignedPsbt(), reloaded.getCompletedResult().getSignedPsbt());
        assertEquals(AntiExfilKeystorePolicy.REQUIRED, kern.getAntiExfilPolicy());
    }

    @Test
    void ordinaryReturnedPsbtAndMissingOrCorruptReceiptFailClosed() throws Exception {
        PSBT ordinaryReturn = new PSBT(hex("signed_psbt_hex"), false);
        byte[] before = ordinaryReturn.serialize();
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, ordinaryReturn, Set.of()));
        TransactionData tab = new TransactionData("ordinary return", ordinaryReturn);
        tab.setSigningWallet(wallet);
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING, AntiExfilPolicy.evaluatePsbtEgress(tab));
        assertArrayEquals(before, ordinaryReturn.serialize(), "rejection must not mutate the returned PSBT");

        Path sessions = temporary.resolve("sessions");
        Path journals = temporary.resolve("journals");
        String identity = Utils.bytesToHex(AntiExfilCoordinator.getWalletKeyIdentity(kern));
        session = sessions.resolve(identity).resolve(vector.get("original_psbt_sha256").getAsString() + ".aexs");
        journal = journals.resolve(identity + ".aexj");
        AntiExfilCoordinator coordinator = coordinator();
        coordinator.acceptOpenings(hex("message_2_hex"));
        coordinator.complete(hex("message_4_hex"));
        var proofs = AntiExfilProvenanceStore.resolve(sessions, journals, wallet, ordinaryReturn);
        assertEquals(1, proofs.size());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, ordinaryReturn, proofs));
        byte[] receipt = Files.readAllBytes(session);
        byte[] corrupt = receipt.clone();
        corrupt[corrupt.length - 1] ^= 1;
        Files.write(session, corrupt);
        assertTrue(AntiExfilProvenanceStore.resolve(sessions, journals, wallet, ordinaryReturn).isEmpty());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, ordinaryReturn,
                        AntiExfilProvenanceStore.resolve(sessions, journals, wallet, ordinaryReturn)));
        assertEquals(AntiExfilKeystorePolicy.REQUIRED, kern.getAntiExfilPolicy());
    }

    @Test
    void abortAndInvalidSignatureDoNotLowerKernPolicyOrPermitOrdinaryReturn() throws Exception {
        AntiExfilCoordinator coordinator = coordinator();
        coordinator.acceptOpenings(hex("message_2_hex"));
        byte[] invalid = hex("message_4_hex");
        invalid[invalid.length - 1] ^= 1;
        assertThrows(AntiExfilException.class, () -> coordinator.complete(invalid));
        assertNotEquals(AntiExfilCoordinator.Phase.COMPLETE, coordinator.getStatus().getPhase());
        coordinator.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.SIGNATURE_REJECTED);
        AntiExfilCoordinator reloaded = AntiExfilCoordinator.load(session, journal, kern);
        assertEquals(1, reloaded.getStatus().getPostRevealAbortCount());
        assertEquals(AntiExfilKeystorePolicy.REQUIRED, kern.getAntiExfilPolicy());
        assertEquals(AntiExfilPolicy.ProvenanceStatus.REQUIRED_PROOF_MISSING,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, new PSBT(hex("signed_psbt_hex"), false), Set.of()));
    }

    @Test
    void requiredKernBlocksSoftwareFallbackWhileOptionalStillWorks() throws Exception {
        // Private material comes only from the repository's public software test vector.
        Wallet software = wallet.copy();
        Keystore privateSigner = Keystore.fromSeed(new DeterministicSeed(
                vector.getAsJsonObject("signer_a").get("mnemonic").getAsString(), "", 0, DeterministicSeed.Type.BIP39),
                PolicyType.MULTI_HD, KeyDerivation.parsePath(vector.getAsJsonObject("signer_a").get("account_derivation").getAsString()));
        software.getKeystores().set(0, privateSigner);
        assertTrue(HeadersController.violatesRequiredSoftwareSigning(wallet, software, new PSBT(original, false)));
        kern.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL);
        assertFalse(HeadersController.violatesRequiredSoftwareSigning(wallet, software, new PSBT(original, false)));
        assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,
                AntiExfilPolicy.evaluateSignatureProvenance(wallet, new PSBT(hex("signed_psbt_hex"), false), Set.of()));
    }

    private byte[] hex(String field) { return Utils.hexToBytes(vector.get(field).getAsString()); }

    private static Keystore signer(JsonObject data, WalletModel model, AntiExfilKeystorePolicy policy) throws Exception {
        Keystore signer = Keystore.fromSeed(new DeterministicSeed(data.get("mnemonic").getAsString(), "", 0,
                DeterministicSeed.Type.BIP39), PolicyType.MULTI_HD,
                KeyDerivation.parsePath(data.get("account_derivation").getAsString()));
        signer.setSeed(null);
        signer.setMasterPrivateExtendedKey(null);
        signer.setSource(KeystoreSource.HW_AIRGAPPED);
        signer.setWalletModel(model);
        signer.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);
        signer.setAntiExfilPolicy(policy);
        return signer;
    }

    private AntiExfilCoordinator coordinator() throws Exception {
        // Reproduce the existing public vector; no new physical signing session is involved.
        var create = AntiExfilCoordinator.class.getDeclaredMethod("create", Path.class, Path.class, byte[].class,
                Keystore.class, AntiExfilNetwork.class, boolean.class, SecureRandom.class);
        create.setAccessible(true);
        return (AntiExfilCoordinator)create.invoke(null, session, journal, original, kern,
                AntiExfilNetwork.TESTNET4, false, new SecureRandom() {
                    private int call;
                    @Override public void nextBytes(byte[] bytes) { Arrays.fill(bytes, call++ == 0 ? (byte)'m' : (byte)0xa1); }
                });
    }
}
