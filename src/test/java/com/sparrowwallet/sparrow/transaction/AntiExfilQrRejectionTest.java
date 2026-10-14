package com.sparrowwallet.sparrow.transaction;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.drongo.KeyDerivation;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.antiexfil.*;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.hummingbird.UR;
import com.sparrowwallet.sparrow.control.QRScanDialog;
import com.sparrowwallet.sparrow.io.AntiExfilQrCodec;
import com.sparrowwallet.sparrow.io.AntiExfilTransportPackage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/** Real QR result decoding, signing flow and RAM-only coordinator, without camera/dialog execution. */
class AntiExfilQrRejectionTest {
    @TempDir Path temporary;
    private JsonObject vector;
    private Keystore signer;
    private Path session;
    private Path journal;
    private AntiExfilCoordinator coordinator;

    @BeforeEach
    void setup() throws Exception {
        try(var reader = new InputStreamReader(getClass().getResourceAsStream(
                "/com/sparrowwallet/sparrow/io/protocol-v1-mixed-provenance-vector.json"), StandardCharsets.UTF_8)) {
            vector = JsonParser.parseReader(reader).getAsJsonObject();
        }
        JsonObject account = vector.getAsJsonObject("signer_a");
        signer = Keystore.fromSeed(new DeterministicSeed(account.get("mnemonic").getAsString(), "", 0,
                DeterministicSeed.Type.BIP39), PolicyType.MULTI_HD,
                KeyDerivation.parsePath(account.get("account_derivation").getAsString()));
        signer.setSeed(null);
        signer.setMasterPrivateExtendedKey(null);
        signer.setSource(KeystoreSource.HW_AIRGAPPED);
        signer.setWalletModel(WalletModel.JADE);
        signer.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);
        signer.setAntiExfilPolicy(AntiExfilKeystorePolicy.REQUIRED);
        session = temporary.resolve("public-vector.aexs");
        journal = temporary.resolve("public-vector.aexj");
        var create = AntiExfilCoordinator.class.getDeclaredMethod("create", Path.class, Path.class, byte[].class,
                Keystore.class, AntiExfilNetwork.class, boolean.class, SecureRandom.class);
        create.setAccessible(true);
        coordinator = (AntiExfilCoordinator)create.invoke(null, session, journal, hex("original_psbt_hex"), signer,
                AntiExfilNetwork.TESTNET4, false, new SecureRandom() {
                    private int call;
                    @Override public void nextBytes(byte[] bytes) { Arrays.fill(bytes, call++ == 0 ? (byte)'m' : (byte)0xa1); }
                });
        assertArrayEquals(hex("message_1_hex"), coordinator.getHostCommitMessage());
    }

    @Test
    void wrongNetworkOpeningsAreJournalledBeforeRevealAndStaySpentAfterReload() throws Exception {
        Exchange exchange = new Exchange();
        exchange.scans.add(scan(wrongNetwork(hex("message_2_hex"))));
        assertCode(AntiExfilException.Code.TRANSACTION_MISMATCH, exchange);
        assertEquals(List.of(AntiExfilStage.HOST_COMMIT), exchange.stages);
        assertEquals(AntiExfilCoordinator.Phase.CLOSED, reload().getStatus().getPhase());
        assertOneEvent(AntiExfilCoordinator.AbortReason.SIGNATURE_REJECTED);
        assertEquals(AntiExfilException.Code.STATE_INVALID, assertThrows(AntiExfilException.class,
                () -> reload().acceptOpenings(hex("message_2_hex"))).getCode());
        assertEquals(AntiExfilKeystorePolicy.REQUIRED, signer.getAntiExfilPolicy());
    }

    @Test
    void wrongNetworkSignaturesAreJournalledAfterRevealWithoutCompletion() throws Exception {
        Exchange exchange = new Exchange();
        exchange.scans.add(scan(hex("message_2_hex")));
        exchange.scans.add(scan(wrongNetwork(hex("message_4_hex"))));
        assertCode(AntiExfilException.Code.TRANSACTION_MISMATCH, exchange);
        assertEquals(List.of(AntiExfilStage.HOST_COMMIT, AntiExfilStage.HOST_REVEAL), exchange.stages);
        assertEquals(AntiExfilCoordinator.Phase.CLOSED, reload().getStatus().getPhase());
        assertOneEvent(AntiExfilCoordinator.AbortReason.SIGNATURE_REJECTED);
        assertThrows(AntiExfilException.class, () -> reload().getCompletedResult());
        assertEquals(AntiExfilKeystorePolicy.REQUIRED, signer.getAntiExfilPolicy());
    }

    @Test
    void malformedDecodedPackageIsARejectionInsteadOfCancellation() throws Exception {
        Exchange exchange = new Exchange();
        exchange.scans.add(Optional.of(new QRScanDialog.Result(
                UR.fromBytes(AntiExfilTransportPackage.UR_TYPE, new byte[]{'A', 'E', 'X', 'T'}))));
        assertCode(AntiExfilException.Code.INVALID_MESSAGE, exchange);
        assertOneEvent(AntiExfilCoordinator.AbortReason.SIGNATURE_REJECTED);
        assertEquals(List.of(AntiExfilStage.HOST_COMMIT), exchange.stages);
    }

    @Test
    void typedProtocolErrorFromScannerResultKeepsItsCodeAndJournal() {
        Exchange exchange = new Exchange();
        AntiExfilException error = new AntiExfilException(AntiExfilException.Code.TRANSACTION_MISMATCH, "changed context");
        exchange.scans.add(Optional.of(new QRScanDialog.Result(error)));
        assertSame(error, assertCode(AntiExfilException.Code.TRANSACTION_MISMATCH, exchange));
        assertOneEvent(AntiExfilCoordinator.AbortReason.SIGNATURE_REJECTED);
    }

    @Test
    void wrongStageBeforeRevealDoesNotSpendTheSession() throws Exception {
        Exchange exchange = new Exchange();
        exchange.scans.add(scan(hex("message_4_hex")));
        assertCode(AntiExfilException.Code.WRONG_STAGE, exchange);
        assertTrue(events().isEmpty());
        assertEquals(List.of(AntiExfilStage.HOST_COMMIT), exchange.stages);
        assertThrows(AntiExfilException.class, () -> reload().acceptOpenings(hex("message_2_hex")));
        assertFalse(java.nio.file.Files.exists(session));
    }

    @Test
    void wrongStageAfterRevealKeepsTheExistingExactSessionRetry() throws Exception {
        Exchange exchange = new Exchange();
        exchange.scans.add(scan(hex("message_2_hex")));
        exchange.scans.add(scan(hex("message_2_hex")));
        assertCode(AntiExfilException.Code.WRONG_STAGE, exchange);
        assertEquals("PENDING_REVEAL", events().getFirst().getReason());
        assertEquals(AntiExfilCoordinator.Phase.CLOSED, reload().getStatus().getPhase());
        assertThrows(AntiExfilException.class, () -> reload().complete(hex("message_4_hex")));
    }

    @Test
    void cancellingCommitDisplayDoesNotSpendSession() throws Exception {
        Exchange exchange = new Exchange();
        exchange.displayResults.add(false);
        assertEquals(AntiExfilSigningFlow.Outcome.CANCELLED_BEFORE_REVEAL, execute(exchange).outcome());
        assertTrue(events().isEmpty());
        assertThrows(AntiExfilException.class, () -> reload().acceptOpenings(hex("message_2_hex")));
        assertFalse(java.nio.file.Files.exists(session));
    }

    @Test
    void cancellingOpeningScanDoesNotSpendSession() throws Exception {
        Exchange exchange = new Exchange();
        exchange.scans.add(Optional.empty());
        assertEquals(AntiExfilSigningFlow.Outcome.CANCELLED_BEFORE_REVEAL, execute(exchange).outcome());
        assertTrue(exchange.transportErrors.isEmpty());
        assertTrue(events().isEmpty());
        assertThrows(AntiExfilException.class, () -> reload().acceptOpenings(hex("message_2_hex")));
        assertFalse(java.nio.file.Files.exists(session));
    }

    @Test
    void ordinaryScannerFailureKeepsTransportHandling() throws Exception {
        Exchange exchange = new Exchange();
        exchange.scans.add(Optional.of(new QRScanDialog.Result(new IllegalArgumentException("camera unavailable"))));
        assertEquals(AntiExfilSigningFlow.Outcome.CANCELLED_BEFORE_REVEAL, execute(exchange).outcome());
        assertEquals(List.of("camera unavailable"), exchange.transportErrors);
        assertTrue(events().isEmpty());
        assertThrows(AntiExfilException.class, () -> reload().acceptOpenings(hex("message_2_hex")));
        assertFalse(java.nio.file.Files.exists(session));
    }

    @Test
    void scannerResultWithoutUrKeepsTransportHandling() {
        Exchange exchange = new Exchange();
        exchange.scans.add(Optional.of(new QRScanDialog.Result((UR)null)));
        assertEquals(AntiExfilSigningFlow.Outcome.CANCELLED_BEFORE_REVEAL, execute(exchange).outcome());
        assertEquals(List.of("Scanner returned no anti-exfil UR"), exchange.transportErrors);
        assertTrue(events().isEmpty());
    }

    @Test
    void postRevealCancellationRetriesTheExactPackageThenCompletes() throws Exception {
        Exchange exchange = new Exchange();
        exchange.scans.add(scan(hex("message_2_hex")));
        exchange.scans.add(Optional.empty());
        exchange.scans.add(scan(hex("message_4_hex")));
        exchange.actions.add(AntiExfilSigningFlow.PostRevealAction.RETRY_EXACT);
        var result = execute(exchange);
        assertEquals(AntiExfilSigningFlow.Outcome.COMPLETE, result.outcome());
        assertArrayEquals(exchange.displayed.get(1), exchange.displayed.get(2));
        assertEquals(List.of("PENDING_REVEAL", "VERIFIED_COMPLETE"), events().stream().map(AntiExfilAbortJournal.AbortEvent::getReason).toList());
        assertFalse(result.completion().isBroadcast());
    }

    @Test
    void abandoningAfterScanCancellationRecordsTransportFailure() throws Exception {
        Exchange exchange = new Exchange();
        exchange.scans.add(scan(hex("message_2_hex")));
        exchange.scans.add(Optional.empty());
        exchange.actions.add(AntiExfilSigningFlow.PostRevealAction.ABANDON);
        assertEquals(AntiExfilSigningFlow.Outcome.ABORTED_AFTER_REVEAL, execute(exchange).outcome());
        assertOneEvent(AntiExfilCoordinator.AbortReason.TRANSPORT_FAILED);
        assertEquals(AntiExfilCoordinator.Phase.CLOSED, reload().getStatus().getPhase());
    }

    @Test
    void abandoningRevealDisplayRecordsUserAbandonment() throws Exception {
        Exchange exchange = new Exchange();
        exchange.displayResults.add(true);
        exchange.displayResults.add(false);
        exchange.scans.add(scan(hex("message_2_hex")));
        exchange.actions.add(AntiExfilSigningFlow.PostRevealAction.ABANDON);
        assertEquals(AntiExfilSigningFlow.Outcome.ABORTED_AFTER_REVEAL, execute(exchange).outcome());
        assertOneEvent(AntiExfilCoordinator.AbortReason.USER_ABANDONED);
    }

    @Test
    void coordinatorAndFlowRejectionHandlersDoNotDuplicateTheEvent() throws Exception {
        AntiExfilMessage good = AntiExfilCodec.decode(hex("message_2_hex"));
        byte[] changed = good.getPsbtDigest();
        changed[0] ^= 1;
        byte[] wrongContext = AntiExfilCodec.encode(new AntiExfilMessage(good.getNetwork(), good.getStage(),
                good.getSessionId(), changed, good.getSlots()));
        Exchange exchange = new Exchange();
        exchange.scans.add(scan(wrongContext));
        assertCode(AntiExfilException.Code.TRANSACTION_MISMATCH, exchange);
        assertOneEvent(AntiExfilCoordinator.AbortReason.SIGNATURE_REJECTED);
        assertEquals(AntiExfilException.Code.STATE_INVALID, assertThrows(AntiExfilException.class,
                () -> reload().acceptOpenings(hex("message_2_hex"))).getCode());
    }

    @Test
    void validFourStageCeremonyStillCompletesAndReloadsProof() throws Exception {
        Exchange exchange = new Exchange();
        exchange.scans.add(scan(hex("message_2_hex")));
        exchange.scans.add(scan(hex("message_4_hex")));
        var result = execute(exchange);
        assertEquals(AntiExfilSigningFlow.Outcome.COMPLETE, result.outcome());
        assertEquals(1, result.completion().getVerifiedSignatures().size());
        assertFalse(result.completion().isBroadcast());
        assertEquals(List.of("PENDING_REVEAL", "VERIFIED_COMPLETE"), events().stream().map(AntiExfilAbortJournal.AbortEvent::getReason).toList());
        assertThrows(AntiExfilException.class, () -> AntiExfilCoordinator.load(session, journal, signer));
        assertFalse(java.nio.file.Files.exists(session));
        assertEquals(result.completion().getVerifiedSignatures(), reload().getCompletedResult().getVerifiedSignatures());
        assertEquals(AntiExfilKeystorePolicy.REQUIRED, signer.getAntiExfilPolicy());
    }

    private byte[] hex(String field) { return Utils.hexToBytes(vector.get(field).getAsString()); }
    private AntiExfilCoordinator reload() { return coordinator; }
    private List<AntiExfilAbortJournal.AbortEvent> events() {
        return new AntiExfilAbortJournal(journal, AntiExfilCoordinator.getWalletKeyIdentity(signer)).getEvents();
    }
    private void assertOneEvent(AntiExfilCoordinator.AbortReason reason) {
        var events = events();
        String expected = coordinator.getStatus().getPhase() == AntiExfilCoordinator.Phase.CLOSED
                && events.size() == 1 ? "PRE_REVEAL_REJECTED" : reason.name();
        assertEquals(expected, events.getLast().getReason());
        assertArrayEquals(coordinator.getStatus().getSessionId(), events.getFirst().getSessionId());
        assertArrayEquals(coordinator.getStatus().getPsbtDigest(), events.getFirst().getPsbtDigest());
    }
    private byte[] wrongNetwork(byte[] message) { byte[] changed = message.clone(); changed[5] = (byte)AntiExfilNetwork.TESTNET3.getCode(); return changed; }
    private Optional<QRScanDialog.Result> scan(byte[] message) {
        return Optional.of(new QRScanDialog.Result(AntiExfilQrCodec.toUr(
                new AntiExfilTransportPackage(AntiExfilCodec.decode(message), null))));
    }
    private AntiExfilSigningFlow.Result execute(Exchange exchange) {
        return AntiExfilSigningFlow.execute(coordinator, AntiExfilNetwork.TESTNET4, exchange);
    }
    private AntiExfilException assertCode(AntiExfilException.Code code, Exchange exchange) {
        var error = assertThrows(AntiExfilException.class, () -> execute(exchange));
        assertEquals(code, error.getCode());
        assertTrue(exchange.transportErrors.isEmpty());
        assertEquals(0, exchange.interruptionPrompts);
        return error;
    }
    private static final class Exchange implements AntiExfilSigningFlow.Exchange {
        private final Deque<Boolean> displayResults = new ArrayDeque<>();
        private final Deque<Optional<QRScanDialog.Result>> scans = new ArrayDeque<>();
        private final Deque<AntiExfilSigningFlow.PostRevealAction> actions = new ArrayDeque<>();
        private final List<AntiExfilStage> stages = new ArrayList<>();
        private final List<byte[]> displayed = new ArrayList<>();
        private final List<String> transportErrors = new ArrayList<>();
        private int interruptionPrompts;
        @Override public boolean display(AntiExfilTransportPackage p) {
            stages.add(p.getMessage().getStage()); displayed.add(p.encode());
            return displayResults.isEmpty() || displayResults.removeFirst();
        }
        @Override public Optional<AntiExfilTransportPackage> scan(AntiExfilStage stage, AntiExfilNetwork network) {
            return AntiExfilQrExchange.decodeScanResult(scans.removeFirst(), stage, network, transportErrors::add);
        }
        @Override public AntiExfilSigningFlow.PostRevealAction onPostRevealInterruption() {
            interruptionPrompts++;
            return actions.isEmpty() ? AntiExfilSigningFlow.PostRevealAction.ABANDON : actions.removeFirst();
        }
    }
}