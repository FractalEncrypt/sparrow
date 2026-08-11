package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.antiexfil.AntiExfilCodec;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCrypto;
import com.sparrowwallet.drongo.antiexfil.AntiExfilException;
import com.sparrowwallet.drongo.antiexfil.AntiExfilMessage;
import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.antiexfil.AntiExfilSlot;
import com.sparrowwallet.drongo.antiexfil.AntiExfilStage;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.sparrow.io.AntiExfilTransportPackage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class AntiExfilSigningFlowTest {
    private final byte[] psbt = new byte[]{'p', 's', 'b', 't', (byte)0xff, 0};
    private AntiExfilMessage message1;
    private AntiExfilMessage message2;
    private AntiExfilMessage message3;
    private AntiExfilMessage message4;

    @BeforeEach
    void setup() {
        message1 = message(AntiExfilStage.HOST_COMMIT);
        message2 = message(AntiExfilStage.SIGNER_OPENINGS);
        message3 = message(AntiExfilStage.HOST_REVEAL);
        message4 = message(AntiExfilStage.SIGNER_SIGNATURES);
    }

    @Test
    void completesFourStageExchange() {
        FakeSession session = new FakeSession();
        FakeExchange exchange = new FakeExchange(true, true);
        exchange.scans.add(Optional.of(transport(message2)));
        exchange.scans.add(Optional.of(transport(message4)));
        AntiExfilSigningFlow.Result result = AntiExfilSigningFlow.execute(session, AntiExfilNetwork.TESTNET4, exchange);
        assertEquals(AntiExfilSigningFlow.Outcome.COMPLETE, result.outcome());
        assertEquals(List.of(AntiExfilStage.HOST_COMMIT, AntiExfilStage.HOST_REVEAL), exchange.displayedStages);
        assertTrue(session.aborts.isEmpty());
    }

    @Test
    void cancellationBeforeRevealDoesNotCreateSecurityEvent() {
        FakeSession session = new FakeSession();
        FakeExchange exchange = new FakeExchange(false);
        AntiExfilSigningFlow.Result result = AntiExfilSigningFlow.execute(session, AntiExfilNetwork.TESTNET4, exchange);
        assertEquals(AntiExfilSigningFlow.Outcome.CANCELLED_BEFORE_REVEAL, result.outcome());
        assertTrue(session.aborts.isEmpty());
        assertEquals(AntiExfilCoordinator.Phase.COMMITMENTS_CREATED, session.phase);
    }

    @Test
    void postRevealRetryRedisplaysExactPackageWithoutAbort() {
        FakeSession session = new FakeSession();
        FakeExchange exchange = new FakeExchange(true, true, true);
        exchange.scans.add(Optional.of(transport(message2)));
        exchange.scans.add(Optional.empty());
        exchange.scans.add(Optional.of(transport(message4)));
        exchange.actions.add(AntiExfilSigningFlow.PostRevealAction.RETRY_EXACT);
        AntiExfilSigningFlow.Result result = AntiExfilSigningFlow.execute(session, AntiExfilNetwork.TESTNET4, exchange);
        assertEquals(AntiExfilSigningFlow.Outcome.COMPLETE, result.outcome());
        assertEquals(3, exchange.displayed.size());
        assertArrayEquals(exchange.displayed.get(1), exchange.displayed.get(2));
        assertTrue(session.aborts.isEmpty());
    }

    @Test
    void postRevealAbandonAndInvalidSignatureAreJournaled() {
        FakeSession abandoned = new FakeSession();
        FakeExchange cancelled = new FakeExchange(true, true);
        cancelled.scans.add(Optional.of(transport(message2)));
        cancelled.scans.add(Optional.empty());
        cancelled.actions.add(AntiExfilSigningFlow.PostRevealAction.ABANDON);
        assertEquals(AntiExfilSigningFlow.Outcome.ABORTED_AFTER_REVEAL,
                AntiExfilSigningFlow.execute(abandoned, AntiExfilNetwork.TESTNET4, cancelled).outcome());
        assertEquals(List.of(AntiExfilCoordinator.AbortReason.TRANSPORT_FAILED), abandoned.aborts);

        FakeSession rejected = new FakeSession();
        FakeExchange wrongStage = new FakeExchange(true, true);
        wrongStage.scans.add(Optional.of(transport(message2)));
        wrongStage.scans.add(Optional.of(transport(message2)));
        assertThrows(AntiExfilException.class,
                () -> AntiExfilSigningFlow.execute(rejected, AntiExfilNetwork.TESTNET4, wrongStage));
        assertEquals(List.of(AntiExfilCoordinator.AbortReason.SIGNATURE_REJECTED), rejected.aborts);
    }

    private AntiExfilTransportPackage transport(AntiExfilMessage message) {
        AntiExfilStage stage = message.getStage();
        return new AntiExfilTransportPackage(message,
                stage == AntiExfilStage.HOST_COMMIT || stage == AntiExfilStage.HOST_REVEAL ? psbt : null);
    }

    private AntiExfilMessage message(AntiExfilStage stage) {
        byte[] rho = repeat((byte)0x11);
        byte[] signature = new byte[64];
        signature[31] = 1;
        signature[63] = 1;
        AntiExfilSlot slot = new AntiExfilSlot(0, 1, ECKey.fromPrivate(BigInteger.valueOf(17)).getPubKey(),
                repeat((byte)0x22), AntiExfilCrypto.hostCommit(rho),
                stage.getCode() >= 2 ? ECKey.fromPrivate(BigInteger.valueOf(19)).getPubKey() : null,
                stage == AntiExfilStage.HOST_REVEAL ? rho : null,
                stage == AntiExfilStage.SIGNER_SIGNATURES ? signature : null);
        return new AntiExfilMessage(AntiExfilNetwork.TESTNET4, stage, repeat((byte)0x33),
                Sha256Hash.hash(psbt), List.of(slot));
    }

    private static byte[] repeat(byte value) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, value);
        return bytes;
    }

    private final class FakeSession implements AntiExfilSigningFlow.Session {
        private AntiExfilCoordinator.Phase phase = AntiExfilCoordinator.Phase.COMMITMENTS_CREATED;
        private final List<AntiExfilCoordinator.AbortReason> aborts = new ArrayList<>();
        @Override public AntiExfilCoordinator.Phase phase() { return phase; }
        @Override public byte[] frozenPsbt() { return psbt.clone(); }
        @Override public byte[] hostCommitMessage() { return AntiExfilCodec.encode(message1); }
        @Override public byte[] acceptOpenings(byte[] message) { assertArrayEquals(AntiExfilCodec.encode(message2), message); phase = AntiExfilCoordinator.Phase.OPENINGS_ACCEPTED; return AntiExfilCodec.encode(message3); }
        @Override public byte[] hostRevealMessage() { return AntiExfilCodec.encode(message3); }
        @Override public AntiExfilCoordinator.Completion complete(byte[] message) { assertArrayEquals(AntiExfilCodec.encode(message4), message); phase = AntiExfilCoordinator.Phase.COMPLETE; return null; }
        @Override public AntiExfilCoordinator.Completion completedResult() { return null; }
        @Override public void recordPostRevealAbort(AntiExfilCoordinator.AbortReason reason) { aborts.add(reason); }
    }

    private static final class FakeExchange implements AntiExfilSigningFlow.Exchange {
        private final Deque<Boolean> displays = new ArrayDeque<>();
        private final Deque<Optional<AntiExfilTransportPackage>> scans = new ArrayDeque<>();
        private final Deque<AntiExfilSigningFlow.PostRevealAction> actions = new ArrayDeque<>();
        private final List<byte[]> displayed = new ArrayList<>();
        private final List<AntiExfilStage> displayedStages = new ArrayList<>();

        private FakeExchange(boolean... displayResults) {
            for(boolean result : displayResults) displays.add(result);
        }

        @Override public boolean display(AntiExfilTransportPackage transportPackage) {
            displayed.add(transportPackage.encode());
            displayedStages.add(transportPackage.getMessage().getStage());
            return displays.removeFirst();
        }
        @Override public Optional<AntiExfilTransportPackage> scan(AntiExfilStage expectedStage, AntiExfilNetwork expectedNetwork) { return scans.removeFirst(); }
        @Override public AntiExfilSigningFlow.PostRevealAction onPostRevealInterruption() { return actions.removeFirst(); }
    }
}
