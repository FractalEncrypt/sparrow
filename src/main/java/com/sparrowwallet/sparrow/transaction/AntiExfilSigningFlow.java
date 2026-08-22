package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.antiexfil.AntiExfilCodec;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator;
import com.sparrowwallet.drongo.antiexfil.AntiExfilException;
import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.antiexfil.AntiExfilStage;
import com.sparrowwallet.sparrow.io.AntiExfilTransportPackage;

import java.util.Optional;

public final class AntiExfilSigningFlow {
    private AntiExfilSigningFlow() {
    }

    public static Result execute(AntiExfilCoordinator coordinator, AntiExfilNetwork network, Exchange exchange) {
        return execute(new CoordinatorSession(coordinator), network, exchange);
    }

    static Result execute(Session session, AntiExfilNetwork network, Exchange exchange) {
        AntiExfilCoordinator.Phase phase = session.phase();
        if(phase == AntiExfilCoordinator.Phase.COMPLETE) {
            return new Result(Outcome.COMPLETE, session.completedResult());
        }

        byte[] frozenPsbt = session.frozenPsbt();
        byte[] revealBytes;
        if(phase == AntiExfilCoordinator.Phase.COMMITMENTS_CREATED) {
            AntiExfilTransportPackage commit = outgoing(session.hostCommitMessage(), frozenPsbt);
            if(!exchange.display(commit)) return new Result(Outcome.CANCELLED_BEFORE_REVEAL, null);
            Optional<AntiExfilTransportPackage> scanned = exchange.scan(AntiExfilStage.SIGNER_OPENINGS, network);
            if(scanned.isEmpty()) return new Result(Outcome.CANCELLED_BEFORE_REVEAL, null);
            try {
                AntiExfilTransportPackage openings = exactIncoming(scanned.get(), AntiExfilStage.SIGNER_OPENINGS, network);
                revealBytes = session.acceptOpenings(AntiExfilCodec.encode(openings.getMessage()));
            } catch(AntiExfilException e) {
                if(AntiExfilCoordinator.isSignerDataRejection(e)) session.recordSignerDataRejection();
                throw e;
            }
        } else {
            revealBytes = session.hostRevealMessage();
        }

        AntiExfilTransportPackage reveal = outgoing(revealBytes, frozenPsbt);
        while(true) {
            if(!exchange.display(reveal)) {
                if(exchange.onPostRevealInterruption() == PostRevealAction.RETRY_EXACT) continue;
                session.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.USER_ABANDONED);
                return new Result(Outcome.ABORTED_AFTER_REVEAL, null);
            }
            Optional<AntiExfilTransportPackage> scanned = exchange.scan(AntiExfilStage.SIGNER_SIGNATURES, network);
            if(scanned.isEmpty()) {
                if(exchange.onPostRevealInterruption() == PostRevealAction.RETRY_EXACT) continue;
                session.recordPostRevealAbort(AntiExfilCoordinator.AbortReason.TRANSPORT_FAILED);
                return new Result(Outcome.ABORTED_AFTER_REVEAL, null);
            }
            try {
                AntiExfilTransportPackage signatures = exactIncoming(scanned.get(), AntiExfilStage.SIGNER_SIGNATURES, network);
                AntiExfilCoordinator.Completion completion = session.complete(AntiExfilCodec.encode(signatures.getMessage()));
                return new Result(Outcome.COMPLETE, completion);
            } catch(AntiExfilException e) {
                if(AntiExfilCoordinator.isSignerDataRejection(e)) session.recordSignerDataRejection();
                throw e;
            }
        }
    }

    private static AntiExfilTransportPackage outgoing(byte[] message, byte[] psbt) {
        AntiExfilTransportPackage transportPackage = new AntiExfilTransportPackage(AntiExfilCodec.decode(message), psbt);
        return AntiExfilTransportPackage.decode(transportPackage.encode());
    }

    private static AntiExfilTransportPackage exactIncoming(AntiExfilTransportPackage transportPackage,
                                                            AntiExfilStage stage, AntiExfilNetwork network) {
        AntiExfilTransportPackage canonical = AntiExfilTransportPackage.decode(transportPackage.encode());
        canonical.require(stage, network);
        return canonical;
    }

    public interface Exchange {
        boolean display(AntiExfilTransportPackage transportPackage);
        Optional<AntiExfilTransportPackage> scan(AntiExfilStage expectedStage, AntiExfilNetwork expectedNetwork);
        PostRevealAction onPostRevealInterruption();
    }

    interface Session {
        AntiExfilCoordinator.Phase phase();
        byte[] frozenPsbt();
        byte[] hostCommitMessage();
        byte[] acceptOpenings(byte[] message);
        byte[] hostRevealMessage();
        AntiExfilCoordinator.Completion complete(byte[] message);
        AntiExfilCoordinator.Completion completedResult();
        void recordPostRevealAbort(AntiExfilCoordinator.AbortReason reason);
        void recordSignerDataRejection();
    }

    private record CoordinatorSession(AntiExfilCoordinator coordinator) implements Session {
        @Override public AntiExfilCoordinator.Phase phase() { return coordinator.getStatus().getPhase(); }
        @Override public byte[] frozenPsbt() { return coordinator.getFrozenPsbt(); }
        @Override public byte[] hostCommitMessage() { return coordinator.getHostCommitMessage(); }
        @Override public byte[] acceptOpenings(byte[] message) { return coordinator.acceptOpenings(message); }
        @Override public byte[] hostRevealMessage() { return coordinator.getHostRevealMessage(); }
        @Override public AntiExfilCoordinator.Completion complete(byte[] message) { return coordinator.complete(message); }
        @Override public AntiExfilCoordinator.Completion completedResult() { return coordinator.getCompletedResult(); }
        @Override public void recordPostRevealAbort(AntiExfilCoordinator.AbortReason reason) { coordinator.recordPostRevealAbort(reason); }
        @Override public void recordSignerDataRejection() { coordinator.recordSignerDataRejection(); }
    }

    public enum PostRevealAction {
        RETRY_EXACT,
        ABANDON
    }

    public enum Outcome {
        COMPLETE,
        CANCELLED_BEFORE_REVEAL,
        ABORTED_AFTER_REVEAL
    }

    public record Result(Outcome outcome, AntiExfilCoordinator.Completion completion) {
    }
}
