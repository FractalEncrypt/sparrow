package com.sparrowwallet.sparrow.transaction;
import com.sparrowwallet.drongo.antiexfil.VerifiedAntiExfilSignature;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.sparrow.io.Storage;
import java.nio.file.Path;
import java.util.Set;

/** Retired durable provenance API. Legacy files are preserved, never replayed or copied. */
public final class AntiExfilProvenanceStore {
    private AntiExfilProvenanceStore() {}
    static Set<VerifiedAntiExfilSignature> resolve(Path sessions, Path journals, Wallet wallet, PSBT psbt) { return Set.of(); }
    public static void record(Wallet wallet, Storage storage, Path ignoredSessionPath, PSBT signedPsbt) {}
    public static Set<VerifiedAntiExfilSignature> resolve(Wallet wallet, Storage storage, PSBT psbt) { return Set.of(); }
}
