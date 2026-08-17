package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator;
import com.sparrowwallet.drongo.antiexfil.VerifiedAntiExfilSignature;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.sparrow.io.Storage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Untrusted lookup index plus bounded legacy scan for revalidated ceremony sessions.
 * Index entries can only suggest candidates; AntiExfilCoordinator.load is always the
 * authority before a proof is returned.
 */
public final class AntiExfilProvenanceStore {
    private static final Logger log = LoggerFactory.getLogger(AntiExfilProvenanceStore.class);
    private static final int MAX_INDEX_LINES = 4096;
    private static final int MAX_SESSION_CANDIDATES = 1024;

    private AntiExfilProvenanceStore() {
    }

    public static void record(Wallet wallet, Storage storage, Path sessionPath, PSBT signedPsbt) {
        if(wallet == null || storage == null || sessionPath == null || signedPsbt == null) return;
        Path walletRoot = walletSessionRoot(Storage.getStateDir().toPath(), storage.getWalletId(wallet));
        Path normalizedSession = sessionPath.toAbsolutePath().normalize();
        if(!normalizedSession.startsWith(walletRoot.toAbsolutePath().normalize())) return;
        String relative = walletRoot.relativize(normalizedSession).toString().replace('\\', '/');
        String digest = Utils.bytesToHex(Sha256Hash.hash(signedPsbt.getForExport().serialize()));
        Path index = indexPath(walletRoot);
        try {
            Files.createDirectories(index.getParent());
            List<String> lines = Files.exists(index)
                    ? new ArrayList<>(Files.readAllLines(index, StandardCharsets.UTF_8))
                    : new ArrayList<>();
            String entry = digest + " " + relative;
            lines.remove(entry);
            lines.add(0, entry);
            if(lines.size() > MAX_INDEX_LINES) lines.subList(MAX_INDEX_LINES, lines.size()).clear();
            Path temporary = index.resolveSibling(index.getFileName() + ".tmp");
            Files.write(temporary, lines, StandardCharsets.UTF_8);
            try {
                Files.move(temporary, index, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch(IOException atomicUnavailable) {
                Files.move(temporary, index, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch(IOException exception) {
            log.warn("Could not update anti-exfil provenance lookup index; bounded session scan remains available", exception);
        }
    }

    public static Set<VerifiedAntiExfilSignature> resolve(Wallet wallet, Storage storage, PSBT psbt) {
        if(wallet == null || storage == null || psbt == null) return Set.of();
        Path stateRoot = Storage.getStateDir().toPath();
        return resolve(walletSessionRoot(stateRoot, storage.getWalletId(wallet)),
                stateRoot.resolve("anti-exfil").resolve("journals"), wallet, psbt);
    }

    static Set<VerifiedAntiExfilSignature> resolve(Path walletRoot, Path journalsRoot, Wallet wallet, PSBT psbt) {
        Set<Path> candidates = new LinkedHashSet<>();
        addIndexedCandidate(walletRoot, psbt, candidates);
        for(Keystore keystore : wallet.getKeystores()) {
            if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) continue;
            String identity = Utils.bytesToHex(AntiExfilCoordinator.getWalletKeyIdentity(keystore));
            Path directory = walletRoot.resolve(identity);
            if(!Files.isDirectory(directory)) continue;
            try(var paths = Files.list(directory)) {
                paths.filter(path -> path.getFileName().toString().endsWith(".aexs"))
                        .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                        .limit(MAX_SESSION_CANDIDATES).forEach(candidates::add);
            } catch(IOException exception) {
                log.debug("Could not enumerate anti-exfil sessions in {}", directory, exception);
            }
        }

        Set<VerifiedAntiExfilSignature> resolved = new LinkedHashSet<>();
        Path normalizedRoot = walletRoot.toAbsolutePath().normalize();
        Path realRoot;
        try {
            realRoot = normalizedRoot.toRealPath();
        } catch(IOException exception) {
            return Set.of();
        }
        for(Path candidate : candidates) {
            Path normalized = candidate.toAbsolutePath().normalize();
            if(!normalized.startsWith(normalizedRoot) || !Files.isRegularFile(normalized)) continue;
            try {
                normalized = normalized.toRealPath();
            } catch(IOException exception) {
                continue;
            }
            if(!normalized.startsWith(realRoot)) continue;
            for(Keystore keystore : wallet.getKeystores()) {
                if(keystore.getExtendedPublicKey() == null || keystore.getKeyDerivation() == null) continue;
                String identity = Utils.bytesToHex(AntiExfilCoordinator.getWalletKeyIdentity(keystore));
                if(!normalized.getParent().getFileName().toString().equals(identity)) continue;
                try {
                    Path journal = journalsRoot.resolve(identity + ".aexj");
                    AntiExfilCoordinator.Completion completion = AntiExfilCoordinator.load(normalized, journal, keystore)
                            .getCompletedResult();
                    resolved.addAll(AntiExfilPolicy.retainMatchingProofs(wallet, psbt,
                            completion.getVerifiedSignatures()));
                } catch(Exception exception) {
                    log.debug("Rejected anti-exfil session candidate {}", normalized, exception);
                }
            }
        }
        return Set.copyOf(resolved);
    }

    private static void addIndexedCandidate(Path walletRoot, PSBT psbt, Set<Path> candidates) {
        Path index = indexPath(walletRoot);
        if(!Files.isRegularFile(index)) return;
        String digest = Utils.bytesToHex(Sha256Hash.hash(psbt.getForExport().serialize()));
        try {
            Files.readAllLines(index, StandardCharsets.UTF_8).stream().limit(MAX_INDEX_LINES)
                    .map(line -> line.split(" ", 2))
                    .filter(parts -> parts.length == 2 && parts[0].equals(digest))
                    .map(parts -> walletRoot.resolve(parts[1]).normalize())
                    .forEach(candidates::add);
        } catch(IOException exception) {
            log.debug("Ignoring unreadable anti-exfil provenance lookup index", exception);
        }
    }

    private static Path walletSessionRoot(Path stateRoot, String walletId) {
        String walletDirectory = Utils.bytesToHex(Sha256Hash.hash(walletId.getBytes(StandardCharsets.UTF_8)))
                .substring(0, 32);
        return stateRoot.resolve("anti-exfil").resolve("sessions").resolve(walletDirectory);
    }

    private static Path indexPath(Path walletRoot) {
        return walletRoot.resolve("provenance-v1.index");
    }
}
