package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTOutput;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentAddress;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.io.Storage;
import com.sparrowwallet.drongo.antiexfil.VerifiedAntiExfilSignature;
import javafx.beans.property.SimpleObjectProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableMap;

import java.util.*;

public class TransactionData {
    public enum Origin {
        EXTERNAL,
        INTERNAL_SWEEP
    }

    private Transaction transaction;
    private String name;
    private PSBT psbt;
    private BlockTransaction blockTransaction;
    private Map<Sha256Hash, BlockTransaction> inputTransactions;
    private List<BlockTransaction> outputTransactions;
    private final Set<VerifiedAntiExfilSignature> verifiedAntiExfilSignatures = new LinkedHashSet<>();
    private final Origin origin;
    private final byte[] originTransactionDigest;

    private int minInputFetched;
    private int maxInputFetched;
    private int minOutputFetched;
    private int maxOutputFetched;

    private final ObservableMap<Wallet, Storage> availableWallets = FXCollections.observableHashMap();
    private final SimpleObjectProperty<Wallet> signingWallet = new SimpleObjectProperty<>(this, "signingWallet", null);
    private final ObservableMap<TransactionSignature, Keystore> signatureKeystoreMap = FXCollections.observableMap(new LinkedHashMap<>());
    private final SimpleObjectProperty<WalletTransaction> walletTransaction = new SimpleObjectProperty<>(this, "walletTransaction", null);

    public TransactionData(String name, PSBT psbt) {
        this(name, psbt, Set.of());
    }

    public TransactionData(String name, PSBT psbt, Set<VerifiedAntiExfilSignature> verifiedAntiExfilSignatures) {
        this(name, psbt.getTransaction());
        this.psbt = psbt;
        this.verifiedAntiExfilSignatures.addAll(verifiedAntiExfilSignatures);
    }

    public TransactionData(String name, BlockTransaction blockTransaction) {
        this(name, blockTransaction.getTransaction());
        this.blockTransaction = blockTransaction;
    }

    public TransactionData(String name, Transaction transaction) {
        this(name, transaction, Origin.EXTERNAL);
    }

    public TransactionData(String name, Transaction transaction, Origin origin) {
        this.name = name;
        this.transaction = transaction;
        this.origin = Objects.requireNonNull(origin);
        // This authorization is intentionally in-memory only. File/QR parsing, persistence,
        // and cross-window events use the EXTERNAL constructors, and any byte mutation
        // invalidates the snapshot below.
        this.originTransactionDigest = origin == Origin.INTERNAL_SWEEP
                ? Sha256Hash.hash(transaction.bitcoinSerialize())
                : null;
    }

    public Transaction getTransaction() {
        return transaction;
    }

    public void setTransaction(Transaction transaction) {
        this.transaction = transaction;
    }

    public boolean hasValidInternalSweepOrigin() {
        return origin == Origin.INTERNAL_SWEEP
                && Arrays.equals(originTransactionDigest, Sha256Hash.hash(transaction.bitcoinSerialize()));
    }

    public String getName() {
        return name;
    }

    public PSBT getPsbt() {
        return psbt;
    }

    public Set<VerifiedAntiExfilSignature> getVerifiedAntiExfilSignatures() {
        return Collections.unmodifiableSet(verifiedAntiExfilSignatures);
    }

    public void addVerifiedAntiExfilSignatures(Collection<VerifiedAntiExfilSignature> signatures) {
        verifiedAntiExfilSignatures.addAll(signatures);
    }

    public void replaceVerifiedAntiExfilSignatures(Collection<VerifiedAntiExfilSignature> signatures) {
        verifiedAntiExfilSignatures.clear();
        verifiedAntiExfilSignatures.addAll(signatures);
    }

    public BlockTransaction getBlockTransaction() {
        return blockTransaction;
    }

    public void setBlockTransaction(BlockTransaction blockTransaction) {
        this.blockTransaction = blockTransaction;
    }

    public Map<Sha256Hash, BlockTransaction> getInputTransactions() {
        return inputTransactions;
    }

    public void setInputTransactions(Map<Sha256Hash, BlockTransaction> inputTransactions) {
        this.inputTransactions = inputTransactions;
    }

    public void updateInputsFetchedRange(int pageStart, int pageEnd) {
        if(pageStart < 0 || pageEnd > transaction.getInputs().size()) {
            throw new IllegalStateException("Paging outside transaction inputs range");
        }

        if(pageStart != maxInputFetched) {
            //non contiguous range, ignore
            return;
        }

        this.minInputFetched = Math.min(minInputFetched, pageStart);
        this.maxInputFetched = Math.max(maxInputFetched, pageEnd);
    }

    public int getMaxInputFetched() {
        return maxInputFetched;
    }

    public boolean allInputsFetched() {
        return minInputFetched == 0 && maxInputFetched == transaction.getInputs().size();
    }

    public List<BlockTransaction> getOutputTransactions() {
        return outputTransactions;
    }

    public void setOutputTransactions(List<BlockTransaction> outputTransactions) {
        this.outputTransactions = outputTransactions;
    }

    public void updateOutputsFetchedRange(int pageStart, int pageEnd) {
        if(pageStart < 0 || pageEnd > transaction.getOutputs().size()) {
            throw new IllegalStateException("Paging outside transaction outputs range");
        }

        if(pageStart != maxOutputFetched) {
            //non contiguous range, ignore
            return;
        }

        this.minOutputFetched = Math.min(minOutputFetched, pageStart);
        this.maxOutputFetched = Math.max(maxOutputFetched, pageEnd);
    }

    public int getMaxOutputFetched() {
        return maxOutputFetched;
    }

    public boolean allOutputsFetched() {
        return minOutputFetched == 0 && maxOutputFetched == transaction.getOutputs().size();
    }

    public ObservableMap<Wallet, Storage> getAvailableWallets() {
        return availableWallets;
    }

    public Wallet getSigningWallet() {
        return signingWallet.get();
    }

    public SimpleObjectProperty<Wallet> signingWalletProperty() {
        return signingWallet;
    }

    public void setSigningWallet(Wallet wallet) {
        this.signingWallet.set(wallet);
    }

    public ObservableMap<TransactionSignature, Keystore> getSignatureKeystoreMap() {
        return signatureKeystoreMap;
    }

    public Collection<Keystore> getSignedKeystores() {
        return signatureKeystoreMap.values();
    }

    public Set<WalletNode> getSigningWalletNodes() {
        if(getSigningWallet() == null) {
            throw new IllegalStateException("Signing wallet cannot be null");
        }

        Set<WalletNode> signingWalletNodes = new LinkedHashSet<>();
        for(TransactionInput txInput : transaction.getInputs()) {
            Optional<WalletNode> optNode = getSigningWallet().getWalletTxos().entrySet().stream().filter(entry -> entry.getKey().getHash().equals(txInput.getOutpoint().getHash()) && entry.getKey().getIndex() == txInput.getOutpoint().getIndex()).map(Map.Entry::getValue).findFirst();
            optNode.ifPresent(signingWalletNodes::add);
        }

        for(TransactionOutput txOutput : transaction.getOutputs()) {
            WalletNode changeNode = getSigningWallet().getWalletOutputScripts(KeyPurpose.CHANGE).get(txOutput.getScript());
            if(changeNode != null) {
                signingWalletNodes.add(changeNode);
            } else {
                WalletNode receiveNode = getSigningWallet().getWalletOutputScripts(KeyPurpose.RECEIVE).get(txOutput.getScript());
                if(receiveNode != null) {
                    signingWalletNodes.add(receiveNode);
                }
            }
        }

        return signingWalletNodes;
    }

    public WalletTransaction getWalletTransaction() {
        return walletTransaction.get();
    }

    public SimpleObjectProperty<WalletTransaction> walletTransactionProperty() {
        return walletTransaction;
    }

    public void setWalletTransaction(WalletTransaction walletTransaction) {
        this.walletTransaction.set(walletTransaction);
    }

    public Wallet getWallet() {
        return getSigningWallet() != null ? getSigningWallet() : (getWalletTransaction() != null ? getWalletTransaction().getWallet() : null);
    }

    protected SilentPaymentAddress getSilentPaymentAddress(TransactionOutput txOutput) {
        if(getPsbt() != null && txOutput.getParent() != null) {
            for(PSBTOutput psbtOutput : getPsbt().getPsbtOutputs()) {
                if(psbtOutput.getOutput().getIndex() == txOutput.getIndex() && psbtOutput.getSilentPaymentAddress() != null) {
                    return psbtOutput.getSilentPaymentAddress();
                }
            }
        }

        return null;
    }
}
