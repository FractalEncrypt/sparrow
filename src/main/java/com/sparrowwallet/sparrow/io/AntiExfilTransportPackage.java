package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.antiexfil.AntiExfilCodec;
import com.sparrowwallet.drongo.antiexfil.AntiExfilException;
import com.sparrowwallet.drongo.antiexfil.AntiExfilMessage;
import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.antiexfil.AntiExfilStage;
import com.sparrowwallet.drongo.protocol.Sha256Hash;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static com.sparrowwallet.drongo.antiexfil.AntiExfilException.Code.*;

public final class AntiExfilTransportPackage {
    public static final String UR_TYPE = "x-btc-anti-exfil";
    public static final byte[] MAGIC = {'A', 'E', 'X', 'T'};
    public static final int VERSION = 1;
    public static final int MAX_PSBT_BYTES = 2_000_000;
    private static final int FLAG_PSBT = 1;
    private static final int HEADER_LENGTH = 48;

    private final AntiExfilMessage message;
    private final byte[] psbt;

    public AntiExfilTransportPackage(AntiExfilMessage message, byte[] psbt) {
        this.message = message;
        this.psbt = psbt == null ? null : psbt.clone();
    }

    public AntiExfilMessage getMessage() {
        return message;
    }

    public byte[] getPsbt() {
        return psbt == null ? null : psbt.clone();
    }

    public byte[] encode() {
        byte[] encodedMessage = AntiExfilCodec.encode(message);
        boolean requiresPsbt = message.getStage() == AntiExfilStage.HOST_COMMIT
                || message.getStage() == AntiExfilStage.HOST_REVEAL;
        if(requiresPsbt != (psbt != null)) {
            throw fail(INVALID_MESSAGE, message.getStage() + (requiresPsbt ? " requires" : " forbids") + " a PSBT");
        }
        if(psbt != null && (psbt.length < 5 || psbt.length > MAX_PSBT_BYTES
                || psbt[0] != 'p' || psbt[1] != 's' || psbt[2] != 'b' || psbt[3] != 't' || psbt[4] != (byte)0xff)) {
            throw fail(INVALID_MESSAGE, "AEXT PSBT is invalid or oversized");
        }
        byte[] digest = psbt == null ? new byte[32] : Sha256Hash.hash(psbt);
        if(psbt != null && !Arrays.equals(digest, message.getPsbtDigest())) {
            throw fail(TRANSACTION_MISMATCH, "AEXT PSBT differs from the embedded protocol digest");
        }
        int psbtLength = psbt == null ? 0 : psbt.length;
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_LENGTH + encodedMessage.length + psbtLength);
        buffer.put(MAGIC).put((byte)VERSION).put((byte)message.getNetwork().getCode())
                .put((byte)message.getStage().getCode()).put((byte)(psbt == null ? 0 : FLAG_PSBT))
                .putInt(encodedMessage.length).putInt(psbtLength).put(digest).put(encodedMessage);
        if(psbt != null) buffer.put(psbt);
        return buffer.array();
    }

    public static AntiExfilTransportPackage decode(byte[] encoded) {
        if(encoded == null || encoded.length < HEADER_LENGTH) throw fail(INVALID_MESSAGE, "Truncated AEXT package");
        try {
            ByteBuffer buffer = ByteBuffer.wrap(encoded);
            byte[] magic = new byte[4];
            buffer.get(magic);
            int version = Byte.toUnsignedInt(buffer.get());
            AntiExfilNetwork network = AntiExfilNetwork.fromCode(Byte.toUnsignedInt(buffer.get()));
            AntiExfilStage stage = AntiExfilStage.fromCode(Byte.toUnsignedInt(buffer.get()));
            int flags = Byte.toUnsignedInt(buffer.get());
            long messageLength = Integer.toUnsignedLong(buffer.getInt());
            long psbtLength = Integer.toUnsignedLong(buffer.getInt());
            byte[] digest = new byte[32];
            buffer.get(digest);
            if(!Arrays.equals(magic, MAGIC) || version != VERSION || (flags & ~FLAG_PSBT) != 0
                    || messageLength > AntiExfilCodec.MAX_MESSAGE_BYTES || psbtLength > MAX_PSBT_BYTES
                    || encoded.length != HEADER_LENGTH + messageLength + psbtLength) {
                throw fail(INVALID_MESSAGE, "Invalid AEXT header or lengths");
            }
            boolean hasPsbt = (flags & FLAG_PSBT) != 0;
            if(hasPsbt != (psbtLength > 0)) throw fail(INVALID_MESSAGE, "AEXT PSBT flag is inconsistent");
            byte[] messageBytes = new byte[(int)messageLength];
            byte[] psbt = new byte[(int)psbtLength];
            buffer.get(messageBytes).get(psbt);
            byte[] expectedDigest = hasPsbt ? Sha256Hash.hash(psbt) : new byte[32];
            if(!Arrays.equals(expectedDigest, digest)) throw fail(TRANSACTION_MISMATCH, "AEXT PSBT digest mismatch");
            AntiExfilMessage message = AntiExfilCodec.decode(messageBytes);
            if(message.getNetwork() != network) throw fail(TRANSACTION_MISMATCH, "AEXT network conflicts with AEXB");
            if(message.getStage() != stage) throw fail(WRONG_STAGE, "AEXT stage conflicts with AEXB");
            AntiExfilTransportPackage result = new AntiExfilTransportPackage(message, hasPsbt ? psbt : null);
            if(!Arrays.equals(encoded, result.encode())) throw fail(INVALID_MESSAGE, "AEXT package is not canonical");
            return result;
        } catch(AntiExfilException e) {
            throw e;
        } catch(RuntimeException e) {
            throw new AntiExfilException(INVALID_MESSAGE, "Malformed AEXT package", e);
        }
    }

    public void require(AntiExfilStage expectedStage, AntiExfilNetwork expectedNetwork) {
        if(message.getStage() != expectedStage) throw fail(WRONG_STAGE, "Expected " + expectedStage + " but received " + message.getStage());
        if(message.getNetwork() != expectedNetwork) throw fail(TRANSACTION_MISMATCH, "AEXT package is for another network");
    }

    private static AntiExfilException fail(AntiExfilException.Code code, String message) {
        return new AntiExfilException(code, message);
    }
}
