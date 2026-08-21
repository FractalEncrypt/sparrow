package com.sparrowwallet.sparrow.io;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCodec;
import com.sparrowwallet.drongo.antiexfil.AntiExfilCrypto;
import com.sparrowwallet.drongo.antiexfil.AntiExfilException;
import com.sparrowwallet.drongo.antiexfil.AntiExfilMessage;
import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.antiexfil.AntiExfilSlot;
import com.sparrowwallet.drongo.antiexfil.AntiExfilStage;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.hummingbird.UR;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AntiExfilTransportPackageTest {
    private final byte[] psbt = new byte[]{'p', 's', 'b', 't', (byte)0xff, 0};

    @Test
    void matchesPythonGoldenAextPackagesByteForByte() throws Exception {
        JsonObject vector;
        try(InputStreamReader reader = new InputStreamReader(
                getClass().getResourceAsStream("protocol-v1-semantic-psbt-vector.json"), StandardCharsets.UTF_8)) {
            vector = JsonParser.parseReader(reader).getAsJsonObject();
        }
        byte[] goldenPsbt = Utils.hexToBytes(vector.get("psbt_hex").getAsString());
        JsonArray packages = vector.getAsJsonArray("aext_packages");
        for(int index = 0; index < packages.size(); index++) {
            int stageNumber = index + 1;
            AntiExfilStage stage = AntiExfilStage.fromCode(stageNumber);
            byte[] messageBytes = Utils.hexToBytes(vector.get("message_" + stageNumber + "_hex").getAsString());
            AntiExfilTransportPackage transport = new AntiExfilTransportPackage(AntiExfilCodec.decode(messageBytes),
                    stage == AntiExfilStage.HOST_COMMIT || stage == AntiExfilStage.HOST_REVEAL ? goldenPsbt : null);
            JsonObject expected = packages.get(index).getAsJsonObject();
            assertEquals(expected.get("package_hex").getAsString(), Utils.bytesToHex(transport.encode()));
            assertEquals(expected.get("package_sha256").getAsString(), Utils.bytesToHex(Sha256Hash.hash(transport.encode())));
            assertArrayEquals(transport.encode(), AntiExfilQrCodec.fromUr(AntiExfilQrCodec.toUr(transport),
                    stage, AntiExfilNetwork.TESTNET4).encode());
        }
    }

    @Test
    void roundTripsEveryStageAndCustomUrExactly() {
        for(AntiExfilStage stage : AntiExfilStage.values()) {
            AntiExfilTransportPackage transport = transport(stage);
            byte[] encoded = transport.encode();
            AntiExfilTransportPackage decoded = AntiExfilTransportPackage.decode(encoded);
            assertArrayEquals(encoded, decoded.encode());
            assertEquals(stage, decoded.getMessage().getStage());
            assertEquals(stage == AntiExfilStage.HOST_COMMIT || stage == AntiExfilStage.HOST_REVEAL,
                    decoded.getPsbt() != null);

            UR ur = AntiExfilQrCodec.toUr(decoded);
            assertEquals(AntiExfilTransportPackage.UR_TYPE, ur.getType());
            assertArrayEquals(encoded, AntiExfilQrCodec.fromUr(ur, stage, AntiExfilNetwork.TESTNET4).encode());
        }
    }

    @Test
    void rejectsHeaderDigestStageNetworkAndPresenceMutations() throws Exception {
        byte[] valid = transport(AntiExfilStage.HOST_COMMIT).encode();
        for(int offset : new int[]{0, 4, 5, 6, 7, 15, 16}) {
            byte[] changed = valid.clone();
            changed[offset] ^= 1;
            assertThrows(AntiExfilException.class, () -> AntiExfilTransportPackage.decode(changed));
        }
        assertThrows(AntiExfilException.class, () -> new AntiExfilTransportPackage(
                message(AntiExfilStage.HOST_COMMIT), null).encode());
        assertThrows(AntiExfilException.class, () -> new AntiExfilTransportPackage(
                message(AntiExfilStage.SIGNER_OPENINGS), psbt).encode());
        assertThrows(AntiExfilException.class, () -> AntiExfilQrCodec.fromUr(
                UR.fromBytes("bytes", valid), AntiExfilStage.HOST_COMMIT, AntiExfilNetwork.TESTNET4));
        assertThrows(AntiExfilException.class, () -> AntiExfilQrCodec.fromUr(
                AntiExfilQrCodec.toUr(transport(AntiExfilStage.HOST_COMMIT)),
                AntiExfilStage.HOST_REVEAL, AntiExfilNetwork.TESTNET4));
        byte[] packageBytes = transport(AntiExfilStage.HOST_COMMIT).encode();
        byte[] canonicalCbor = UR.fromBytes(AntiExfilTransportPackage.UR_TYPE, packageBytes).getCborBytes();
        assertEquals(0x58, Byte.toUnsignedInt(canonicalCbor[0]));
        byte[] nonCanonicalCbor = new byte[canonicalCbor.length + 1];
        nonCanonicalCbor[0] = 0x59;
        nonCanonicalCbor[1] = 0;
        System.arraycopy(canonicalCbor, 1, nonCanonicalCbor, 2, canonicalCbor.length - 1);
        assertThrows(AntiExfilException.class, () -> AntiExfilQrCodec.fromUr(
                new UR(AntiExfilTransportPackage.UR_TYPE, nonCanonicalCbor),
                AntiExfilStage.HOST_COMMIT, AntiExfilNetwork.TESTNET4));
    }

    @Test
    void rejectsSharedHostNegativeVectors() throws Exception {
        JsonObject vector;
        try(InputStreamReader reader = new InputStreamReader(
                getClass().getResourceAsStream("protocol-v1-negative-vectors.json"), StandardCharsets.UTF_8)) {
            vector = JsonParser.parseReader(reader).getAsJsonObject();
        }
        JsonObject testCase = vector.getAsJsonArray("cases").get(0).getAsJsonObject();
        AntiExfilException exception = assertThrows(AntiExfilException.class,
                () -> AntiExfilTransportPackage.decode(Utils.hexToBytes(testCase.get("package_hex").getAsString())));
        assertEquals(AntiExfilException.Code.valueOf(testCase.get("expected_error").getAsString()), exception.getCode());
    }

    private AntiExfilTransportPackage transport(AntiExfilStage stage) {
        return new AntiExfilTransportPackage(message(stage),
                stage == AntiExfilStage.HOST_COMMIT || stage == AntiExfilStage.HOST_REVEAL ? psbt : null);
    }

    private AntiExfilMessage message(AntiExfilStage stage) {
        byte[] rho = repeat((byte)0x11);
        byte[] opening = ECKey.fromPrivate(BigInteger.valueOf(19)).getPubKey();
        byte[] signature = new byte[64];
        signature[31] = 1;
        signature[63] = 1;
        AntiExfilSlot slot = new AntiExfilSlot(0, AntiExfilCodec.SIGHASH_ALL,
                ECKey.fromPrivate(BigInteger.valueOf(17)).getPubKey(), repeat((byte)0x22),
                AntiExfilCrypto.hostCommit(rho),
                stage.getCode() >= AntiExfilStage.SIGNER_OPENINGS.getCode() ? opening : null,
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
}
