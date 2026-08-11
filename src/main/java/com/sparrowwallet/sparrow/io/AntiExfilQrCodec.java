package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.antiexfil.AntiExfilException;
import com.sparrowwallet.drongo.antiexfil.AntiExfilNetwork;
import com.sparrowwallet.drongo.antiexfil.AntiExfilStage;
import com.sparrowwallet.hummingbird.UR;

import java.util.Arrays;

public final class AntiExfilQrCodec {
    private AntiExfilQrCodec() {
    }

    public static UR toUr(AntiExfilTransportPackage transportPackage) {
        try {
            return UR.fromBytes(AntiExfilTransportPackage.UR_TYPE, transportPackage.encode());
        } catch(UR.URException e) {
            throw new AntiExfilException(AntiExfilException.Code.INVALID_MESSAGE,
                    "Cannot encode anti-exfil UR", e);
        }
    }

    public static AntiExfilTransportPackage fromUr(UR ur, AntiExfilStage expectedStage,
                                                    AntiExfilNetwork expectedNetwork) {
        if(ur == null || !AntiExfilTransportPackage.UR_TYPE.equals(ur.getType())) {
            throw new AntiExfilException(AntiExfilException.Code.INVALID_MESSAGE,
                    "Expected ur:" + AntiExfilTransportPackage.UR_TYPE);
        }
        try {
            byte[] payload = ur.toBytes();
            UR canonical = UR.fromBytes(AntiExfilTransportPackage.UR_TYPE, payload);
            if(!Arrays.equals(ur.getCborBytes(), canonical.getCborBytes())) {
                throw new AntiExfilException(AntiExfilException.Code.INVALID_MESSAGE,
                        "Anti-exfil UR uses non-canonical CBOR");
            }
            AntiExfilTransportPackage transportPackage = AntiExfilTransportPackage.decode(payload);
            transportPackage.require(expectedStage, expectedNetwork);
            return transportPackage;
        } catch(AntiExfilException e) {
            throw e;
        } catch(UR.URException e) {
            throw new AntiExfilException(AntiExfilException.Code.INVALID_MESSAGE,
                    "Anti-exfil UR is not a canonical CBOR byte string", e);
        }
    }
}
