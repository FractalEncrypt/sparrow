package com.sparrowwallet.sparrow.transaction;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.google.protobuf.ByteString;
import com.sparrowwallet.drongo.Version;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.bitbox02.*;
import com.sparrowwallet.lark.bitbox02.generated.*;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

/** Real protobuf request/response and production msgQuery, substituted transport only. */
class BitBoxPayloadNonRetentionTest {
    @Test void debugLoggingDoesNotRetainEncodedNonceRequestOrResponse() throws Exception {
        byte[] nonce=new byte[32];Arrays.fill(nonce,(byte)0x9b);
        Hww.Request request=Hww.Request.newBuilder().setBtc(Btc.BTCRequest.newBuilder()
                .setAntikleptoSignature(Antiklepto.AntiKleptoSignatureRequest.newBuilder().setHostNonce(ByteString.copyFrom(nonce)))).build();
        Hww.Response response=Hww.Response.newBuilder().setBtc(Btc.BTCResponse.newBuilder()
                .setAntikleptoSignerCommitment(Antiklepto.AntiKleptoSignerCommitment.newBuilder().setCommitment(ByteString.copyFrom(nonce)))).build();
        Stub transport=new Stub(response.toByteArray());
        var ctor=BitBox02Device.class.getDeclaredConstructor(Version.class,BitBoxProtocol.class);ctor.setAccessible(true);
        BitBox02Device device=ctor.newInstance(new Version("9.0.0"),transport);
        Logger logger=(Logger)LoggerFactory.getLogger(BitBox02Device.class);Level previous=logger.getLevel();
        ListAppender<ILoggingEvent> captured=new ListAppender<>();captured.start();logger.addAppender(captured);logger.setLevel(Level.DEBUG);
        try {
            assertEquals(response,device.msgQuery(request,Hww.Response.ResponseCase.BTC));
            assertArrayEquals(request.toByteArray(),transport.request);
            assertTrue(captured.list.isEmpty(),"DEBUG must not print protobuf request or response payloads");
        } finally {logger.detachAppender(captured);logger.setLevel(previous);captured.stop();}
    }

    @Test void untrustedDeviceErrorCannotReflectNonceIntoDiagnostics() throws Exception {
        String secret="test-only-host-nonce-"+"9b".repeat(32);
        Hww.Response response=Hww.Response.newBuilder().setError(Hww.Error.newBuilder().setCode(103).setMessage(secret)).build();
        var ctor=BitBox02Device.class.getDeclaredConstructor(Version.class,BitBoxProtocol.class);ctor.setAccessible(true);
        var device=ctor.newInstance(new Version("9.0.0"),new Stub(response.toByteArray()));
        DeviceException error=assertThrows(DeviceException.class,()->device.msgQuery(Hww.Request.newBuilder().build(),null));
        assertFalse(error.toString().contains(secret));assertNull(error.getCause());
    }

    @Test void malformedResponseDoesNotAttachRawProtocolException() throws Exception {
        var ctor=BitBox02Device.class.getDeclaredConstructor(Version.class,BitBoxProtocol.class);ctor.setAccessible(true);
        var device=ctor.newInstance(new Version("9.0.0"),new Stub(new byte[]{(byte)0xff}));
        DeviceException error=assertThrows(DeviceException.class,()->device.msgQuery(Hww.Request.newBuilder().build(),null));
        assertNull(error.getCause());assertTrue(error.getMessage().contains("payload omitted"));
    }

    private static class Stub extends BitBoxProtocol {
        private final byte[] response;private byte[] request;
        Stub(byte[] response){super(null);this.response=response;}
        @Override public byte[] encryptedQuery(byte[] request){this.request=request.clone();return response.clone();}
        @Override public byte[] encodeNoiseRequest(byte[] message){throw new UnsupportedOperationException();}
        @Override public Response decodeNoiseResponse(byte[] message){throw new UnsupportedOperationException();}
        @Override public Response handshakeQuery(byte[] message){throw new UnsupportedOperationException();}
        @Override public void cancelOutstandingRequest(){throw new UnsupportedOperationException();}
        @Override public void unlockQuery(){throw new UnsupportedOperationException();}
    }
}
