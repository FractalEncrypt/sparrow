package com.sparrowwallet.sparrow.net;

import com.google.common.eventbus.EventBus;
import com.google.common.eventbus.Subscribe;
import com.sparrowwallet.sparrow.EventManager;
import com.sparrowwallet.sparrow.event.WalletNodeHistoryChangedEvent;
import javafx.application.Platform;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Field;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SubscriptionServiceTest {
    private Field eventBusField;
    private Object previousEventBus;
    private final Recorder recorder = new Recorder();

    private static final String SCRIPT_HASH = "0000000000000000000000000000000000000000000000000000000000000001";

    private static final String STATUS_A = "aa00000000000000000000000000000000000000000000000000000000000000";
    private static final String STATUS_B = "bb00000000000000000000000000000000000000000000000000000000000000";

    private final SubscriptionService subscriptionService = new SubscriptionService();

    @BeforeAll
    public static void setUpAll() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        try { Platform.startup(started::countDown); }
        catch(IllegalStateException alreadyRunning) { started.countDown(); }
        assertTrue(started.await(15, TimeUnit.SECONDS));
        Platform.setImplicitExit(false);
        // Use the test task's isolated sparrow.home; do not put an open log in a JUnit-owned temporary directory.
    }

    @BeforeEach
    public void setUp() throws Exception {
        eventBusField = EventManager.class.getDeclaredField("SINGLETON");
        eventBusField.setAccessible(true);
        previousEventBus = eventBusField.get(null);
        EventBus bus = new EventBus();
        bus.register(recorder);
        eventBusField.set(null, bus);
        ElectrumServer.getSubscribedScriptHashes().clear();
    }

    @AfterEach
    public void tearDown() throws Exception {
        try { drainFx(); }
        finally {
            ElectrumServer.getSubscribedScriptHashes().clear();
            eventBusField.set(null, previousEventBus);
        }
    }

    @Test
    public void aRepeatedStatusIsNotAChange() {
        ElectrumServer.updateSubscribedScriptHashStatus(SCRIPT_HASH, STATUS_A);
        assertFalse(notifyStatus(SCRIPT_HASH, STATUS_A));
        assertEquals(STATUS_A, ElectrumServer.getSubscribedScriptHashStatus(SCRIPT_HASH));
    }

    /**
     * A mempool transaction that is evicted or replaced returns the script hash to the status it held before the transaction arrived, and that is a
     * change like any other: comparing against every status ever seen would leave the wallet showing a transaction the server no longer has.
     */
    @Test
    public void aStatusReturningToAnEarlierValueIsAChange() {
        ElectrumServer.updateSubscribedScriptHashStatus(SCRIPT_HASH, STATUS_A);
        assertTrue(notifyStatus(SCRIPT_HASH, STATUS_B));
        assertEquals(STATUS_B, ElectrumServer.getSubscribedScriptHashStatus(SCRIPT_HASH));

        assertTrue(notifyStatus(SCRIPT_HASH, STATUS_A));
        assertEquals(STATUS_A, ElectrumServer.getSubscribedScriptHashStatus(SCRIPT_HASH));
    }

    /**
     * A script hash with no history has a null status, which is a value the subscription carries rather than an absent subscription.
     */
    @Test
    public void anEmptyHistoryIsAStatusOfItsOwn() {
        ElectrumServer.updateSubscribedScriptHashStatus(SCRIPT_HASH, null);
        assertTrue(ElectrumServer.getSubscribedScriptHashes().containsKey(SCRIPT_HASH));
        assertFalse(notifyStatus(SCRIPT_HASH, null));

        assertTrue(notifyStatus(SCRIPT_HASH, STATUS_A));
        assertEquals(STATUS_A, ElectrumServer.getSubscribedScriptHashStatus(SCRIPT_HASH));

        //Every transaction on the script hash disappearing, as a reorg can do, empties the history again
        assertTrue(notifyStatus(SCRIPT_HASH, null));
        assertNull(ElectrumServer.getSubscribedScriptHashStatus(SCRIPT_HASH));
    }

    /**
     * The decoy and recent transaction subscriptions are not wallet script hashes and are deliberately not tracked, so their notifications are
     * passed on without being recorded - recording them would make them look like wallet nodes already subscribed to.
     */
    @Test
    public void anUntrackedScriptHashIsNotRecorded() {
        assertTrue(notifyStatus(SCRIPT_HASH, STATUS_A));
        assertFalse(ElectrumServer.getSubscribedScriptHashes().containsKey(SCRIPT_HASH));
    }

    /**
     * Observe real queued notifications, regardless of whether another test already started JavaFX.
     */
    private boolean notifyStatus(String scriptHash, String status) {
        int before = recorder.deliveries.get();
        subscriptionService.scriptHashStatusUpdated(scriptHash, status);
        drainFx();
        int delivered = recorder.deliveries.get() - before;
        assertTrue(delivered == 0 || delivered == 1);
        if(delivered == 1) {
            assertEquals(scriptHash, recorder.last.getScriptHash());
            assertEquals(status, recorder.last.getStatus());
        }
        return delivered == 1;
    }

    private static void drainFx() {
        CountDownLatch drained = new CountDownLatch(1);
        Platform.runLater(drained::countDown);
        try { assertTrue(drained.await(10, TimeUnit.SECONDS), "JavaFX notifications did not drain"); }
        catch(InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }

    public static final class Recorder {
        final AtomicInteger deliveries = new AtomicInteger();
        volatile WalletNodeHistoryChangedEvent last;
        @Subscribe public void changed(WalletNodeHistoryChangedEvent event) {
            last = event;
            deliveries.incrementAndGet();
        }
    }
}
