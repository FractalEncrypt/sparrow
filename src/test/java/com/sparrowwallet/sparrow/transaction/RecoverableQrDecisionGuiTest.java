package com.sparrowwallet.sparrow.transaction;

import com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator;
import javafx.animation.*;
import javafx.scene.Node;
import javafx.scene.control.*;
import javafx.stage.*;
import javafx.util.Duration;
import org.junit.jupiter.api.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;
import static com.sparrowwallet.sparrow.transaction.ProtectedCompletionGuiTest.*;

class RecoverableQrDecisionGuiTest {
    @BeforeAll static void startup() throws Exception { toolkit(); }
    @Test void dismissalKeepsSameExchangeAndRetryIsDefault() throws Exception {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        var action = fx(() -> {
            Stage owner = new Stage(); owner.setScene(new javafx.scene.Scene(new javafx.scene.layout.Pane(), 300, 200)); owner.show();
            Timeline dismiss = new Timeline(new KeyFrame(Duration.millis(100), event -> {
                for(Window window : new ArrayList<>(Window.getWindows())) {
                    if(window == owner || window.getScene() == null) continue;
                    Node node = window.getScene().getRoot().lookup(".dialog-pane");
                    if(node instanceof DialogPane pane && "Protected signing is incomplete".equals(pane.getHeaderText())) {
                        try {
                            ButtonType retry = pane.getButtonTypes().stream().filter(b -> b.getText().equals("Retry same exchange")).findFirst().orElseThrow();
                            assertTrue(((Button)pane.lookupButton(retry)).isDefaultButton());
                            assertTrue(((Button)pane.lookupButton(retry)).isCancelButton());
                            assertTrue(pane.getContentText().contains("scan the device's final response"));
                            assertFalse(pane.getContentText().contains("permanently"));
                            window.fireEvent(new WindowEvent(window, WindowEvent.WINDOW_CLOSE_REQUEST));
                        } catch(Throwable e) { failure.set(e); pane.getButtonTypes().forEach(b -> { if(b.getText().equals("Retry same exchange")) ((Button)pane.lookupButton(b)).fire(); }); }
                    }
                }
            })); dismiss.setCycleCount(50); dismiss.play();
            try { return new AntiExfilQrExchange(owner, "Public test signer").onPostRevealInterruption(); }
            finally { dismiss.stop(); owner.close(); }
        });
        assertNull(failure.get(), String.valueOf(failure.get()));
        assertEquals(AntiExfilSigningFlow.PostRevealAction.RETRY_EXACT, action);
    }
    @Test void freshStartCopyShowsCountsAndCryptoInvestigationWithoutBlanketLegacyText() {
        var summary = new AntiExfilCoordinator.RecoverySummary("a".repeat(64), "b".repeat(64), 3, 2, 1, 1, 1, 0, false,
                Map.of("SIGNATURE_REJECTED", 1L));
        String text = AntiExfilQrExchange.freshStartText(summary);
        assertTrue(text.contains("1 unfinished exchanges")); assertTrue(text.contains("1 concern this payment"));
        assertTrue(text.contains("failed cryptographic verification")); assertTrue(text.contains("new randomness"));
        assertFalse(text.contains("Migrated")); assertFalse(text.contains("unknown payment identities"));
    }
}
