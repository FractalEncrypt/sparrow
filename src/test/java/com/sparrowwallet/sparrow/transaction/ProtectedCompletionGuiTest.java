package com.sparrowwallet.sparrow.transaction;

import com.google.common.eventbus.EventBus;
import com.google.common.eventbus.Subscribe;
import com.google.gson.*;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.antiexfil.*;
import com.sparrowwallet.drongo.policy.*;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.*;
import com.sparrowwallet.sparrow.control.SignaturesProgressBar;
import com.sparrowwallet.sparrow.event.*;
import com.sparrowwallet.sparrow.io.*;
import com.sparrowwallet.sparrow.net.ServerType;
import javafx.application.*;
import javafx.fxml.FXMLLoader;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.input.*;
import javafx.stage.Stage;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import static org.junit.jupiter.api.Assertions.*;

/** Real headless FXML/controller/map/animation events; external dialogs and services isolated. */
class ProtectedCompletionGuiTest {
    @TempDir Path temp;
    private Wallet wallet;
    private Network previousNetwork;
    private byte[] original, signed;
    private Set<VerifiedAntiExfilSignature> proofs;
    private Config config;
    private final List<Fixture> fixtures = new ArrayList<>();
    private final List<Throwable> eventErrors = new CopyOnWriteArrayList<>();
    private Events events;

    @BeforeAll static void toolkit() throws Exception {
        CountDownLatch ready = new CountDownLatch(1);
        try { Platform.startup(ready::countDown); } catch(IllegalStateException alreadyStarted) { ready.countDown(); }
        assertTrue(ready.await(10, TimeUnit.SECONDS));
        Platform.setImplicitExit(false);
        // Construct but NEVER start application services. Remove its subscribers so
        // a regressed RequestConnectEvent is recorded, never dispatched to networking.
        var constructor = AppServices.class.getDeclaredConstructor(Application.class, InteractionServices.class);
        constructor.setAccessible(true);
        Object services = constructor.newInstance(null, null);
        set(AppServices.class, null, "INSTANCE", services);
        EventManager.get().unregister(services);
    }

    @BeforeEach void setup() throws Exception {
        previousNetwork = Network.get(); Network.set(Network.TESTNET4);
        set(EventManager.class, null, "SINGLETON", new EventBus((error, context) -> eventErrors.add(error)));
        config = new Config();
        set(Config.class, null, "INSTANCE", config);
        events = new Events(); EventManager.get().register(events);
        JsonObject vector;
        try(var reader = new InputStreamReader(getClass().getResourceAsStream(
                "/com/sparrowwallet/sparrow/io/protocol-v1-mixed-provenance-vector.json"), StandardCharsets.UTF_8)) {
            vector = JsonParser.parseReader(reader).getAsJsonObject();
        }
        Keystore kern = signer(vector.getAsJsonObject("signer_a"), AntiExfilKeystorePolicy.REQUIRED);
        wallet = new Wallet("Isolated public GUI fixture");
        wallet.getKeystores().addAll(List.of(kern, signer(vector.getAsJsonObject("signer_b"), AntiExfilKeystorePolicy.OPTIONAL)));
        wallet.setPolicyType(PolicyType.MULTI_HD); wallet.setScriptType(ScriptType.P2WSH);
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.MULTI_HD, ScriptType.P2WSH, wallet.getKeystores(), 2));
        wallet.checkWallet();
        original = Utils.hexToBytes(vector.get("original_psbt_hex").getAsString());
        var create = AntiExfilCoordinator.class.getDeclaredMethod("create", Path.class, Path.class, byte[].class,
                Keystore.class, AntiExfilNetwork.class, boolean.class, SecureRandom.class);
        create.setAccessible(true);
        AntiExfilCoordinator coordinator = (AntiExfilCoordinator)create.invoke(null, temp.resolve("public.aexs"),
                temp.resolve("public.aexj"), original, kern, AntiExfilNetwork.TESTNET4, false, new SecureRandom() {
                    int call;
                    @Override public void nextBytes(byte[] bytes) { Arrays.fill(bytes, call++ == 0 ? (byte)'m' : (byte)0xa1); }
                });
        assertArrayEquals(Utils.hexToBytes(vector.get("message_1_hex").getAsString()), coordinator.getHostCommitMessage());
        assertArrayEquals(Utils.hexToBytes(vector.get("message_3_hex").getAsString()), coordinator.acceptOpenings(Utils.hexToBytes(vector.get("message_2_hex").getAsString())));
        var completion = coordinator.complete(Utils.hexToBytes(vector.get("message_4_hex").getAsString()));
        signed = completion.getSignedPsbt(); proofs = completion.getVerifiedSignatures();
        assertArrayEquals(Utils.hexToBytes(vector.get("signed_psbt_hex").getAsString()), signed);
        assertTrue(new PSBT(signed, false).isSigned());
        assertFalse(new PSBT(signed, false).isFinalized());
    }

    @AfterEach void cleanup() throws Exception {
        fx(() -> { for(Fixture f : fixtures) { f.controller.close(); f.stage.close(); } return null; });
        Network.set(previousNetwork);
        assertTrue(eventErrors.isEmpty(), eventErrors.toString());
        assertEquals(0, events.connects.get()); assertEquals(0, events.extractions.get());
    }

    private Fixture fixture(byte[] bytes, Set<VerifiedAntiExfilSignature> initialProofs) throws Exception {
        return fx(() -> {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("headers.fxml"));
            TestController controller = new TestController(); loader.setControllerFactory(type -> controller);
            Parent root = loader.load(); Stage stage = new Stage(); stage.setScene(new Scene(root, 1100, 900));
            TransactionData data = new TransactionData("public-fixture", new PSBT(bytes, false), initialProofs);
            controller.setModel(new HeadersForm(data)); data.setSigningWallet(wallet);
            stage.show(); root.applyCss(); root.layout();
            Fixture f = new Fixture(controller, data, stage, loader.getNamespace()); fixtures.add(f); return f;
        });
    }

    private void merge(Fixture f) throws Exception {
        events.animationContext = f.data.getSignatureKeystoreMap();
        fx(() -> {
            PSBT returned = new PSBT(signed, false);
            assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED, AntiExfilPolicy.evaluateSignatureProvenance(wallet, returned, proofs));
            f.data.combineVerifiedPsbt(returned, proofs);
            EventManager.get().post(new PSBTCombinedEvent(f.data.getPsbt())); return null;
        });
    }

    @Test void actualAnimationCannotFinalizeProtectedReturnAndProductionSaveIsExact() throws Exception {
        Fixture f = fixture(original, Set.of()); merge(f);
        assertTrue(events.animation.await(6, TimeUnit.SECONDS), "Real Timeline completion callback was not delivered");
        fx(() -> {
            assertFalse(f.data.getPsbt().isFinalized()); assertArrayEquals(signed, f.data.getPsbt().getForExport().serialize());
            assertTrue(f.node("protectedCompletionBox").isVisible()); assertTrue(f.node("protectedCompletionBox").isManaged());
            assertFalse(f.node("signButtonBox").isVisible()); assertFalse(f.node("broadcastButtonBox").isVisible());
            assertFalse(((Button)f.node("finalizeProtectedButton")).isDefaultButton());
            f.controller.exportFile = temp.resolve("actual-gui-export.psbt").toFile();
            ((ToggleButton)f.node("protectedSavePsbtButton")).fire();
            assertArrayEquals(signed, Files.readAllBytes(f.controller.exportFile.toPath()));
            assertEquals(0, events.finalizations.get()); return null;
        });
    }

    @Test void duplicateCallbacksAndEqualPsbtFromAnotherTabDoNotAdvanceOrLeakContext() throws Exception {
        Fixture first = fixture(original, Set.of()); merge(first);
        Fixture other = fixture(original, Set.of());
        fx(() -> {
            byte[] before = other.data.getPsbt().serialize();
            EventManager.get().post(new KeystoreSignedEvent(wallet.getKeystores().get(0), first.data.getSignatureKeystoreMap()));
            EventManager.get().post(new PSBTCombinedEvent(new PSBT(signed, false)));
            EventManager.get().post(new PSBTFinalizedEvent(new PSBT(signed, false)));
            EventManager.get().post(new PSBTFinalizedEvent(first.data.getPsbt()));
            assertArrayEquals(before, other.data.getPsbt().serialize());
            assertFalse(other.data.hasVerifiedProtectedContext());
            assertFalse(first.data.getPsbt().isFinalized()); return null;
        });
    }

    @Test void replacedProofsCannotTurnOptionalProtectedReturnIntoOrdinaryCompletion() throws Exception {
        wallet.getKeystores().forEach(k -> k.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL));
        Fixture f = fixture(signed, proofs);
        fx(() -> {
            f.data.replaceVerifiedAntiExfilSignatures(Set.of()); f.controller.refreshProtectedCompletion();
            EventManager.get().post(new KeystoreSignedEvent(wallet.getKeystores().get(0), f.data.getSignatureKeystoreMap()));
            assertTrue(f.data.hasProtectedSigningContext()); assertFalse(f.data.getPsbt().isFinalized());
            assertEquals(AntiExfilPolicy.ProvenanceStatus.INVALID_PROVENANCE, AntiExfilPolicy.evaluatePsbtEgress(f.data));
            assertFalse(f.node("protectedCompletionBox").isVisible()); return null;
        });
    }

    @Test void proofReloadAndWalletChangesKeepTheStop() throws Exception {
        Fixture f = fixture(signed, proofs);
        fx(() -> {
            f.data.setSigningWallet(null);
            assertFalse(f.node("protectedCompletionBox").isVisible());
            assertEquals(AntiExfilPolicy.ProvenanceStatus.POLICY_CONTEXT_UNAVAILABLE, AntiExfilPolicy.evaluatePsbtEgress(f.data));
            f.data.replaceVerifiedAntiExfilSignatures(proofs); f.data.setSigningWallet(wallet);
            assertTrue(f.node("protectedCompletionBox").isVisible()); assertFalse(f.data.getPsbt().isFinalized()); return null;
        });
    }

    @Test void noWalletCombinedBranchCannotFinalizeProtectedContext() throws Exception {
        Fixture f = fixture(signed, proofs);
        fx(() -> {
            f.data.setSigningWallet(null);
            EventManager.get().post(new PSBTCombinedEvent(f.data.getPsbt()));
            assertTrue(f.data.hasProtectedSigningContext()); assertFalse(f.data.getPsbt().isFinalized()); return null;
        });
    }

    @Test void partialProtectedResultDoesNotOfferFinalize() throws Exception {
        Fixture f = fixture(signed, proofs);
        fx(() -> {
            var signatures = f.data.getPsbt().getPsbtInputs().get(0).getPartialSignatures();
            var optional = wallet.getKeystores().get(1);
            var signedKeys = wallet.getSignedKeystores(f.data.getPsbt()).values().iterator().next();
            signatures.entrySet().removeIf(entry -> optional.equals(signedKeys.get(entry.getValue())));
            assertFalse(f.data.getPsbt().isSigned()); f.controller.refreshProtectedCompletion();
            assertFalse(f.node("protectedCompletionBox").isVisible()); assertTrue(f.node("signButtonBox").isVisible());
            assertFalse(f.data.getPsbt().isFinalized()); return null;
        });
        merge(f);
        fx(() -> { assertTrue(f.node("protectedCompletionBox").isVisible()); assertFalse(f.data.getPsbt().isFinalized()); return null; });
    }

    @Test void directFinalActionsAreGuardedBeforeExternalEffects() throws Exception {
        Fixture f = fixture(signed, proofs);
        fx(() -> {
            assertFalse(f.controller.extractTransaction()); f.controller.showTransaction(null);
            f.controller.saveFinalTransaction(null); f.controller.broadcastTransaction(null); f.controller.getPayjoinTransaction(null);
            assertEquals(5, f.controller.errors.size()); assertFalse(f.data.getPsbt().isFinalized()); return null;
        });
    }

    @Test void cancelAndChangedApprovalDoNotFinalize() throws Exception {
        Fixture f = fixture(signed, proofs);
        fx(() -> {
            f.controller.confirm = () -> false; f.controller.finalizeProtectedTransaction(null);
            assertFalse(f.data.getPsbt().isFinalized());
            f.controller.confirm = () -> { f.data.replaceVerifiedAntiExfilSignatures(Set.of()); return true; };
            f.controller.finalizeProtectedTransaction(null);
            assertFalse(f.data.getPsbt().isFinalized()); assertTrue(f.controller.errors.getLast().startsWith("Transaction changed.")); return null;
        });
    }

    @Test void changingPsbtOrWalletPolicyInvalidatesApproval() throws Exception {
        Fixture f = fixture(signed, proofs);
        fx(() -> {
            f.controller.confirm = () -> { wallet.getKeystores().get(0).setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL); return true; };
            f.controller.finalizeProtectedTransaction(null); assertFalse(f.data.getPsbt().isFinalized());
            assertTrue(f.controller.errors.getLast().startsWith("Transaction changed.")); return null;
        });
    }

    @Test void missingProofCannotBeApproved() throws Exception {
        Fixture f = fixture(signed, Set.of());
        fx(() -> {
            f.controller.confirm = () -> { fail("No confirmation may authorize missing proof"); return true; };
            f.controller.finalizeProtectedTransaction(null); assertFalse(f.data.getPsbt().isFinalized()); return null;
        });
    }

    @Test void confirmationDefaultsAndEnterAreSafe() throws Exception {
        fx(() -> {
            Alert dialog = HeadersController.protectedFinalizationDialog();
            ButtonType finalize = dialog.getButtonTypes().stream().filter(b -> b.getText().equals("Finalize")).findFirst().orElseThrow();
            assertFalse(((Button)dialog.getDialogPane().lookupButton(finalize)).isDefaultButton());
            assertTrue(((Button)dialog.getDialogPane().lookupButton(ButtonType.CANCEL)).isDefaultButton());
            dialog.getDialogPane().fireEvent(new KeyEvent(KeyEvent.KEY_PRESSED, "\r", "\r", KeyCode.ENTER, false, false, false, false));
            assertEquals(ButtonType.CANCEL, dialog.getResult()); dialog.close(); return null;
        });
    }

    @Test void closingTheRealConfirmationCancels() throws Exception {
        fx(() -> {
            Alert dialog = HeadersController.protectedFinalizationDialog();
            Platform.runLater(dialog::close);
            assertEquals(ButtonType.CANCEL, dialog.showAndWait().orElse(ButtonType.CANCEL)); return null;
        });
    }

    @Test void finalizeButtonEnterDoesNotAskForApproval() throws Exception {
        Fixture f = fixture(signed, proofs);
        fx(() -> {
            f.controller.confirm = () -> { fail("Enter must not request approval"); return true; };
            f.node("finalizeProtectedButton").fireEvent(new KeyEvent(KeyEvent.KEY_PRESSED, "\r", "\r", KeyCode.ENTER, false, false, false, false));
            assertFalse(f.data.getPsbt().isFinalized()); return null;
        });
    }

    @Test void changedTransactionInvalidatesApprovalAndProof() throws Exception {
        Fixture f = fixture(signed, proofs);
        fx(() -> {
            f.controller.confirm = () -> {
                var tx = f.data.getPsbt().getTransaction();
                tx.setLocktime(tx.getLocktime() + 1); return true;
            };
            f.controller.finalizeProtectedTransaction(null);
            assertFalse(f.data.getPsbt().isFinalized());
            assertTrue(f.controller.errors.getLast().startsWith("Transaction changed."));
            f.controller.refreshProtectedCompletion();
            assertFalse(f.node("protectedCompletionBox").isVisible()); return null;
        });
    }

    @Test void walletCloseAndReopenEventsKeepCurrentPolicyAndHold() throws Exception {
        Fixture f = fixture(signed, proofs);
        fx(() -> {
            EventManager.get().post(new OpenWalletsEvent(f.stage, List.of()));
            assertNull(f.data.getSigningWallet()); assertFalse(f.node("protectedCompletionBox").isVisible());
            // A data-only event supplies the public wallet without starting wallet services.
            OpenWalletsEvent reopen = new OpenWalletsEvent(f.stage, List.of()) {
                @Override public Map<Wallet,Storage> getWalletsMap() {
                    Map<Wallet,Storage> result = new LinkedHashMap<>(); result.put(wallet, null); return result;
                }
            };
            EventManager.get().post(reopen);
            assertSame(wallet, f.data.getSigningWallet());
            assertTrue(f.node("protectedCompletionBox").isVisible()); assertFalse(f.data.getPsbt().isFinalized());
            EventManager.get().post(new FinalizeTransactionEvent(f.data.getPsbt(), wallet));
            assertTrue(f.node("protectedCompletionBox").isVisible()); assertFalse(f.node("broadcastButtonBox").isVisible()); return null;
        });
    }

    @Test void sharedKeystoreCallbackCannotFinalizeAnotherSignedTab() throws Exception {
        Fixture first = fixture(signed, proofs);
        wallet.getKeystores().forEach(k -> k.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL));
        Fixture other = fixture(signed, Set.of());
        fx(() -> {
            assertFalse(other.data.hasProtectedSigningContext());
            EventManager.get().post(new KeystoreSignedEvent(wallet.getKeystores().get(0), first.data.getSignatureKeystoreMap()));
            assertFalse(other.data.getPsbt().isFinalized());
            assertFalse(first.data.getPsbt().isFinalized()); return null;
        });
    }

    @Test void explicitPublicFixtureFinalizationNeverConnectsForAnyPreference() throws Exception {
        for(Boolean preference : Arrays.asList(null, false, true)) {
            Fixture f = fixture(signed, proofs);
            fx(() -> {
                set(Config.class, config, "connectToBroadcast", preference);
                set(Config.class, config, "serverType", ServerType.PUBLIC_ELECTRUM_SERVER);
                set(Config.class, config, "publicElectrumServer", new Server("ssl://127.0.0.1:1"));
                assertTrue(config.hasServer());
                f.controller.confirm = () -> true; f.controller.finalizeProtectedTransaction(null);
                assertTrue(f.data.getPsbt().isFinalized()); assertFalse(f.node("protectedCompletionBox").isVisible());
                assertTrue(f.node("broadcastButtonBox").isVisible());
                int once = events.finalizations.get(); f.controller.finalizeProtectedTransaction(null);
                assertEquals(once, events.finalizations.get()); return null;
            });
        }
    }

    @Test void alreadyFinalizedProtectedImportDoesNotAutoConnect() throws Exception {
        PSBT finalized = new PSBT(signed, false); wallet.finalise(finalized);
        Fixture f = fixture(finalized.serialize(), proofs);
        fx(() -> {
            set(Config.class, config, "serverType", ServerType.PUBLIC_ELECTRUM_SERVER);
            set(Config.class, config, "publicElectrumServer", new Server("ssl://127.0.0.1:1"));
            set(Config.class, config, "connectToBroadcast", true);
            EventManager.get().post(new PSBTFinalizedEvent(f.data.getPsbt()));
            assertFalse(f.node("protectedCompletionBox").isVisible()); return null;
        });
    }

    @Test void ordinaryControlStillFinalizesThroughActualAnimation() throws Exception {
        wallet.getKeystores().forEach(k -> k.setAntiExfilPolicy(AntiExfilKeystorePolicy.OPTIONAL));
        Fixture f = fixture(original, Set.of());
        events.animationContext = f.data.getSignatureKeystoreMap();
        fx(() -> {
            f.data.combineVerifiedPsbt(new PSBT(signed, false), Set.of());
            EventManager.get().post(new PSBTCombinedEvent(f.data.getPsbt())); return null;
        });
        assertTrue(events.animation.await(6, TimeUnit.SECONDS));
        fx(() -> { assertTrue(f.data.getPsbt().isFinalized()); assertFalse(f.data.hasProtectedSigningContext()); return null; });
    }

    @Test void completionControlsHaveFiniteReadableNonOverlappingBounds() throws Exception {
        Fixture f = fixture(original, Set.of()); merge(f);
        assertTrue(events.animation.await(6, TimeUnit.SECONDS));
        fx(() -> {
            f.stage.getScene().getRoot().applyCss(); f.stage.getScene().getRoot().layout();
            captureLayout(f, "baseline-or-corrected-1100x900");
            assertReadableControls(f);
            return null;
        });
    }

    private void assertReadableControls(Fixture f) {
        ButtonBase save = (ButtonBase)f.node("protectedSavePsbtButton");
        ButtonBase finalize = (ButtonBase)f.node("finalizeProtectedButton");
        for(ButtonBase button : List.of(save, finalize)) {
            var bounds = button.localToScene(button.getBoundsInLocal());
            assertTrue(Double.isFinite(bounds.getMinX()) && Double.isFinite(bounds.getMaxX())
                    && Double.isFinite(bounds.getMinY()) && Double.isFinite(bounds.getMaxY()),
                    "LAYOUT: non-finite control bounds: " + button.getId() + " " + bounds);
            assertTrue(bounds.getWidth() > 80 && bounds.getHeight() >= 24,
                    "LAYOUT: collapsed control: " + button.getId() + " " + bounds);
            assertTrue(button.isVisible() && button.isManaged() && !button.isDisabled());
            var text = (javafx.scene.text.Text)button.lookup(".text");
            assertNotNull(text);
            assertEquals(button.getText(), text.getText(), "LAYOUT: clipped/ellipsized label: " + button.getId());
            var textBounds = text.localToScene(text.getBoundsInLocal());
            assertTrue(bounds.contains(textBounds), "LAYOUT: text outside control: " + button.getId());
            assertTrue(bounds.getMinX() >= 0 && bounds.getMaxX() <= f.stage.getScene().getWidth()
                    && bounds.getMinY() >= 0 && bounds.getMaxY() <= f.stage.getScene().getHeight(),
                    "LAYOUT: control outside viewport: " + button.getId());
        }
        var a = save.localToScene(save.getBoundsInLocal());
        var b = finalize.localToScene(finalize.getBoundsInLocal());
        assertTrue(a.getMaxX() <= b.getMinX(), "LAYOUT: controls overlap or order is reversed");
        assertEquals("Save Transaction", save.getText());
        assertEquals("Finalize Transaction", finalize.getText());
        assertFalse(((Button)finalize).isDefaultButton());
    }

    private void captureLayout(Fixture f, String name) throws Exception {
        String configuredOutput = System.getProperty("m8.layout.output");
        Path output = configuredOutput == null || configuredOutput.isBlank() ? temp.resolve("layout") : Path.of(configuredOutput);
        Files.createDirectories(output);
        JsonObject result = new JsonObject();
        result.addProperty("sceneWidth", f.stage.getScene().getWidth());
        result.addProperty("sceneHeight", f.stage.getScene().getHeight());
        result.addProperty("fixture", "Existing public deterministic TESTNET4 software fixture; not physical M8 evidence");
        result.addProperty("finalized", f.data.getPsbt().isFinalized());
        for(String id : List.of("protectedSavePsbtButton", "finalizeProtectedButton")) {
            ButtonBase button = (ButtonBase)f.node(id);
            var bounds = button.localToScene(button.getBoundsInLocal());
            JsonObject node = new JsonObject();
            node.addProperty("label", button.getText());
            node.addProperty("x", Double.toString(bounds.getMinX())); node.addProperty("y", Double.toString(bounds.getMinY()));
            node.addProperty("width", Double.toString(bounds.getWidth())); node.addProperty("height", Double.toString(bounds.getHeight()));
            node.addProperty("visible", button.isVisible()); node.addProperty("managed", button.isManaged());
            var text = (javafx.scene.text.Text)button.lookup(".text");
            node.addProperty("renderedText", text == null ? "NO_TEXT_NODE" : text.getText()); result.add(id, node);
        }
        Files.writeString(output.resolve(name + ".json"), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n");
        int width=(int)f.stage.getScene().getWidth(), height=(int)f.stage.getScene().getHeight();
        SnapshotParameters parameters = new SnapshotParameters();
        parameters.setViewport(new javafx.geometry.Rectangle2D(0, 0, width, height));
        var image = f.stage.getScene().getRoot().snapshot(parameters, new javafx.scene.image.WritableImage(width,height));
        int[] pixels = new int[width*height];
        image.getPixelReader().getPixels(0,0,width,height,javafx.scene.image.PixelFormat.getIntArgbInstance(),pixels,0,width);
        var buffered = new java.awt.image.BufferedImage(width,height,java.awt.image.BufferedImage.TYPE_INT_ARGB);
        buffered.setRGB(0,0,width,height,pixels,0,width);
        assertTrue(javax.imageio.ImageIO.write(buffered,"png",output.resolve(name+".png").toFile()));
        System.out.println("LAYOUT_EVIDENCE " + name + " " + result);
    }


    private Fixture transactionLayoutFixture(double width, double height) throws Exception {
        Fixture f = fixture(original, Set.of());
        fx(() -> {
            Parent headers = f.stage.getScene().getRoot();
            f.stage.getScene().setRoot(new Group());
            // Actual transaction containers/CSS, without TransactionController services.
            FXMLLoader transactionLoader = new FXMLLoader(getClass().getResource("transaction.fxml"));
            transactionLoader.setControllerFactory(type -> new Object());
            Parent transaction = transactionLoader.load();
            ((javafx.scene.layout.StackPane)transactionLoader.getNamespace().get("txpane")).getChildren().add(headers);
            var tree = (TreeView<String>)transactionLoader.getNamespace().get("txtree");
            tree.setRoot(new TreeItem<>("PUBLIC SOFTWARE FIXTURE"));
            var detail = (org.controlsfx.control.MasterDetailPane)transactionLoader.getNamespace().get("transactionMasterDetail");
            detail.setShowDetailNode(true); detail.setDividerPosition(0.85);
            ((javafx.scene.layout.Region)transactionLoader.getNamespace().get("txhex")).setMinHeight(0);
            var top = new javafx.scene.layout.VBox(new MenuBar(new Menu("File"),new Menu("View")),
                    new Label("Public software fixture - offline headless layout regression"));
            top.setMinHeight(60); top.setPrefHeight(60);
            Label footer = new Label("TEST FIXTURE - no physical device or network service");
            footer.setMinHeight(26); footer.setPrefHeight(26);
            var shell = new javafx.scene.layout.BorderPane(transaction,top,null,footer,null);
            Scene scene = new Scene(shell,width,height);
            scene.getStylesheets().add(AppServices.class.getResource("app.css").toExternalForm());
            f.stage.setScene(scene); f.stage.sizeToScene(); f.stage.show();
            shell.applyCss(); shell.layout(); return null;
        });
        merge(f); assertTrue(events.animation.await(6,TimeUnit.SECONDS));
        fx(() -> { f.stage.getScene().getRoot().applyCss(); f.stage.getScene().getRoot().layout(); return null; });
        return f;
    }

    @Test void completionControlsRemainReadableInTransactionContainerAcrossWindowSizes() throws Exception {
        for(int[] size : List.of(new int[]{1086,809},new int[]{650,708},new int[]{1100,900},new int[]{1440,1000})) {
            events.animation = new CountDownLatch(1);
            Fixture f = transactionLayoutFixture(size[0],size[1]);
            fx(() -> {
                captureLayout(f,"transaction-container-"+size[0]+"x"+size[1]);
                assertReadableControls(f);
                assertArrayEquals(signed,f.data.getPsbt().getForExport().serialize());
                assertFalse(f.data.getPsbt().isFinalized());
                assertEquals(0,events.finalizations.get());
                f.stage.hide(); return null;
            });
        }
    }

    private void clickHeadlessMouse(Node node) {
        var bounds = node.localToScreen(node.getBoundsInLocal());
        var robot = new javafx.scene.robot.Robot();
        robot.mouseMove(bounds.getCenterX(),bounds.getCenterY());
        robot.mousePress(MouseButton.PRIMARY); robot.mouseRelease(MouseButton.PRIMARY);
    }

    @Test void saveMouseTargetAndCancelConfirmationKeepExactUnfinalizedExport() throws Exception {
        Fixture f = transactionLayoutFixture(1086,809);
        fx(() -> {
            assertReadableControls(f); f.stage.requestFocus();
            f.controller.exportFile=temp.resolve("mouse-target-export.psbt").toFile();
            clickHeadlessMouse(f.node("protectedSavePsbtButton")); return null;
        });
        assertTrue(f.controller.saveChosen.await(5,TimeUnit.SECONDS),"Mouse hit must reach Save handler");
        fx(() -> {
            assertArrayEquals(signed,Files.readAllBytes(f.controller.exportFile.toPath()));
            assertEquals(1,f.controller.saveSelections);
            f.controller.confirm=() -> { f.controller.cancelled.countDown(); return false; };
            clickHeadlessMouse(f.node("finalizeProtectedButton")); return null;
        });
        assertTrue(f.controller.cancelled.await(5,TimeUnit.SECONDS),"Mouse hit must reach only Finalize confirmation");
        fx(() -> {
            assertArrayEquals(signed,f.data.getPsbt().getForExport().serialize());
            assertFalse(f.data.getPsbt().isFinalized()); assertEquals(0,events.finalizations.get());
            assertEquals(1,f.controller.saveSelections);
            captureLayout(f,"mouse-save-and-cancel"); return null;
        });
    }

    @Test void fileMenuBinarySerializationAndProvenanceMatchCompletionExport() throws Exception {
        Fixture f = fixture(signed,proofs);
        fx(() -> {
            assertEquals(AntiExfilPolicy.ProvenanceStatus.PERMITTED,AntiExfilPolicy.evaluatePsbtEgress(f.data));
            f.controller.exportFile=temp.resolve("completion-export.psbt").toFile();
            ((ToggleButton)f.node("protectedSavePsbtButton")).fire();
            // File-menu handler uses this exact serialization after the same current-policy guard.
            // Its native chooser is NOT opened by this test; source bindings are reviewed separately.
            byte[] menuPayload=f.data.getPsbt().getForExport().serialize(true,true);
            assertArrayEquals(menuPayload,Files.readAllBytes(f.controller.exportFile.toPath()));
            assertArrayEquals(signed,menuPayload); assertFalse(new PSBT(menuPayload,false).isFinalized());
            f.data.replaceVerifiedAntiExfilSignatures(Set.of());
            assertEquals(AntiExfilPolicy.ProvenanceStatus.INVALID_PROVENANCE,AntiExfilPolicy.evaluatePsbtEgress(f.data));
            return null;
        });
    }


    static class TestController extends HeadersController {
        File exportFile; java.util.function.BooleanSupplier confirm = () -> false;
        final List<String> errors = new ArrayList<>();
        final CountDownLatch saveChosen = new CountDownLatch(1), cancelled = new CountDownLatch(1);
        int saveSelections;
        @Override File choosePsbtExportFile() { saveSelections++; saveChosen.countDown(); return exportFile; }
        @Override boolean confirmProtectedFinalization() { return confirm.getAsBoolean(); }
        @Override void protectedCompletionError(String message) { errors.add(message); }
    }
    record Fixture(TestController controller, TransactionData data, Stage stage, Map<String,Object> namespace) {
        Node node(String name) { return (Node)namespace.get(name); }
    }
    public static class Events {
        volatile CountDownLatch animation = new CountDownLatch(1);
        volatile Object animationContext;
        final AtomicInteger finalizations = new AtomicInteger(), connects = new AtomicInteger(), extractions = new AtomicInteger();
        @Subscribe public void animated(KeystoreSignedEvent e) {
            if(e.getTransactionContext() == animationContext && animationContext != null) animation.countDown();
        }
        @Subscribe public void finalized(PSBTFinalizedEvent e) { finalizations.incrementAndGet(); }
        @Subscribe public void connected(RequestConnectEvent e) { connects.incrementAndGet(); }
        @Subscribe public void extracted(TransactionExtractedEvent e) { extractions.incrementAndGet(); }
    }
    static void set(Class<?> type, Object target, String name, Object value) throws Exception {
        Field field = type.getDeclaredField(name); field.setAccessible(true); field.set(target,value);
    }
    static <T> T fx(Callable<T> callable) throws Exception {
        FutureTask<T> task = new FutureTask<>(callable); Platform.runLater(task); return task.get(15, TimeUnit.SECONDS);
    }
    private static Keystore signer(JsonObject data, AntiExfilKeystorePolicy policy) throws Exception {
        Keystore key = Keystore.fromSeed(new DeterministicSeed(data.get("mnemonic").getAsString(), "", 0,
                DeterministicSeed.Type.BIP39), PolicyType.MULTI_HD, KeyDerivation.parsePath(data.get("account_derivation").getAsString()));
        key.setSeed(null); key.setMasterPrivateExtendedKey(null); key.setSource(KeystoreSource.HW_AIRGAPPED);
        key.setLabel(key.getKeyDerivation().getMasterFingerprint());
        key.setWalletModel(WalletModel.KERN); key.setAntiExfilProfile(AntiExfilProfile.AEXT_V1); key.setAntiExfilPolicy(policy); return key;
    }
}
