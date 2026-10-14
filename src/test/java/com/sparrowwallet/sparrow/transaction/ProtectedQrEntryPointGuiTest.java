package com.sparrowwallet.sparrow.transaction;

import com.google.common.eventbus.EventBus;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.policy.*;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.*;
import com.sparrowwallet.sparrow.event.FinalizeTransactionEvent;
import com.sparrowwallet.sparrow.io.Config;
import com.sparrowwallet.sparrow.io.Storage;
import com.sparrowwallet.sparrow.SparrowWallet;
import javafx.animation.*;
import javafx.fxml.FXMLLoader;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.stage.Stage;
import javafx.stage.Window;
import javafx.util.Duration;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import static org.junit.jupiter.api.Assertions.*;
import static com.sparrowwallet.sparrow.transaction.ProtectedCompletionGuiTest.*;

/** Reproduces the public offline guide with production FXML/controller and exact public PSBT. */
class ProtectedQrEntryPointGuiTest {
    @TempDir java.nio.file.Path temp;
    private Network previous;
    private final List<Throwable> errors = new CopyOnWriteArrayList<>();
    private final List<Stage> stages = new ArrayList<>();
    private final List<HeadersController> controllers = new ArrayList<>();
    @BeforeAll static void startup() throws Exception { toolkit(); }
    @BeforeEach void setup() throws Exception {
        previous=Network.get(); Network.set(Network.TESTNET4);
        set(EventManager.class,null,"SINGLETON",new EventBus((e,c)->errors.add(e)));
        set(Config.class,null,"INSTANCE",new Config());
    }
    @AfterEach void cleanup() throws Exception {
        fx(()->{controllers.forEach(HeadersController::close);stages.forEach(Stage::close);return null;});
        Network.set(previous);assertTrue(errors.isEmpty(),errors.toString());
    }
    private Wallet wallet(WalletModel model, AntiExfilKeystorePolicy capability) throws Exception {
        Keystore key=Keystore.fromSeed(new DeterministicSeed("model ensure search plunge galaxy firm exclude brain satoshi meadow cable roast","",0,DeterministicSeed.Type.BIP39),PolicyType.SINGLE_HD,KeyDerivation.parsePath("m/84'/1'/0'"));
        key.setSeed(null);key.setMasterPrivateExtendedKey(null);key.setSource(KeystoreSource.HW_AIRGAPPED);
        key.setWalletModel(model);key.setAntiExfilProfile(AntiExfilProfile.AEXT_V1);key.setAntiExfilPolicy(capability);
        Wallet wallet=new Wallet("Public offline entry-point fixture");wallet.setPolicyType(PolicyType.SINGLE_HD);wallet.setScriptType(ScriptType.P2WPKH);
        wallet.getKeystores().add(key);wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD,ScriptType.P2WPKH,wallet.getKeystores(),1));wallet.checkWallet();return wallet;
    }
    private record View(HeadersController controller,TransactionData data,Map<String,Object> nodes,Stage stage) {}
    private View view(Wallet wallet) throws Exception {
        return fx(()->{
            byte[] bytes=getClass().getResourceAsStream("offline-singlesig-A-first.psbt").readAllBytes();
            assertEquals("cd4e579d43d78b8a6fac27326b9947aecaa08242ae2f4c1a2c691d5d80805ccb",Utils.bytesToHex(com.sparrowwallet.drongo.protocol.Sha256Hash.hash(bytes)));
            FXMLLoader loader=new FXMLLoader(getClass().getResource("headers.fxml"));Parent root=loader.load();
            HeadersController controller=loader.getController();controllers.add(controller);
            TransactionData data=new TransactionData("singlesig-A-first.psbt",new PSBT(bytes,false));
            Stage stage=new Stage();stage.setScene(new Scene(root,1100,850));stages.add(stage);
            stage.getScene().getStylesheets().add(AppServices.class.getResource("app.css").toExternalForm());
            controller.setModel(new HeadersForm(data));stage.show();
            // The production event handler is the same one used by Finalize Transaction for Signing.
            controller.finalizeTransaction(new FinalizeTransactionEvent(data.getPsbt(),wallet));
            root.applyCss();root.layout();return new View(controller,data,loader.getNamespace(),stage);
        });
    }
    @Test void actualProtectedButtonDisplaysStepOneAndCancelsBeforeRevealInIsolatedState() throws Exception {
        String homeProperty=ApplicationDir.getHomeProperty(SparrowWallet.APP_NAME);
        String priorHome=System.getProperty(homeProperty);
        System.setProperty(homeProperty,temp.toString());
        try {
            assertTrue(Storage.getStateDir().toPath().toAbsolutePath().startsWith(temp.toAbsolutePath()));
            for(WalletModel model:List.of(WalletModel.SEEDSIGNER,WalletModel.KERN)){
                Wallet wallet=wallet(model,AntiExfilKeystorePolicy.OPTIONAL);View v=view(wallet);
                fx(()->{
                    v.data.getAvailableWallets().put(wallet,new Storage(temp.resolve(model+".mv.db").toFile()){
                        @Override public String getWalletId(Wallet ignored){return "public-isolated-"+model;}
                    });
                    java.util.concurrent.atomic.AtomicReference<String> shown=new java.util.concurrent.atomic.AtomicReference<>();
                    java.util.concurrent.atomic.AtomicReference<String> displayedUr=new java.util.concurrent.atomic.AtomicReference<>();
                    java.util.concurrent.atomic.AtomicInteger ticks=new java.util.concurrent.atomic.AtomicInteger();
                    Timeline cancel=new Timeline(new KeyFrame(Duration.millis(100),event->{
                        ticks.incrementAndGet();
                        for(Window window:new ArrayList<>(Window.getWindows())){
                            if(window==v.stage||window.getScene()==null)continue;
                            Node found=window.getScene().getRoot().lookup(".dialog-pane");
                            if(found instanceof DialogPane pane){
                                shown.set(pane.getHeaderText());
                                if(pane.getHeaderText()!=null&&pane.getHeaderText().startsWith("Step 1 of 2:")){
                                    for(Node imageNode:pane.lookupAll(".image-view")){
                                        if(imageNode instanceof javafx.scene.image.ImageView view&&view.getImage()!=null&&view.getImage().getWidth()>=500){
                                            var qr=view.getImage();int width=(int)qr.getWidth(),height=(int)qr.getHeight();int[] pixels=new int[width*height];
                                            qr.getPixelReader().getPixels(0,0,width,height,javafx.scene.image.PixelFormat.getIntArgbInstance(),pixels,0,width);
                                            try{displayedUr.set(new com.google.zxing.qrcode.QRCodeReader().decode(new com.google.zxing.BinaryBitmap(new com.google.zxing.common.HybridBinarizer(new com.google.zxing.RGBLuminanceSource(width,height,pixels)))).getText());}
                                            catch(com.google.zxing.ReaderException notReady){/* Wait for an actual decodable frame. */}
                                        }
                                    }
                                    if(displayedUr.get()==null&&ticks.get()<90)continue;
                                    try{snapshot(pane,model+"-step-one");}catch(Exception e){throw new RuntimeException(e);}
                                }
                                pane.getButtonTypes().stream().filter(b->b.getButtonData()==ButtonBar.ButtonData.CANCEL_CLOSE)
                                    .findFirst().ifPresent(b->((Button)pane.lookupButton(b)).fire());
                            }
                        }
                    }));
                    cancel.setCycleCount(100);cancel.play();
                    try{((Button)v.nodes.get("antiExfilButton")).fire();}finally{cancel.stop();}
                    assertNotNull(shown.get(),"Click must display the actual commitment dialog");
                    assertTrue(shown.get().startsWith("Step 1 of 2: scan this commitment with "),shown.get());
                    assertNotNull(displayedUr.get(),"Step 1 must display a decodable QR image, not only open a dialog");
                    assertTrue(displayedUr.get().toUpperCase(Locale.ROOT).startsWith("UR:X-BTC-ANTI-EXFIL/"),displayedUr.get());
                    assertFalse(v.data.getPsbt().hasSignatures());
                    snapshot(v.stage.getScene().getRoot(),model+"-signing-controls");return null;
                });
            }
            try(var paths=Files.walk(temp)){
                assertFalse(paths.anyMatch(path->path.toString().endsWith(".aexs")),"Cancelling Step 1 must create no secret-bearing session file");
            }
            Keystore key=wallet(WalletModel.SEEDSIGNER,AntiExfilKeystorePolicy.OPTIONAL).getKeystores().getFirst();
            Path journal=Storage.getStateDir().toPath().resolve("anti-exfil/journals/ram-"+Utils.bytesToHex(com.sparrowwallet.drongo.antiexfil.AntiExfilCoordinator.getSigningKeyHistoryIdentity(key))+".aexj");
            assertFalse(Files.exists(journal), "V3 Step-1 cancellation must not create or rewrite V2 history");
        }finally{if(priorHome==null)System.clearProperty(homeProperty);else System.setProperty(homeProperty,priorHome);}
    }
    private void snapshot(Node node,String name) throws Exception {
        String directory=System.getProperty("m8.layout.output");if(directory==null)return;
        Path output=Path.of(directory);Files.createDirectories(output);
        var image=node.snapshot(null,null);int width=(int)image.getWidth(),height=(int)image.getHeight();
        int[] pixels=new int[width*height];image.getPixelReader().getPixels(0,0,width,height,javafx.scene.image.PixelFormat.getIntArgbInstance(),pixels,0,width);
        var buffer=new java.awt.image.BufferedImage(width,height,java.awt.image.BufferedImage.TYPE_INT_ARGB);buffer.setRGB(0,0,width,height,pixels,0,width);
        assertTrue(javax.imageio.ImageIO.write(buffer,"png",output.resolve("entry-"+name+".png").toFile()));
    }
    @Test void publicGuideOffersVisibleClickableProtectedQrForBothDevices() throws Exception {
        for(WalletModel model:List.of(WalletModel.SEEDSIGNER,WalletModel.KERN)){
            View v=view(wallet(model,AntiExfilKeystorePolicy.OPTIONAL));
            fx(()->{
                Button protectedQr=(Button)v.nodes.get("antiExfilButton");ToggleButton showQr=(ToggleButton)v.nodes.get("showPsbtButton");
                assertTrue(((Node)v.nodes.get("signButtonBox")).isVisible());
                assertTrue(protectedQr.isVisible(),model+": Protected QR must be visible after finalizing for signing");
                assertTrue(protectedQr.isManaged());assertFalse(protectedQr.isDisabled());assertNotNull(protectedQr.getOnAction());
                assertFalse(protectedQr.isDefaultButton());assertEquals("Protected QR",protectedQr.getText());
                assertTrue(protectedQr.getWidth()>70);assertTrue(protectedQr.getHeight()>24);
                assertEquals("Show QR",showQr.getText());assertTrue(showQr.isVisible());assertFalse(showQr.isDisabled());
                assertFalse(v.data.getPsbt().isSigned());assertFalse(v.data.hasProtectedSigningContext());return null;
            });
        }
    }
    @Test void removingOrDisablingCapabilityHidesTheActionWithoutChangingOrdinaryQr() throws Exception {
        View v=view(wallet(WalletModel.SEEDSIGNER,AntiExfilKeystorePolicy.OPTIONAL));
        fx(()->{v.data.setSigningWallet(null);assertFalse(((Node)v.nodes.get("antiExfilButton")).isVisible());assertFalse(((Node)v.nodes.get("antiExfilButton")).isManaged());return null;});
        for(WalletModel model:List.of(WalletModel.SEEDSIGNER,WalletModel.PASSPORT)){
            Wallet candidate=wallet(model,model==WalletModel.SEEDSIGNER?AntiExfilKeystorePolicy.UNSUPPORTED:AntiExfilKeystorePolicy.OPTIONAL);
            fx(()->{v.data.setSigningWallet(candidate);assertFalse(((Node)v.nodes.get("antiExfilButton")).isVisible());assertFalse(((ToggleButton)v.nodes.get("showPsbtButton")).isDisabled());return null;});
        }
    }
    @Test void capabilityLabelsFitTheActualDropdownWithoutEllipsis() throws Exception {
        fx(()->{
            FXMLLoader loader=new FXMLLoader(getClass().getResource("/com/sparrowwallet/sparrow/wallet/keystore.fxml"));Parent root=loader.load();
            ((Node)loader.getNamespace().get("selectSourcePane")).setVisible(false);
            Node field=(Node)loader.getNamespace().get("antiExfilPolicyField");field.setVisible(true);field.setManaged(true);
            @SuppressWarnings("unchecked") ComboBox<AntiExfilKeystorePolicy> combo=(ComboBox<AntiExfilKeystorePolicy>)loader.getNamespace().get("antiExfilPolicy");
            Stage stage=new Stage();stage.setScene(new Scene(root,1050,720));stages.add(stage);
            stage.getScene().getStylesheets().add(AppServices.class.getResource("app.css").toExternalForm());stage.show();
            combo.getItems().setAll(AntiExfilKeystorePolicy.values());
            assertEquals("Enabled",AntiExfilKeystorePolicy.OPTIONAL.toString());
            for(AntiExfilKeystorePolicy policy:AntiExfilKeystorePolicy.values()){
                combo.setValue(policy);root.applyCss();root.layout();
                Node display=((javafx.scene.control.skin.ComboBoxListViewSkin<?>)combo.getSkin()).getDisplayNode();
                javafx.scene.text.Text rendered=(javafx.scene.text.Text)display.lookup(".text");assertNotNull(rendered);
                assertEquals(policy.toString(),rendered.getText(),"Capability label must not be truncated");
                assertTrue(display.localToScene(display.getBoundsInLocal()).contains(rendered.localToScene(rendered.getBoundsInLocal())));
                if(policy==AntiExfilKeystorePolicy.OPTIONAL)snapshot(root,"capability-enabled");
            }
            return null;
        });
    }
}
