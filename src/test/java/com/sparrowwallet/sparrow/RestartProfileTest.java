package com.sparrowwallet.sparrow;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.sparrow.io.Storage;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Method;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class RestartProfileTest {
    @Test
    void restartKeepsEffectiveHomeAndActiveNetwork() throws Exception {
        String previousHome = System.getProperty(SparrowWallet.APP_HOME_PROPERTY);
        Network previousNetwork = Network.get();
        Method method = AppController.class.getDeclaredMethod("getRestartArgs");
        method.setAccessible(true);
        try {
            for(String home : new String[] {null, Path.of("build", "restart test home").toAbsolutePath().toString()}) {
                if(home == null) System.clearProperty(SparrowWallet.APP_HOME_PROPERTY);
                else System.setProperty(SparrowWallet.APP_HOME_PROPERTY, home);
                for(Network network : new Network[] {Network.TESTNET, Network.TESTNET4}) {
                    Network.set(network);
                    Args args = (Args)method.invoke(null);
                    if(home == null) {
                        // Keep default/XDG category resolution instead of turning it into an explicit home.
                        assertNull(args.dir);
                        assertFalse(args.toParams().contains("-d"));
                    } else {
                        assertEquals(Storage.getConfigHome().getAbsolutePath(), args.dir);
                        assertEquals(args.dir, args.toParams().get(args.toParams().indexOf("-d") + 1));
                    }
                    assertEquals(network, args.network);
                    assertEquals(network.toString(), args.toParams().get(args.toParams().indexOf("-n") + 1));
                }
            }
        } finally {
            if(previousHome == null) System.clearProperty(SparrowWallet.APP_HOME_PROPERTY);
            else System.setProperty(SparrowWallet.APP_HOME_PROPERTY, previousHome);
            Network.set(previousNetwork);
        }
    }
}
