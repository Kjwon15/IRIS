package etri.sdn.controller.module.authmanager;

import etri.sdn.controller.protocol.io.Connection;
import etri.sdn.controller.protocol.io.IOFSwitch;
import org.joda.time.DateTime;

import java.util.HashMap;

/**
 * @author kjwon15
 * @created 15. 2. 16
 */
public class SwitchInfo {
    boolean isAuthenticated;
    IOFSwitch iofSwitch;
    Connection connection;
    HashMap<Long, byte[]> authMsgs = new HashMap<>();
    DateTime lastAuthenticated = DateTime.now();

    public SwitchInfo(IOFSwitch iofSwitch) {
        this.iofSwitch = iofSwitch;
        this.isAuthenticated = false;
        this.connection = iofSwitch.getConnection();
    }

    public void setAuthenticated() {
        this.isAuthenticated = true;
    }
}