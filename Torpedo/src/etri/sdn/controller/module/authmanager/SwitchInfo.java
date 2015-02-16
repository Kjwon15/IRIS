package etri.sdn.controller.module.authmanager;

import etri.sdn.controller.protocol.io.Connection;
import etri.sdn.controller.protocol.io.IOFSwitch;

/**
 * @author kjwon15
 * @created 15. 2. 16
 */
public class SwitchInfo {
    boolean isAuthenticated;
    IOFSwitch iofSwitch;
    Connection connection;

    public SwitchInfo(IOFSwitch iofSwitch) {
        this.iofSwitch = iofSwitch;
        this.isAuthenticated = false;
        this.connection = iofSwitch.getConnection();
    }

    public void setAuthenticated() {
        this.isAuthenticated = true;
    }
}
