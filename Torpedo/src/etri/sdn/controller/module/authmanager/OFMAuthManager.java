package etri.sdn.controller.module.authmanager;

import etri.sdn.controller.*;
import etri.sdn.controller.protocol.io.Connection;
import etri.sdn.controller.protocol.io.IOFSwitch;
import org.projectfloodlight.openflow.protocol.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * @author kjwon15
 * @created 15. 2. 16
 *
 * T: Authenticated switch, U: Switch that is not authenticated yet.
 * T -> T: overwrite
 * T -> U: hold until authenticated.
 * U -> T: overwrite
 * U -> U: overwrite (like normal)
 */
public class OFMAuthManager extends OFModule {

    private static final byte[] AUTH_DATA = "TEST".getBytes();

    HashMap<Long, SwitchInfo> existingSwitches;
    HashMap<Connection, SwitchInfo> unauthenticatedSwitches;

    private static final Logger logger = LoggerFactory.getLogger(OFMAuthManager.class);


    @Override
    protected Collection<Class<? extends IService>> services() {
        return Collections.emptyList();
    }

    @Override
    protected void initialize() {

        existingSwitches = new HashMap<>();
        unauthenticatedSwitches = new HashMap<>();

        for (IOFSwitch iofSwitch : getController().getSwitches()) {
            SwitchInfo sw = new SwitchInfo(iofSwitch);
            existingSwitches.put(iofSwitch.getId(), sw);
            authRequest(iofSwitch.getConnection());
        }

        registerFilter(OFType.EXPERIMENTER, new OFMFilter() {
            @Override
            public boolean filter(OFMessage m) {
                return m instanceof OFAuthReply;
            }
        });
    }

    private void authRequest(Connection conn) {
        OFVersion version = conn.getSwitch().getVersion();
        OFAuthRequest authRequest = OFFactories.getFactory(version).authRequest(AUTH_DATA);
        conn.write(authRequest);
        logger.info("Auth request");
    }

    @Override
    protected boolean handleHandshakedEvent(Connection conn, MessageContext context) {
        IOFSwitch newSwitch = conn.getSwitch();
        Long dpid = newSwitch.getId();
        SwitchInfo existingSwitchInfo = existingSwitches.get(dpid);
        SwitchInfo newSwitchInfo = new SwitchInfo(newSwitch);

        if (existingSwitchInfo != null && existingSwitchInfo.isAuthenticated) {
            // Replace to old switch, and hold new switch until authenticated.

            getController().addSwitch(dpid, existingSwitchInfo.iofSwitch);
            unauthenticatedSwitches.put(conn, newSwitchInfo);
            logger.info("Duplicated DPID with authenticated switch!");
        } else {
            // replace switch.
            existingSwitches.put(dpid, newSwitchInfo);
            unauthenticatedSwitches.put(conn, newSwitchInfo);
        }

        authRequest(conn);
        return true;
    }

    @Override
    protected boolean handleMessage(Connection conn, MessageContext context, OFMessage msg, List<OFMessage> outgoing) {

        IOFSwitch sw = conn.getSwitch();
        Long dpid = sw.getId();

        SwitchInfo switchInfo = unauthenticatedSwitches.get(conn);
        if (switchInfo == null) {
            return true;
        }

        OFAuthReply authReply = (OFAuthReply) msg;
        if (Arrays.equals(authReply.getData(), AUTH_DATA)) {
            conn.close();
            return false;
        }

        switchInfo.setAuthenticated();
        // Overwrite.
        existingSwitches.put(dpid, switchInfo);

        logger.info("Got auth reply");

        return true;
    }

    @Override
    protected boolean handleDisconnect(Connection conn) {
        unauthenticatedSwitches.remove(conn);

        Long dpid = conn.getSwitch().getId();
        SwitchInfo existingSwitch = existingSwitches.get(dpid);
        if (existingSwitch != null && existingSwitch.iofSwitch.getConnection() == conn) {
            existingSwitches.remove(dpid);
        }
        logger.info("Disconnect holding switch");
        return true;
    }

    @Override
    public OFModel[] getModels() {
        return null;
    }
}
