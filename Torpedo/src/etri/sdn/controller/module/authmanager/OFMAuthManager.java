package etri.sdn.controller.module.authmanager;

import etri.sdn.controller.*;
import etri.sdn.controller.protocol.io.Connection;
import etri.sdn.controller.protocol.io.IOFSwitch;
import org.joda.time.DateTime;
import org.joda.time.Period;
import org.projectfloodlight.openflow.protocol.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

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

    final ConcurrentHashMap<Long, SwitchInfo> existingSwitches = new ConcurrentHashMap<>();
    final HashMap<Connection, SwitchInfo> unauthenticatedSwitches = new HashMap<>();
    Timer scheduler;

    private static final Logger logger = LoggerFactory.getLogger(OFMAuthManager.class);

    private static long period = 1024;
    private static final long TIMEOUT = 1000000;


    @Override
    protected Collection<Class<? extends IService>> services() {
        return Collections.emptyList();
    }

    @Override
    protected void initialize() {

        existingSwitches.clear();
        unauthenticatedSwitches.clear();

        for (IOFSwitch iofSwitch : getController().getSwitches()) {
            SwitchInfo sw = new SwitchInfo(iofSwitch);
            existingSwitches.put(iofSwitch.getId(), sw);
        }

        period =TorpedoProperties.loadConfiguration().getInt("auth-period");

        logger.info("Auth manager with period {}", period);

        scheduler = new Timer();
        scheduler.scheduleAtFixedRate(new AuthScheduler(), 0, period);

        registerFilter(OFType.EXPERIMENTER, new OFMFilter() {
            @Override
            public boolean filter(OFMessage m) {
                return m instanceof OFAuthReply;
            }
        });
    }

    private void authRequest(SwitchInfo swInfo) {
        OFVersion version = swInfo.iofSwitch.getVersion();
        byte[] authData = new byte[]{(byte) System.currentTimeMillis(), (byte) swInfo.iofSwitch.getId()};
        OFAuthRequest authRequest = OFFactories.getFactory(version).authRequest(authData);

        // FIXME: This algorithm is very dangerous.
        swInfo.authMsgs.put(authRequest.getXid(), authData);
        swInfo.connection.write(authRequest);
        logger.debug("Auth request {}", swInfo.iofSwitch.getStringId());
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
            logger.warn("Duplicated DPID with authenticated switch! {}", newSwitch.getStringId());
        } else {
            // replace switch.
            if (existingSwitchInfo != null) {
                existingSwitchInfo.connection.close();
            }
            existingSwitches.put(dpid, newSwitchInfo);
            unauthenticatedSwitches.put(conn, newSwitchInfo);
            authRequest(newSwitchInfo);
        }

        return true;
    }

    @Override
    protected boolean handleMessage(Connection conn, MessageContext context, OFMessage msg, List<OFMessage> outgoing) {

        IOFSwitch sw = conn.getSwitch();
        Long dpid = sw.getId();

        SwitchInfo switchInfo = unauthenticatedSwitches.get(conn);
        if (switchInfo == null) {
            switchInfo = existingSwitches.get(dpid);
        }

        OFAuthReply authReply = (OFAuthReply) msg;
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] data = switchInfo.authMsgs.get(authReply.getXid());
            if (Arrays.equals(sha1.digest(data), authReply.getData())) {
                switchInfo.lastAuthenticated = DateTime.now();
                unauthenticatedSwitches.remove(conn);
                switchInfo.authMsgs.remove(authReply.getXid());
            } else {
                logger.warn("Authentication failed {}", sw.getStringId());
                conn.close();
                return false;
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        }

        switchInfo.setAuthenticated();
        // Overwrite.
        existingSwitches.put(dpid, switchInfo);

        logger.debug("Got auth reply {}", sw.getStringId());

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
        logger.info("Disconnect holding switch {}", conn.getSwitch().getStringId());
        return true;
    }

    @Override
    public OFModel[] getModels() {
        return null;
    }

    private class AuthScheduler extends TimerTask {
        Period timeout = new Period(TIMEOUT);

        @Override
        public void run() {
            DateTime now = DateTime.now();
            for (SwitchInfo swInfo : existingSwitches.values()) {
                Period p = new Period(swInfo.lastAuthenticated, now);
                if (comparePeriod(p, timeout) > 0) {
                    logger.info("Timed out {}", swInfo.iofSwitch.getStringId());
                    swInfo.connection.close();
                    existingSwitches.remove(swInfo.iofSwitch.getId());
                    continue;
                }

                authRequest(swInfo);
            }
        }

        int comparePeriod(Period p1, Period p2) {
            int[] v1 = p1.getValues();
            int[] v2 = p2.getValues();
            assert v1.length == v2.length;

            for (int i = 0; i < v1.length; i++) {
                if (v1[i] == v2[i]) {
                    continue;
                }

                if (v1[i] > v2[i]) {
                    return 1;
                } else {
                    return -1;
                }
            }

            return 0;
        }
    }
}