package etri.sdn.controller.module.statemanager;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.codehaus.jackson.JsonFactory;
import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.map.ObjectMapper;
import org.joda.time.Interval;
import org.joda.time.Period;
import org.openflow.protocol.OFFeaturesReply;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.statistics.OFAggregateStatisticsReply;
import org.openflow.protocol.statistics.OFAggregateStatisticsRequest;
import org.openflow.protocol.statistics.OFDescriptionStatistics;
import org.openflow.protocol.statistics.OFFlowStatisticsReply;
import org.openflow.protocol.statistics.OFFlowStatisticsRequest;
import org.openflow.protocol.statistics.OFPortStatisticsReply;
import org.openflow.protocol.statistics.OFPortStatisticsRequest;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;
import org.openflow.util.HexString;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.Restlet;
import org.restlet.data.MediaType;

import etri.sdn.controller.OFModel;
import etri.sdn.controller.protocol.io.IOFSwitch;

/**
 * Model that represents the internal data of {@link OFMStateManager}. 
 * 
 * @author bjlee
 *
 */
public class State extends OFModel {

	private OFMStateManager manager;
	private long timeInitiated;
	private long totalMemory;
	
	/**
	 * Create the State instance.
	 * 
	 * @param manager	reference to the OFMStateManager module.
	 */
	public State(OFMStateManager manager) {
		this.manager = manager;
		this.timeInitiated = Calendar.getInstance().getTimeInMillis();
		this.totalMemory = Runtime.getRuntime().totalMemory();
	}
	
	/**
	 * Custom Serializer for FEATURES_REPLY message. 
	 * This is used to handle the REST URI /wm/core/switch/{switchid}/features/json.
	 */
	private OFFeaturesReplySerializerModule features_reply_module = new OFFeaturesReplySerializerModule();
	
	/**
	 * Custom Serializer for FLOW_STATISTICS_REPLY message.
	 * This is used to handle the REST URI /wm/core/switch/{switchid}/flow/json.
	 */
	private OFFlowStatisticsReplySerializerModule flow_statistics_reply_module 
		= new OFFlowStatisticsReplySerializerModule();
	
	/**
	 * Array of RESTApi objects. 
	 * Each objects represent a REST call handler routine bound to a specific URI.
	 */
	private RESTApi[] apis = {
			
		/**
		 * This object is to implement a REST handler routine for retrieving 
		 * all switch information
		 */
		new RESTApi(
			"/wm/core/controller/switches/json",
			new Restlet() {
				@Override
				public void handle(Request request, Response response) {
					StringWriter sWriter = new StringWriter();
					JsonFactory f = new JsonFactory();
					JsonGenerator g = null;
					try { 
						g = f.createJsonGenerator(sWriter);
					
						g.writeStartArray();
						for ( IOFSwitch sw : manager.getController().getSwitches() ) {
							g.writeStartObject();
							g.writeFieldName("dpid");
							g.writeString(HexString.toHexString(sw.getId()));
							g.writeFieldName("inetAddress");
							g.writeString(sw.getConnection().getClient().getRemoteAddress().toString());
							g.writeFieldName("connectedSince");
							g.writeNumber(sw.getConnectedSince().getTime());
							g.writeEndObject();
						}
						g.writeEndArray();
						g.close();
						
					} catch (IOException e) {
						e.printStackTrace();
					}
					
					String r = sWriter.toString();
					response.setEntity(r, MediaType.APPLICATION_JSON);
				}
			}
		),
		
		/**
		 * This object is to implement a REST handler routine 
		 * for retrieving switch aggregate flow statistics
		 */
		new RESTApi(
			"/wm/core/switch/{switchid}/aggregate/json",
			new Restlet() {
				@Override
				public void handle(Request request, Response response) {
					String switchIdStr = (String) request.getAttributes().get("switchid");
					Long switchId = HexString.toLong(switchIdStr);
					IOFSwitch sw = manager.getController().getSwitch(switchId);
					if ( sw == null ) {
						return;		// switch is not completely set up.
					}
					
					OFStatisticsRequest req = new OFStatisticsRequest();
					req.setStatisticType(OFStatisticsType.AGGREGATE);
					int requestLength = req.getLengthU();
					OFAggregateStatisticsRequest specificReq = new OFAggregateStatisticsRequest();
					OFMatch match = new OFMatch();
	                match.setWildcards(0xffffffff);
	                specificReq.setMatch(match);
	                specificReq.setOutPort(OFPort.OFPP_NONE.getValue());
	                specificReq.setTableId((byte) 0xff);
	                req.setStatistics(Collections.singletonList((OFStatistics)specificReq));
	                requestLength += specificReq.getLength();
	                req.setLengthU(requestLength);
	                
	                List<OFStatistics> reply = sw.getSwitchStatistics( req );
	                HashMap<String, List<OFStatistics>> output = new HashMap<String, List<OFStatistics>>();
	                if ( reply != null && ! reply.isEmpty() ) {
	                	output.put(switchIdStr, reply );
	                }
	                
	                // create an object mapper.
					ObjectMapper om = new ObjectMapper();
					
					try {
						String r = om./*writerWithDefaultPrettyPrinter().*/writeValueAsString(output);
						response.setEntity(r, MediaType.APPLICATION_JSON);
					} catch (Exception e) {
						e.printStackTrace();
						return;
					}
				}
			}
		),
		
		/**
		 * This is to implement a REST handler 
		 * for retrieving switch description.
		 */
		new RESTApi(
			"/wm/core/switch/{switchid}/desc/json",
			new Restlet() {
				@Override
				public void handle(Request request, Response response) {
					String switchIdStr = (String) request.getAttributes().get("switchid");
					Long switchId = HexString.toLong(switchIdStr);
					IOFSwitch sw = manager.getController().getSwitch(switchId);
					if ( sw == null ) {
						return;		// switch is not completely set up.
					}
					
					OFStatisticsRequest req = new OFStatisticsRequest();
					req.setStatisticType(OFStatisticsType.AGGREGATE);
					int requestLength = req.getLengthU();
					OFAggregateStatisticsRequest specificReq = new OFAggregateStatisticsRequest();
					OFMatch match = new OFMatch();
	                match.setWildcards(0xffffffff);
	                specificReq.setMatch(match);
	                specificReq.setOutPort(OFPort.OFPP_NONE.getValue());
	                specificReq.setTableId((byte) 0xff);
	                req.setStatistics(Collections.singletonList((OFStatistics)specificReq));
	                requestLength += specificReq.getLength();
	                req.setLengthU(requestLength);
	                
	                List<OFStatistics> reply = sw.getSwitchStatistics( req );
	                int flowCount = 0;
					long packetCount = 0;
					long byteCount = 0;
	                if ( reply != null && !reply.isEmpty() ) {
	                	OFStatistics stat = reply.remove(0);
	                	if ( stat instanceof OFAggregateStatisticsReply ) {
	                		OFAggregateStatisticsReply aggs = (OFAggregateStatisticsReply) stat;
	                		flowCount = aggs.getFlowCount();
	                		byteCount = aggs.getByteCount();
	                		packetCount = aggs.getPacketCount();
//	                		System.out.printf("%x %x %x", flowCount, byteCount, packetCount);
	                	}
	                }
					
	                StringWriter sWriter = new StringWriter();
	                JsonFactory f = new JsonFactory();
	                JsonGenerator g = null;
	                OFDescriptionStatistics desc = sw.getDescription();
	                try {
	                	g = f.createJsonGenerator(sWriter);
	                	g.writeStartObject();
	                	g.writeFieldName(HexString.toHexString(sw.getId()));
	                	g.writeStartArray();
	                	g.writeStartObject();
	                	g.writeFieldName("datapathDescription");
	                	g.writeString( desc!=null ? desc.getDatapathDescription() : "-" );
	                	g.writeFieldName("hardwareDescription");
	                	g.writeString( desc!=null ? desc.getHardwareDescription() : "-" );
	                	g.writeFieldName("manufacturerDescription");
	                	g.writeString( desc!=null ? desc.getManufacturerDescription() : "-" );
	                	g.writeFieldName("serialNumber");
	                	g.writeString( desc!=null ? desc.getSerialNumber() : "-" );
	                	g.writeFieldName("softwareDescription");
	                	g.writeString( desc!=null ? desc.getSoftwareDescription() : "-" );
	                	g.writeFieldName("flowCount");
	                	g.writeNumber(flowCount);
	                	g.writeFieldName("packetCount");
	                	g.writeNumber(packetCount);
	                	g.writeFieldName("byteCount");
	                	g.writeNumber(byteCount);
	                	g.writeEndObject();
	                	g.writeEndArray();
	                	g.writeEndObject();
	                	g.close();
	                } catch (IOException e) {
	                	e.printStackTrace();
	                }

	                String r = sWriter.toString();
	                response.setEntity(r, MediaType.APPLICATION_JSON);
				}
			}
		),
		
		/**
		 * This object is to implement a REST handler 
		 * for retrieving switch port information (all ports)
		 */
		new RESTApi(
			"/wm/core/switch/{switchid}/port/json",
			new Restlet() {
				@Override
				public void handle(Request request, Response response) {

					String switchIdStr = (String) request.getAttributes().get("switchid");
					Long switchId = HexString.toLong(switchIdStr);
					IOFSwitch sw = manager.getController().getSwitch(switchId);
					if ( sw == null ) {
						return;		// switch is not completely set up.
					}
					
					HashMap<String, List<OFPortStatisticsReply>> result = 
						new HashMap<String, List<OFPortStatisticsReply>>();
					
					List<OFPortStatisticsReply> resultValues;
					result.put( 
						switchIdStr, 
						resultValues = new java.util.LinkedList<OFPortStatisticsReply>() 
					);

					OFStatisticsRequest req = new OFStatisticsRequest();
					req.setStatisticType(OFStatisticsType.PORT);
					int requestLength = req.getLengthU();
					
					OFPortStatisticsRequest specificReq = new OFPortStatisticsRequest();
	                specificReq.setPortNumber((short)OFPort.OFPP_NONE.getValue());
	                req.setStatistics(Collections.singletonList((OFStatistics)specificReq));
	                requestLength += specificReq.getLength();

					req.setLengthU( requestLength );

					List<OFStatistics> reply = sw.getSwitchStatistics( req );
					for ( OFStatistics s : reply ) {
						if ( s instanceof OFPortStatisticsReply ) {
							resultValues.add( (OFPortStatisticsReply) s );
						}
					}
					
					// create an object mapper.
					ObjectMapper om = new ObjectMapper();
					
					try {
						String r = om./*writerWithDefaultPrettyPrinter().*/writeValueAsString(result);
						response.setEntity(r, MediaType.APPLICATION_JSON);
					} catch (Exception e) {
						e.printStackTrace();
						return;
					}
				}
			}
		),
		
		/**
		 * This object is to implement a REST handler 
		 * to retrieve switch feature (FEATURES_REPLY) 
		 */
		new RESTApi(
			"/wm/core/switch/{switchid}/features/json",
			new Restlet() {
				@Override
				public void handle(Request request, Response response) {
					
					String switchIdStr = (String) request.getAttributes().get("switchid");
					Long switchId = HexString.toLong(switchIdStr);
					IOFSwitch sw = manager.getController().getSwitch(switchId);
					if ( sw == null ) {
						return;		// switch is not completely set up.
					}
					
					OFFeaturesReply reply = sw.getFeaturesReply();
					
					HashMap<String, OFFeaturesReply> result = new HashMap<String, OFFeaturesReply>();
					result.put( switchIdStr, reply );
					
					// create an object mapper.
					ObjectMapper om = new ObjectMapper();
					om.registerModule(features_reply_module);
					
					try {
						String r = om./*writerWithDefaultPrettyPrinter().*/writeValueAsString(result);
						response.setEntity(r, MediaType.APPLICATION_JSON);
					} catch (Exception e) {
						e.printStackTrace();
						return;
					}
				}
			}
		),
		
		/**
		 * This object is to implement a REST handler 
		 * to retrieve FLOW_STATISTICS_REPLY message content
		 */
		new RESTApi(
			"/wm/core/switch/{switchid}/flow/json",
			new Restlet() {
				@Override
				public void handle(Request request, Response response) {
					
					String switchIdStr = (String) request.getAttributes().get("switchid");
					Long switchId = HexString.toLong(switchIdStr);
					IOFSwitch sw = manager.getController().getSwitch(switchId);
					if ( sw == null ) {
						return;		// switch is not completely set up.
					}
					
					HashMap<String, List<OFFlowStatisticsReply>> result 
						= new HashMap<String, List<OFFlowStatisticsReply>>();
					List<OFFlowStatisticsReply> resultValues = new java.util.LinkedList<OFFlowStatisticsReply>();
					result.put( switchIdStr, resultValues );
					
					OFStatisticsRequest req = new OFStatisticsRequest();
					req.setStatisticType(OFStatisticsType.FLOW);
					int requestLength = req.getLengthU();
					
					OFFlowStatisticsRequest specificReq = new OFFlowStatisticsRequest();
	                OFMatch match = new OFMatch();
	                match.setWildcards(0xffffffff);
	                specificReq.setMatch(match);
	                specificReq.setOutPort(OFPort.OFPP_NONE.getValue());
	                specificReq.setTableId((byte) 0xff);
	                req.setStatistics(Collections.singletonList((OFStatistics)specificReq));
	                requestLength += specificReq.getLength();
	                
	                req.setLengthU( requestLength );

					List<OFStatistics> reply = sw.getSwitchStatistics( req );
					for ( OFStatistics s : reply ) {
						if ( s instanceof OFFlowStatisticsReply ) {
							resultValues.add( (OFFlowStatisticsReply) s );
						}
					}
					
					// create an object mapper.
					ObjectMapper om = new ObjectMapper();
					om.registerModule(flow_statistics_reply_module);
					
					try {
						String r = om.writerWithDefaultPrettyPrinter().writeValueAsString(result);
						response.setEntity(r, MediaType.APPLICATION_JSON);
					} catch (Exception e) {
						e.printStackTrace();
						return;
					}
				}
			}
		),
		
		/**
		 * This object is to implement a REST handler 
		 * to retrieve controller system health-related information 
		 */
		new RESTApi(
			"/wm/core/health/json",
			new Restlet() {
				@Override
				public void handle(Request request, Response response) {
					
					StringWriter sWriter = new StringWriter();
					JsonFactory f = new JsonFactory();
					JsonGenerator g = null;
					try {
						g = f.createJsonGenerator(sWriter);
						g.writeStartObject();
						g.writeFieldName("host");
						g.writeString("localhost");
						g.writeFieldName("ofport");
						g.writeNumber(6633);
						g.writeFieldName("uptime");
						Interval temp = new Interval(timeInitiated, Calendar.getInstance().getTimeInMillis());
						Period tempPeriod = temp.toPeriod();
						g.writeString(
							String.format(
								"System is up for %d days %d hours %d minutes %d seconds",
								tempPeriod.getDays(),
								tempPeriod.getHours(),
								tempPeriod.getMinutes(),
								tempPeriod.getSeconds()
							)
						);
						g.writeFieldName("free");
						g.writeString(Runtime.getRuntime().freeMemory()/1024/1024 + "M");
						g.writeFieldName("total");
						g.writeString(totalMemory/1024/1024 + "M");
						g.writeFieldName("healthy");
						g.writeBoolean(true);
						g.writeFieldName("modules");
						g.writeStartArray();
						String[] moduleNames = manager.getController().getModuleNames();
						if ( moduleNames != null ) {
							for ( String s : moduleNames ) {
								g.writeString(s);
							}
						}
						g.writeEndArray();
						g.writeFieldName("moduleText");
						g.writeString(manager.getController().getConcatenatedModuleNames());
						g.writeEndObject();
						g.close();
					} catch (IOException e) {
						e.printStackTrace();
					}

					String r = sWriter.toString();
					
					response.setEntity(r, MediaType.APPLICATION_JSON);
				}
			}
		),
		
		/**
		 * This object is to implement a REST handler 
		 * for retrieving module information (list of modules)
		 */
		new RESTApi(
			"/wm/core/module/{type}/json",
			new Restlet() {
				@Override
				public void handle(Request request, Response response) {
					String typeStr = (String) request.getAttributes().get("type");
					if ( typeStr.equals("loaded") ) {
											
						// create an object mapper.
						ObjectMapper om = new ObjectMapper();
						om.registerModule( new ModuleListSerializerModule());
						
						try {
							String r = om.writerWithDefaultPrettyPrinter().writeValueAsString( manager.getController() );
							response.setEntity(r, MediaType.APPLICATION_JSON);
						} catch (Exception e) {
							e.printStackTrace();
							return;
						}
					}
				}
			}
		),
		
		/**
		 * This object is to implement a REST handler 
		 * that exports memory status. 
		 */
		new RESTApi(
			"/wm/core/memory/json",
			new Restlet() {
				@Override
				public void handle(Request request, Response response) {
					StringWriter sWriter = new StringWriter();
					JsonFactory f = new JsonFactory();
					JsonGenerator g = null;
					try {
						g = f.createJsonGenerator(sWriter);
						g.writeStartObject();
						g.writeFieldName("total");
						g.writeString(totalMemory/1024/1024 + "M");
						g.writeFieldName("free");
						g.writeString(Runtime.getRuntime().freeMemory()/1024/1024 + "M");
						g.writeEndObject();
						g.close();
					} catch (IOException e) {
						e.printStackTrace();
					}

					String r = sWriter.toString();
					
					response.setEntity(r, MediaType.APPLICATION_JSON);
				}
			}
		)
	};
	
	/**
	 * Returns the list of all RESTApi objects
	 * 
	 * @return		array of all RESTApi objects
	 */
	@Override
	public RESTApi[] getAllRestApi() {
		return this.apis;
	}
}
