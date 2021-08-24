/*
 * Created on Dec 15, 2013
 * Created by Paul Gardner
 * 
 * Copyright 2013 Azureus Software, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details ( see the LICENSE file ).
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */



package org.parg.azureus.plugins.networks.tor;

import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.lang.management.RuntimeMXBean;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.Socket;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import com.biglybt.core.security.SEPasswordListener;
import com.biglybt.core.security.SESecurityManager;
import com.biglybt.core.tracker.protocol.PRHelpers;
import com.biglybt.core.util.*;
import com.biglybt.pif.PluginAdapter;
import com.biglybt.pif.PluginConfig;
import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.UnloadablePlugin;
import com.biglybt.pif.ipc.IPCException;
import com.biglybt.pif.logging.LoggerChannel;
import com.biglybt.pif.logging.LoggerChannelListener;
import com.biglybt.pif.ui.UIInstance;
import com.biglybt.pif.ui.UIManager;
import com.biglybt.pif.ui.UIManagerEvent;
import com.biglybt.pif.ui.UIManagerListener;
import com.biglybt.pif.ui.config.*;
import com.biglybt.pif.ui.model.BasicPluginConfigModel;
import com.biglybt.pif.ui.model.BasicPluginViewModel;
import com.biglybt.pif.utils.LocaleUtilities;
import org.parg.azureus.plugins.networks.tor.TorPluginUI.PromptResponse;

import com.biglybt.core.proxy.*;
import com.biglybt.core.proxy.socks.*;
import com.biglybt.ui.UIFunctions;
import com.biglybt.ui.UIFunctionsManager;

public class 
TorPlugin
	implements UnloadablePlugin
{
	private static final String		BROWSER_PLUGIN_ID = "aznettorbrowser";
	
	private PluginInterface			plugin_interface;
	private PluginConfig plugin_config;
	private LoggerChannel 			log;
	private BasicPluginConfigModel 	config_model;
	private BasicPluginViewModel	view_model;
	
	private volatile TorPluginUI		plugin_ui;
	
	private AESemaphore		init_sem 		= new AESemaphore( "TP:init" );
	private AESemaphore		ui_attach_sem 	= new AESemaphore( "TP:UI" );
	
	private volatile long	init_time;
	
	private static final int	SOCKS_PORT_DEFAULT		= 29101;
	private static final int	CONTROL_PORT_DEFAULT	= 29151;

	private File	plugin_dir;
	private File	config_file;
	private File	data_dir;
	private File	services_dir;
	
	private BooleanParameter prompt_on_use_param;
	
	private ActionParameter prompt_reset_param;
	
	private ActionParameter browser_install_param; 
	private ActionParameter browser_launch_param;
	
	private BooleanParameter services_enable_param;

	private boolean	plugin_enabled;
	private boolean	external_tor;
	private boolean	start_on_demand;
	private boolean	stop_on_idle;
	private boolean	prompt_on_use;
	private boolean	prompt_skip_vuze;
	private int		internal_control_port;
	private String	internal_socks_host	= "127.0.0.1";
	private int		internal_socks_port;
	
	private String	external_socks_host	= internal_socks_host;
	private int		external_socks_port;
	
	private boolean	debug_server;
	
	private String		active_socks_host;
	private int			active_socks_port;
	
	private long	MIN_RECONNECT_TIME		= 60*1000;
	private long	MAX_CONNECT_WAIT_TIME	= 2*60*1000;
	private long	STOP_ON_IDLE_TIME		= 10*60*1000;

	private SOCKSProxy				socks_proxy;
	
	private SOCKSProxy				filtering_proxy;
	private String					filtering_i2p_host	= "127.0.0.1";
	private int						filtering_i2p_port;
	
	private ControlConnection		current_connection;
	private AESemaphore 			connection_sem;
	private long					last_connect_time;
	
	private boolean					permissions_checked;
	
	private Set<String>				prompt_decisions 	= new HashSet<String>();
	private String					last_decision_log	= "";
	
	private volatile long			last_use_time;
	
	private Map<Proxy,ProxyMapEntry>			proxy_map 				= new IdentityHashMap<Proxy, ProxyMapEntry>();
	private Map<String,Object[]>				intermediate_host_map	= new HashMap<String, Object[]>();
	
	private Map<String,String>					domain_rewrite_map	= new HashMap<String, String>();
	
	private Map<String,TorPluginHTTPProxy>		http_proxy_map		= new HashMap<String, TorPluginHTTPProxy>();
	
	private AtomicLong	proxy_request_count		= new AtomicLong();
	private AtomicLong	proxy_request_ok		= new AtomicLong();
	private AtomicLong	proxy_request_failed	= new AtomicLong();
	
	private static final int MAX_HISTORY_RECORDS	= 4096;
	
	@SuppressWarnings( "serial" )
	private Map<String,ProxyHistory>		proxy_history = 
			new LinkedHashMap<String,ProxyHistory>(MAX_HISTORY_RECORDS,0.75f,true)
			{
				@Override
				protected boolean
				removeEldestEntry(
			   		Map.Entry<String,ProxyHistory> eldest) 
				{
					return size() > MAX_HISTORY_RECORDS;
				}
			};
		
	private volatile boolean		config_needs_checking	= true;
	
	private volatile boolean		unloaded;
	
	
	@Override
	public void
	initialize(
		PluginInterface pi )
	{
		try{
			plugin_interface	= pi;
			
			setUnloadable( true );
			
			final LocaleUtilities loc_utils = plugin_interface.getUtilities().getLocaleUtilities();
			
			log	= plugin_interface.getLogger().getTimeStampedChannel( "TorHelper");
			
			final UIManager	ui_manager = plugin_interface.getUIManager();

			view_model = ui_manager.createBasicPluginViewModel( loc_utils.getLocalisedMessageText( "aztorplugin.name" ));

			view_model.getActivity().setVisible( false );
			view_model.getProgress().setVisible( false );
			
			log.addListener(
					new LoggerChannelListener()
					{
						@Override
						public void
						messageLogged(
							int		type,
							String	content )
						{
							view_model.getLogArea().appendText( content + "\n" );
						}
						
						@Override
						public void
						messageLogged(
							String		str,
							Throwable	error )
						{
							view_model.getLogArea().appendText( str + "\n" );
							view_model.getLogArea().appendText( error.toString() + "\n" );
						}
					});
					
			plugin_config = plugin_interface.getPluginconfig();
						
			config_model = ui_manager.createBasicPluginConfigModel( "plugins", "aztorplugin.name" );

			view_model.setConfigSectionID( "aztorplugin.name" );

			config_model.addLabelParameter2( "aztorplugin.info1" );
			config_model.addLabelParameter2( "aztorplugin.info2" );
			
			final BooleanParameter enable_param = config_model.addBooleanParameter2( "enable", "aztorplugin.enable", true );

			final BooleanParameter start_on_demand_param 	= config_model.addBooleanParameter2( "start_on_demand", "aztorplugin.start_on_demand", true );
			final BooleanParameter stop_on_idle_param	 	= config_model.addBooleanParameter2( "stop_on_idle", "aztorplugin.stop_on_idle", true );
			prompt_on_use_param 							= config_model.addBooleanParameter2( "prompt_on_use", "aztorplugin.prompt_on_use", true );
			final BooleanParameter prompt_skip_vuze_param 	= config_model.addBooleanParameter2( "prompt_skip_vuze", "aztorplugin.prompt_skip_vuze", true );

			prompt_reset_param = config_model.addActionParameter2( "aztorplugin.ask.clear", "aztorplugin.ask.clear.button" );
			
			prompt_reset_param.addListener(
				new ParameterListener()
				{
					@Override
					public void
					parameterChanged(
						Parameter param ) 
					{
						resetPromptDecisions();
					}
				});
			
			
			final LabelParameter dr_info_param = config_model.addLabelParameter2( "aztorplugin.dr_info" );

			final StringParameter dr_param = config_model.addStringParameter2( "domain_rewrites", "aztorplugin.dr", "" );
			
			try{
				dr_param.setMultiLine( 5 );
			}catch( Throwable e ){
				// remove once released
			}
			
			config_model.createGroup( "aztorplugin.prompt_options", new Parameter[]{ prompt_skip_vuze_param, prompt_reset_param });
			
			final IntParameter control_port_param = config_model.addIntParameter2( "control_port", "aztorplugin.control_port", 0 ); 
			
			if ( control_port_param.getValue() == 0 ){
				
				control_port_param.setValue( allocatePort( CONTROL_PORT_DEFAULT ));
			}
			
			internal_control_port = control_port_param.getValue();
			
			final IntParameter socks_port_param = config_model.addIntParameter2( "socks_port", "aztorplugin.socks_port", 0 ); 
			
			if ( socks_port_param.getValue() == 0 ){
				
				socks_port_param.setValue( allocatePort( SOCKS_PORT_DEFAULT ));
			}
			
			internal_socks_port = socks_port_param.getValue();
			
			services_enable_param 						= config_model.addBooleanParameter2( "services_enable", "aztorplugin.services.enable", false );
			
			services_enable_param.addListener(
				new ParameterListener()
				{	
					@Override
					public void
					parameterChanged(
						Parameter param) 
					{
						config_needs_checking	= true;
					}
				});
			
			final BooleanParameter debug_server_param 	= config_model.addBooleanParameter2( "debug_server", "aztorplugin.debug_server", false );
			
			final BooleanParameter ext_tor_param 		= config_model.addBooleanParameter2( "ext_tor", "aztorplugin.use_external", false );
			
			final StringParameter 	ext_socks_host_param = config_model.addStringParameter2( "ext_socks_host", "aztorplugin.ext_socks_host", "127.0.0.1" ); 
			final IntParameter 		ext_socks_port_param = config_model.addIntParameter2( "ext_socks_port", "aztorplugin.ext_socks_port", 9050 ); 

			ext_socks_host_param.addListener(
					new ParameterListener()
					{	
						@Override
						public void
						parameterChanged(
							Parameter param) 
						{
							active_socks_host = external_socks_host = ext_socks_host_param.getValue();
						}
					});
			
			ext_socks_port_param.addListener(
				new ParameterListener()
				{	
					@Override
					public void
					parameterChanged(
						Parameter param) 
					{
						active_socks_port = external_socks_port = ext_socks_port_param.getValue();
					}
				});
			
			final StringParameter test_url_param	= config_model.addStringParameter2( "test_url", "aztorplugin.test_url", Constants.URL_CLIENT_HOME );
			
			final ActionParameter test_param = config_model.addActionParameter2( "aztorplugin.test_text", "aztorplugin.test_button" );
			
			test_param.addListener(
				new ParameterListener()
				{
					@Override
					public void
					parameterChanged(
						Parameter param ) 
					{
						test_param.setEnabled( false );
						
						new AEThread2( "tester" )
						{
							@Override
							public void
							run()
							{
								List<String>	lines = new ArrayList<String>();
								
								lines.add( "Testing connection via SOCKS proxy on " + active_socks_host + ":" + active_socks_port );
								
								try{
									if ( !external_tor ){
										
										if ( !isConnected()){
											
											lines.add( "Server not running, starting it" );
										}
										
										getConnection( 10*1000, false );
									}
									
									URL original_url = new URL( test_url_param.getValue());
									
									Object[] proxy_details = getActiveProxy( "Test", original_url.getHost(), true, true );
									
									if ( proxy_details == null ){
										
										throw( new Exception( "Failed to setup proxy" ));
									}
									
									Proxy 	proxy 			= (Proxy)proxy_details[0];
									String	temp_host		= (String)proxy_details[1];
									String	rewrite_host	= (String)proxy_details[2];
									
									boolean	ok = false;
									
									try{
										URL url = UrlUtils.setHost( original_url, temp_host );
										
										HttpURLConnection con = (HttpURLConnection)url.openConnection( proxy );
										
										con.setInstanceFollowRedirects( false );
										
										con.setConnectTimeout( 30*1000 );
										con.setReadTimeout( 30*1000 );
									
										con.setRequestProperty( "HOST", rewrite_host + (original_url.getPort()==-1?"":(":" + original_url.getPort())));
										
										if ( con instanceof HttpsURLConnection ){
										
											UrlUtils.HTTPSURLConnectionSNIHack( rewrite_host, (HttpsURLConnection)con );
											
											TrustManager[] tms_delegate = SESecurityManager.getAllTrustingTrustManager();

											SSLContext sc = SSLContext.getInstance("SSL");

											sc.init( null, tms_delegate, RandomUtils.SECURE_RANDOM );

											SSLSocketFactory factory = sc.getSocketFactory();

											((HttpsURLConnection)con).setSSLSocketFactory(factory);
										}
										
										con.getResponseCode();
										
										InputStream is = con.getInputStream();
										
										try{
											lines.add( "Connection succeeded, response=" + con.getResponseCode() + "/" + con.getResponseMessage());
											lines.add( "Headers: " + con.getHeaderFields());
										
											String text = FileUtil.readInputStreamAsString( is, 1024 );
											
											lines.add( "Start of response: " );
											lines.add( text );
											
											ok = true;
																		
										}finally{
											
											try{										
												is.close();
												
											}catch( Throwable e ){
											}
										}
									}finally{
										
										setProxyStatus( proxy, ok );
									}
								}catch( Throwable e ){
									
									lines.add( "Test failed: " + Debug.getNestedExceptionMessage( e ));
	
								}finally{
									
									test_param.setEnabled( true );
								}
								
								String text = "";
								
								for ( String str: lines ){
									text += str + "\r\n";
								}
								
								ui_manager.showTextMessage(
										"aztorplugin.test.msg.title",
										null,
										text );
																	

							}
						}.start();
					}
				});
			
			/*
			final ActionParameter test_http_proxy_param = config_model.addActionParameter2( "", "!Do It!" );

			test_http_proxy_param.setLabelText( "Create HTTP Proxy" );
			
			test_http_proxy_param.addListener(
					new ParameterListener()
					{
						private Proxy	current_proxy;
						
						public void 
						parameterChanged(
							Parameter param ) 
						{
							test_http_proxy_param.setEnabled( false );
							
							new AEThread2( "launcher" )
							{
								public void
								run()
								{
									try{
										if ( current_proxy == null ){
										
											current_proxy = createHTTPPseudoProxy( "test proxy", new URL( "https://client.vuze.com/" ));
										
											System.out.println( "Proxy: " + current_proxy );
											
											if ( current_proxy != null ){
												
												test_http_proxy_param.setLabelText( "Destroy HTTP Proxy" );
											}
										}else{
											
											destroyHTTPPseudoProxy( current_proxy );
											
											current_proxy = null;
											
											test_http_proxy_param.setLabelText( "Create HTTP Proxy" );
											
										}
									}catch( Throwable e ){
										
										e.printStackTrace();
										
										
										
									}finally{
										
										test_http_proxy_param.setEnabled( true );
									}
								}
							}.start();
						}
					});
			*/
							
			LabelParameter browser_info1 = config_model.addLabelParameter2( "aztorplugin.browser.info1" );
			LabelParameter browser_info2 = config_model.addLabelParameter2( "aztorplugin.browser.info2" );
			
			browser_install_param = config_model.addActionParameter2( "aztorplugin.browser.install", "aztorplugin.browser.install.button" );
			
			browser_install_param.addListener(
				new ParameterListener()
				{
					@Override
					public void
					parameterChanged(
						Parameter param ) 
					{
						browser_install_param.setEnabled( false );
						
						new AEThread2( "installer" )
						{
							@Override
							public void
							run()
							{
								boolean	ok = false;
								
								String	msg;
								
								try{
									installBrowserPlugin();
									
									msg = loc_utils.getLocalisedMessageText( "aztorplugin.browser.install.ok.msg" );
									
									ok = true;
									
								}catch( Throwable e ){
									
									msg = loc_utils.getLocalisedMessageText( 
												"aztorplugin.browser.install.fail.msg",
												new String[]{ Debug.getNestedExceptionMessage( e )});
									
								}finally{
									
									if ( !checkBrowserPlugin()){
										
										if ( ok ){
										
												// something weird happened
											
											ok = false;
											
											msg = loc_utils.getLocalisedMessageText( 
													"aztorplugin.browser.install.fail.msg",
													new String[]{ "Unexpected error, check logs" });
										}
									}
								}
								
								ui_manager.showMessageBox(
									ok?"aztorplugin.browser.install.ok":"aztorplugin.browser.install.fail",
									"!" + msg + "!",
									UIManagerEvent.MT_OK );
							}
						}.start();
					}
				});
			
			
			browser_launch_param = config_model.addActionParameter2( "aztorplugin.browser.launch", "aztorplugin.browser.launch.button" );
			
			browser_launch_param.addListener(
				new ParameterListener()
				{
					@Override
					public void
					parameterChanged(
						Parameter param ) 
					{
						browser_launch_param.setEnabled( false );
						
						new AEThread2( "launcher" )
						{
							@Override
							public void
							run()
							{
								final AESemaphore sem = new AESemaphore( "launch:wait" );
								
								try{
									PluginInterface pi = plugin_interface.getPluginManager().getPluginInterfaceByID( BROWSER_PLUGIN_ID );

									if ( pi == null ){
										
										throw( new Exception( "Tor Browser plugin not found" ));
									}
									
									pi.getIPC().invoke(
										"launchURL",
										new Object[]{ 
											new URL( "https://check.torproject.org/" ), 
											true,
											new Runnable()
											{
												@Override
												public void
												run()
												{
													sem.release();
												}
											}
										});
									
									sem.reserve();
									
								}catch( Throwable e ){
									
									e.printStackTrace();
									
									String msg = loc_utils.getLocalisedMessageText( 
											"aztorplugin.browser.launch.fail.msg",
											new String[]{ Debug.getNestedExceptionMessage(e)});
									
									ui_manager.showMessageBox(
											"aztorplugin.browser.launch.fail",
											"!" + msg + "!",
											UIManagerEvent.MT_OK );
									
								}finally{
									
									browser_launch_param.setEnabled( true );
								}
							}
						}.start();
					}
				});
			
			config_model.createGroup( "aztorplugin.browser.options", new Parameter[]{ browser_info1, browser_info2, browser_install_param, browser_launch_param });
			
			ParameterListener enabler_listener =
				new ParameterListener()
				{
					@Override
					public void
					parameterChanged(
						Parameter param )
					{
						plugin_enabled 		= enable_param.getValue();
						external_tor		= ext_tor_param.getValue();
						start_on_demand		= start_on_demand_param.getValue();
						stop_on_idle		= stop_on_idle_param.getValue();
						prompt_on_use		= prompt_on_use_param.getValue();
						prompt_skip_vuze	= prompt_skip_vuze_param.getValue();
						debug_server 		= debug_server_param.getValue();
						
						if ( plugin_enabled ){
							
							if ( external_tor ){
								
								active_socks_host	= external_socks_host 	= ext_socks_host_param.getValue();
								active_socks_port 	= external_socks_port	= ext_socks_port_param.getValue();
								
							}else{
								
								active_socks_host	= internal_socks_host;
								active_socks_port 	= internal_socks_port;
							}
						}else{
							
							active_socks_host	= "127.0.0.1";
							active_socks_port 	= 0;
						}
						
						start_on_demand_param.setEnabled( plugin_enabled && !external_tor );
						stop_on_idle_param.setEnabled( plugin_enabled && !external_tor && start_on_demand );
						
						prompt_on_use_param.setEnabled( plugin_enabled );
						prompt_skip_vuze_param.setEnabled( plugin_enabled && prompt_on_use );
						prompt_reset_param.setEnabled( plugin_enabled && prompt_on_use && prompt_decisions.size() > 0 );
						
						dr_info_param.setEnabled( plugin_enabled );
						dr_param.setEnabled( plugin_enabled );
						
						String 	domain_rewrites = dr_param.getValue();
						
						synchronized( TorPlugin.this ){
							
							domain_rewrite_map.clear();
							
							String[] lines = domain_rewrites.split( "\n" );
							
							for ( String line: lines ){
								
								line = line.trim();
								
								if ( line.length() > 0 ){
									
									String[] bits = line.split( "=" );
									
									if ( bits.length != 2 ){
										
										log( "Invalid domain rewrite entry: " + line );
										
									}else{
										
										String from = bits[0].trim();
										String to	= bits[1].trim();
										
										if ( ! ( from.contains( "." ) && to.contains( "." ))){
											
											log( "Invalid domain rewrite entry: " + line );
											
										}else{
											
											domain_rewrite_map.put( from, to );
										}
									}
								}
							}
						}
						
						control_port_param.setEnabled( plugin_enabled && !external_tor );
						socks_port_param.setEnabled( plugin_enabled && !external_tor );
						services_enable_param.setEnabled( plugin_enabled && !external_tor );
						
						debug_server_param.setEnabled( plugin_enabled && !external_tor );
						
						ext_tor_param.setEnabled( plugin_enabled );
						ext_socks_host_param.setEnabled( plugin_enabled && external_tor );
						ext_socks_port_param.setEnabled( plugin_enabled && external_tor );
						
						test_url_param.setEnabled( plugin_enabled );
						test_param.setEnabled( plugin_enabled );
						
						if ( param != null ){
						
								// don't run this initially, it will be run on plugin init-complete
							
							checkBrowserPlugin();
						}
						
						if ( param != null ){
						
							logPromptDecisions();
						}
					}
				};
				
			enable_param.addListener( enabler_listener );
			start_on_demand_param.addListener( enabler_listener );
			stop_on_idle_param.addListener( enabler_listener );
			prompt_on_use_param.addListener( enabler_listener );
			prompt_skip_vuze_param.addListener( enabler_listener );
			dr_param.addListener( enabler_listener );
			debug_server_param.addListener( enabler_listener );
			ext_tor_param.addListener( enabler_listener );
			
			enabler_listener.parameterChanged( null );
			
			log( "Plugin enabled=" + plugin_enabled + ", server=" + (external_tor?"external":"internal") + ", socks port=" + active_socks_port );
			log( "Domain rewrites: " + domain_rewrite_map );
			
			readPromptDecisions();

			File plugin_install_dir = new File( pi.getPluginDirectoryName());

			// Ideally we'd do what we used to:
			//     config_file = pif.getPluginconfig().getPluginUserFile( "config.txt" );
			// so we always get a writable location even if plugin installed into shared space. However,
			// the way things currently work we have to have the executable in the same location so for 
			// the moment I'm fixing by assuming we can write to wherever the plugin is installed.
			// This issue came to light on Linux where the bundled plugins are installed into the
			// shared plugin location...
			
			config_file = new File( plugin_install_dir, "config.txt" );
			
			plugin_dir 	= config_file.getParentFile();
			
				// hack for linux and OSX - currently bundle both 32+64 bit versions into one plugin and then
				// copy the required files into place...
			
			if ( Constants.isLinux || Constants.isOSX ){
				
				File	arch_dir;
				
				if ( Constants.isLinux ){
					
					arch_dir = new File( plugin_dir, Constants.is64Bit?"linux64":"linux32" );
					
				}else{
					
					arch_dir = new File( plugin_dir, Constants.is64Bit?"osx64":"osx32" );
				}
				
				File[] files = arch_dir.listFiles();
				
				if ( files != null ){
					
					for ( File f: files ){
						
							// +x permissions will be fixed up later
						
						File target = new File( plugin_dir, f.getName());
						
						if ( !FileUtil.copyFile( f, target )){
							
								// continue, maybe things will work out
							
							Debug.out( "Failed to copy file from " + f + " to " + target );
						}
					}
				}
			}
			
			data_dir 		= new File( plugin_dir, "data" );
			services_dir 	= new File( plugin_dir, "services" );
			
			services_dir.mkdirs();
			
				// see if server already running, unlikely due to the way we arrange for it to die if we do but you never know
			
			ControlConnection control = new ControlConnection( null, data_dir, internal_control_port, internal_socks_port );
		
			if ( control.connect()){
			
				log( "Found an existing server instance - closing it" );
			
				control.shutdown( true );
			}
		
			checkConfig();
			
			pi.addListener(
				new PluginAdapter()
				{
					@Override
					public void
					initializationComplete()
					{
						init_time = SystemTime.getMonotonousTime();
						
						init_sem.releaseForever();
						
						if ( plugin_enabled ){
							
							init();
						}
					}
					
					@Override
					public void
					closedownInitiated()
					{
						init_sem.releaseForever();
						
						synchronized( TorPlugin.this ){
							
							unloaded = true;
							
							if ( current_connection != null ){
								
								current_connection.shutdown( false );
								
								current_connection = null;
							}
						}	
					}
				});
			
			pi.getUIManager().addUIListener(
				new UIManagerListener()
				{
					@Override
					public void
					UIAttached(
						final UIInstance		instance )
					{
						if ( instance.getUIType().equals(UIInstance.UIT_SWT) ){
								
							try{
								synchronized( TorPlugin.this ){
									
									if ( unloaded ){
										
										return;
									}
								
									try{
										plugin_ui = 
											(TorPluginUI)Class.forName( "org.parg.azureus.plugins.networks.tor.swt.TorPluginUISWT").getConstructor(
													new Class[]{ TorPlugin.class } ).newInstance( new Object[]{ TorPlugin.this } );
										
									}catch( Throwable e ){
									
										Debug.out( e );
									}
								}
							}finally{
								
								ui_attach_sem.releaseForever();
							}
						}
					}
					
					@Override
					public void
					UIDetached(
						UIInstance		instance )
					{
						if ( instance.getUIType().equals(UIInstance.UIT_SWT) && plugin_ui != null ) {
							plugin_ui.destroy();
							plugin_ui = null;
						}
					}

				});
			
			pi.addListener(
				new PluginAdapter()
				{
					@Override
					public void
					initializationComplete() 
					{
						checkBrowserPlugin();
					}
				});
		}catch( Throwable e ){
				
			init_time = SystemTime.getMonotonousTime();

			synchronized( TorPlugin.this ){
				
				unloaded = true;
				
				init_sem.releaseForever();
			}
			
			Debug.out( e );
		}
	}

	private void
	checkConfig()
	{
		if ( !config_needs_checking ){
			
			return;
		}
		
		config_needs_checking = false;
		
		boolean	write_config = false;
		
		List<String>	required_config_lines = new ArrayList<String>();
		
		required_config_lines.add( "SocksPort 127.0.0.1:" + internal_socks_port );
		required_config_lines.add( "ControlPort 127.0.0.1:" + internal_control_port );
		required_config_lines.add( "CookieAuthentication 1" );
		required_config_lines.add( "DataDirectory ." + File.separator + data_dir.getName());
		
		LinkedHashSet<String>	required_hs		= new LinkedHashSet<String>();

		if ( services_enable_param.getValue()){
		
			File[] files = services_dir.listFiles();
			
			if ( files != null ){
				
				for ( File f: files ){
					
					if ( f.getName().endsWith( ".txt" )){
						
						try{
							required_hs.addAll( readFileAsStrings( f ));
							
						}catch( Throwable e ){
						}
					}
				}
			}
		}
		
		if ( config_file.exists()){
			
			LineNumberReader lnr = null;
			
			try{
				lnr = new LineNumberReader( new InputStreamReader( new FileInputStream( config_file )));
				
				Set<String>	keys = new HashSet<String>();
				
				for ( String str: required_config_lines ){
					
					str = str.substring( 0, str.indexOf(' ' ));
					
					keys.add( str );
				}
								
				Set<String>		missing_lines 	= new LinkedHashSet<String>( required_config_lines );	
				Set<String> 	removed_hs		= new HashSet<String>();
				List<String> 	config_lines 	= new ArrayList<String>();
				
				while( true ){
					
					String line = lnr.readLine();
					
					if ( line == null ){
						
						break;
					}
					
					line = line.trim();
					
					if ( line.startsWith( "HiddenService" )){
						
						removed_hs.add( line );
						
						continue;
					}
					
					boolean	ok = true;
					
					if ( !missing_lines.remove( line )){
						
						int	pos = line.indexOf( ' ' );
						
						if ( pos > 0 ){
							
							String l_key = line.substring( 0, pos );
							
							if ( keys.contains( l_key )){
								
								ok = false;
							}
						}
					}
					
					if ( ok ){
					
						config_lines.add( line );
					}
				}
				
				if ( missing_lines.size() > 0 ){
					
					config_lines.addAll( missing_lines );
					
					required_config_lines = config_lines;
					
					write_config = true;
				}
				
				if ( !required_hs.equals( removed_hs )){
					
					write_config = true;
				}

			}catch( Throwable e ){
				
				write_config = true;
				
			}finally{
				
				try{
					lnr.close();
					
				}catch( Throwable e ){
				}
			}
		}else{
			
			write_config = true;
		}
		
		if ( write_config ){
			
			required_config_lines.addAll( required_hs );
			
			try{
					// appears that the local file system encoding needs to be used
				
				PrintWriter pw = new PrintWriter( new OutputStreamWriter( new FileOutputStream( config_file )));
				
				for ( String line: required_config_lines ){
					
					pw.println( line );
				}
				
				pw.close();
				
			}catch( Throwable e ){
				
				Debug.out( e );
			}
		}		
	}
	
	private void
	setUnloadable(
		boolean	b )
	{
		PluginInterface pi = plugin_interface;
		
		if ( pi != null ){
			
			pi.getPluginProperties().put( "plugin.unload.disabled", String.valueOf( !b ));
		}
	}
	
	private boolean
	isBrowserPluginInstalled()
	{
		PluginInterface pi = plugin_interface.getPluginManager().getPluginInterfaceByID( BROWSER_PLUGIN_ID );
		
		return( pi != null ); // && pif.getPluginState().isOperational());
	}
	
	private boolean
	checkBrowserPlugin()
	{
		if ( browser_install_param == null ){
			
			return( false );
		}
		
		boolean installed = isBrowserPluginInstalled();
					
		browser_install_param.setEnabled( plugin_enabled && !installed );
		browser_launch_param.setEnabled( plugin_enabled && installed );
		
		return( installed );
	}
	
	private void
	installBrowserPlugin()
	
		throws Throwable
	{
		UIFunctions uif = UIFunctionsManager.getUIFunctions();
		
		if ( uif == null ){
			
			throw( new Exception( "UIFunctions unavailable - can't install plugin" ));
		}
		
		
		final AESemaphore sem = new AESemaphore( "installer_wait" );
		
		final Throwable[] error = { null };
		
		uif.installPlugin(
				BROWSER_PLUGIN_ID,
				"aztorplugin.browser.install",
				new UIFunctions.actionListener()
				{
					@Override
					public void
					actionComplete(
						Object		result )
					{
						try{
							if ( result instanceof Boolean ){
								
							}else{
								
								error[0] = (Throwable)result;
							}
						}finally{
							
							sem.release();
						}
					}
				});
		
		sem.reserve();
		
		if ( error[0] instanceof Throwable ){
			
			throw((Throwable)error[0] );
		}
	}
	
	private int
	allocatePort(
		int		def )
	{
		for ( int i=0;i<32;i++){
			
			int port = 20000 + RandomUtils.nextInt( 20000 );
			
			ServerSocketChannel ssc = null;

			try{	
				ssc = ServerSocketChannel.open();
				
				ssc.socket().bind( new InetSocketAddress( "127.0.0.1", port ));
				
				return( port );
				
			}catch( Throwable e ){
				
			}finally{
				
				if ( ssc != null ){
					
					try{
						ssc.close();
						
					}catch( Throwable e ){
						
					}
				}
			}
		}
		
		return( def );
	}
	
	private void
	init()
	{
			// see if we should connect at start of day
		
		if ( plugin_enabled && !( unloaded || external_tor || ( start_on_demand && !services_enable_param.getValue()))){
			
			prepareConnection( "Startup" );
		}
		
		SimpleTimer.addPeriodicEvent(
			"TP:checker",
			30*1000,
			new TimerEventPerformer()
			{	
				private String	last_stats = "";
				
				@Override
				public void
				perform(
					TimerEvent event ) 
				{
					if ( proxy_request_count.get() > 0 || http_proxy_map.size() > 0 ){
						
						String stats = "Requests=" + proxy_request_count.get() + ", ok=" + proxy_request_ok.get() + ", failed=" + proxy_request_failed.get();
						
						List<TorPluginHTTPProxy>	proxies;
						
						synchronized( TorPlugin.this ){
							
							proxies = new ArrayList<TorPluginHTTPProxy>( http_proxy_map.values());
						}
						
						if ( proxies.size() > 0 ){
							
							stats += "; HTTP proxies=" +  proxies.size();
							
							for ( TorPluginHTTPProxy proxy: proxies ){
								
								stats += " {" + proxy.getString() + "}";
							}
						}
						
						if ( !stats.equals( last_stats )){
							
							last_stats = stats;
							
							log( stats );
						}
					}
					
					checkServerStatus();
				}
			});
	}
	
	private AESemaphore	server_check_sem = new AESemaphore( "checksem", 1 );
	
	private void
	checkServerStatus()
	{
		try{
			server_check_sem.reserve();
		
			boolean	should_be_disconnected 	= false;
			boolean	should_be_connected 	= false;
			boolean	should_be_reloaded	 	= false;
			
			synchronized( TorPlugin.this ){
				
				if ( plugin_enabled && !( unloaded || external_tor )){
					
					if ( start_on_demand && !services_enable_param.getValue()){
						
						if ( stop_on_idle ){
							
							if ( http_proxy_map.size() == 0 ){
							
								should_be_disconnected = SystemTime.getMonotonousTime() - last_use_time > STOP_ON_IDLE_TIME;
							}
						}
					}else{
							// should always be running
													
						if ( !isConnected()){
						
							should_be_connected = true;
							
						}else{
							
							if ( config_needs_checking ){
								
								should_be_reloaded = true;
								
									// next time we come through here we'll restart the server
									// and that will clear the 'needs checking' flag
							}
						}
					}
				}else{
					
					should_be_disconnected = true;
				}
				
				if ( proxy_map.size() > 0 ){
					
					long now = SystemTime.getMonotonousTime();
					
					Iterator<ProxyMapEntry>	it = proxy_map.values().iterator();
					
					while( it.hasNext()){
						
						ProxyMapEntry entry = it.next();
						
						if ( now - entry.getCreateTime() > 10*60*1000 ){
							
							it.remove();
							
							Debug.out( "Removed orphaned proxy entry for " + entry.getHost());
						}
					}
				}
			}
			
			if ( should_be_reloaded ){
				
				closeConnection( "Reloading configuration" );
	
			}else if ( should_be_disconnected ){
				
				closeConnection( "Close on idle" );
				
			}else if ( should_be_connected ){
				
				prepareConnection( "Start on demand disabled" );
			}
		}finally{
			
			server_check_sem.release();
		}
	}
	
	private Process
	startServer()
	{
		log( "Starting server" );
		
		File exe_file = new File( plugin_dir, Constants.isWindows?"BiglyBTTor.exe":(Constants.isOSX?"BiglyBTTor":"tor" ));
		
		checkPermissions( exe_file );
		
		checkConfig();
		
		int	pid = getPID();
		
		try{
			List<String>	cmd_list = new ArrayList<String>();
			
			cmd_list.add( exe_file.getAbsolutePath());
			cmd_list.add( "-f" );
			cmd_list.add( config_file.getName());
			
			if ( pid >= 0 ){
				
				cmd_list.add( "__OwningControllerProcess" );
				cmd_list.add( String.valueOf( pid ));
			}
			
			ProcessBuilder pb = GeneralUtils.createProcessBuilder( plugin_dir, cmd_list.toArray(new String[cmd_list.size()]), null );
		
			if ( Constants.isOSX ){
				
				pb.environment().put(
						"DYLD_LIBRARY_PATH",
						exe_file.getParentFile().getAbsolutePath());
				
			}else if ( Constants.isLinux ){
				
				pb.environment().put(
						"LD_LIBRARY_PATH",
						exe_file.getParentFile().getAbsolutePath());
			}
			
			final Process proc = pb.start();
			
			new AEThread2( "procread" )
			{
				@Override
				public void
				run()
				{
					try{
						LineNumberReader lnr = new LineNumberReader( new InputStreamReader( proc.getInputStream()));
						
						while( true ){
						
							String line = lnr.readLine();
							
							if ( line == null ){
								
								break;
							}
						
							if ( debug_server ){
							
								log( "> " + line );
							}
						}
					}catch( Throwable e ){
						
					}
				}
			}.start();
				
			new AEThread2( "procread" )
			{
				@Override
				public void
				run()
				{
					try{
						LineNumberReader lnr = new LineNumberReader( new InputStreamReader( proc.getErrorStream()));
						
						while( true ){
						
							String line = lnr.readLine();
							
							if ( line == null ){
								
								break;
							}
						
							log( "* " + line );
						}
					}catch( Throwable e ){
						
					}
				}
			}.start();
			
			log( "Server started" );
			
			return( proc );
			
		}catch( Throwable e ){
		
			log( "Server start failed: " + Debug.getNestedExceptionMessage( e ));
			
			Debug.out( e );
			
			return( null );
		}
	}
	
	private boolean
	isConnected()
	{
		synchronized( this ){
			
			return( current_connection != null && current_connection.isConnected());
		}
	}
	
	private boolean
	isConnectedOrConnecting()
	{	
		synchronized( this ){
		
			return( isConnected() || connection_sem != null );
		}
	}
	
	private void
	closeConnection(
		String	reason )
	{
		synchronized( this ){
			
			if ( current_connection != null ){
						
				if ( current_connection.isConnected()){
					
					current_connection.close( "Close requested: " + reason );
				}
				
				current_connection = null;
			}
			
			last_connect_time = 0;		// explicit close so reset connect rate limiter
		}
	}
		
	private void
	prepareConnection(
		final String	reason )
	{
		if ( isConnectedOrConnecting()){
			
			return;
		}
		
		new AEThread2( "init" )
		{
			@Override
			public void
			run()
			{
				
				if ( !isConnectedOrConnecting()){
				
					log( "Preparing connection: " + reason );
					
					getConnection( 0, true );
				}
			}
		}.start();
	}
	
	private ControlConnection
	getConnection(
		int			max_wait_millis,
		boolean		async )
	{
		if ( !init_sem.reserve( max_wait_millis )){
			
			return( null );
		}
		
		final AESemaphore sem;
		
		synchronized( this ){
		
			if ( current_connection != null ){
				
				if ( current_connection.isConnected()){
					
					return( current_connection );
					
				}else{
					
					current_connection = null;
				}
			}
			
			if ( unloaded ){
					
				return( null );
			}
				
			if ( connection_sem == null ){
				
				final long now = SystemTime.getMonotonousTime();
				
				if ( last_connect_time != 0 && now - last_connect_time < MIN_RECONNECT_TIME ){
					
					return( null );
				}
				
				sem = connection_sem = new AESemaphore( "ConWait" );
				
				last_connect_time  = now;
				
					// kick off async con
				
				new AEThread2( "ControlPortCon")
				{
					@Override
					public void
					run()
					{		
						try{
							Process process = startServer();
							
							if ( process != null ){
								
								log( "Waiting for server to initialise" );

								while( !unloaded ){
																	
									ControlConnection control = new ControlConnection( process, data_dir, internal_control_port, internal_socks_port );
								
									if ( control.connect()){
										
										log( "Server initialised" );
										
										current_connection = control;
										
										last_use_time	= SystemTime.getMonotonousTime();
										
										break;
										
									}else{
										
										control.close( null );
									}
									
									if ( SystemTime.getMonotonousTime() - now > MAX_CONNECT_WAIT_TIME ){
										
										log( "Server failed to initialise, abandoning" );
										
										break;
										
									}else{
										
										try{
											Thread.sleep( 1000 );
											
										}catch( Throwable f ){
											
										}
									}
								}
							}
						}finally{
							
							synchronized( TorPlugin.this ){
								
								connection_sem = null;
								
								sem.releaseForever();
							}
						}
					}
				}.start();
				
			}else{
				
				sem = connection_sem;
			}
		}
		
		if ( async ){
			
			return( null );
			
		}else{
			
			sem.reserve( max_wait_millis );
			
			synchronized( this ){
	
				return( current_connection );
			}
		}
	}
	
	private String
	findCommand(
		String	name )
	{
		final String[]  locations = { "/bin", "/usr/bin" };

		for ( String s: locations ){

			File f = new File( s, name );

			if ( f.exists() && f.canRead()){

				return( f.getAbsolutePath());
			}
		}

		return( name );
	}
	
	private void
	checkPermissions(
		File		exe )
	{
		if ( Constants.isOSX || Constants.isLinux ){

			synchronized( this ){
				
				if ( permissions_checked ){
					
					return;
				}
				
				permissions_checked = true;
			}
			
			try{
				String chmod = findCommand( "chmod" );
				
				if ( chmod != null ){
								
					Runtime.getRuntime().exec(
						new String[]{
							chmod,
							"+x",
							exe.getAbsolutePath()
						}).waitFor();
					
					File[] files = exe.getParentFile().listFiles();
					
					for ( File file: files ){
						
						String name = file.getName();
								
						if ( 	name.endsWith( ".dylib" ) 	||
								name.endsWith( ".so" )		||
								name.contains( ".so." )){
							
							Runtime.getRuntime().exec(
									new String[]{
										chmod,
										"+x",
										file.getAbsolutePath()
									}).waitFor();
						}
					}
				}
			}catch( Throwable e ){
				
				Debug.out( e );
			}
		}
	}
	
	private int
	getPID()
	{
		try{
			RuntimeMXBean runtime_bean =	java.lang.management.ManagementFactory.getRuntimeMXBean();
			
			Field jvm_field = runtime_bean.getClass().getDeclaredField( "jvm" );
			
			jvm_field.setAccessible( true );
			
			Object jvm = jvm_field.get( runtime_bean );
			
			Method pid_method = jvm.getClass().getDeclaredMethod( "getProcessId" );
			
			pid_method.setAccessible( true );

			int pid = (Integer)pid_method.invoke( jvm );
			
			return( pid );
			
		}catch( Throwable e ){
			
			return( -1 );
		}
	}
	
	private void
	log(
		String		str )
	{
		if ( log != null ){
			
			log.log( str );
		}
	}
	
	private void
	log(
		String		str,
		Throwable	e )
	{
		if ( log != null ){
			
			log.log( str, e );
		}
	}
	
	@Override
	public void
	unload()
	{
		synchronized( this ){
			
			unloaded = true;
			
			if ( current_connection != null ){
				
				current_connection.shutdown( false );
				
				current_connection = null;
			}
			
			if ( plugin_ui != null ){
				
				plugin_ui.destroy();
				
				plugin_ui = null;
			}
			
			if ( socks_proxy != null ){
				
				socks_proxy.destroy();
				
				socks_proxy = null;
			}
			
			if ( filtering_proxy != null ){
				
				filtering_proxy.destroy();
				
				filtering_proxy = null;
			}
		}
		
		if ( config_model != null ){
			
			config_model.destroy();
			
			config_model = null;
		}
		
		if ( view_model != null ){
			
			view_model.destroy();
		}
	}
	
	private void
	logPromptDecisions()
	{
		String	msg;
		
		if ( prompt_on_use ){
		
			msg = (prompt_skip_vuze?"Allow Vuze; ":"") + prompt_decisions;
			
		}else{
			
			msg = "Disabled";
		}
		
		if ( !last_decision_log.equals( msg )){
			
			last_decision_log = msg;
			
			log( "Prompt decisions: " + msg );
		}
	}
	
	private void
	resetPromptDecisions()
	{
		synchronized( this ){
			
			if ( prompt_decisions.size() > 0 ){
			
				prompt_decisions.clear();
			
				writePromptDecisions();
			}
		}
	}
	
	private void
	readPromptDecisions()
	{
		synchronized( this ){
			
			String	str = plugin_config.getPluginStringParameter( "prompt.decisions", "" );
			
			String[] bits = str.split( "," );
			
			prompt_decisions.clear();
			
			for ( String bit: bits ){
				
				bit = bit.trim();
				
				if ( bit.length() > 0 ){
				
					prompt_decisions.add( bit );
				}
			}
			
			prompt_reset_param.setEnabled( prompt_decisions.size() > 0);
			
			logPromptDecisions();
		}
	}
	
	private void
	writePromptDecisions()
	{
		synchronized( this ){
			
			String str = "";
			
			for ( String s: prompt_decisions ){
				
				str += (str.length()==0?"":",") + s;
			}
			
			prompt_reset_param.setEnabled( prompt_decisions.size() > 0);

			plugin_config.setPluginParameter( "prompt.decisions", str );
			
			try{
				plugin_config.save();
				
			}catch( Throwable e ){
			}
			
			logPromptDecisions();
		}
	}
	
		/**
		 * @param host
		 * @return 0 = no prompt, do it; 1 = prompt; 2 = don't do it
		 */

	private int
	getPromptDecision(
		String		host )
	{
		synchronized( this ){
			
			if ( prompt_on_use ){
	
				if ( prompt_skip_vuze && Constants.isAppDomain( host )){
				
					return( 0 );
					
				}else{
				
					if ( prompt_decisions.contains( "^*" )){
					
						return( 2 );
						
					}else if ( prompt_decisions.contains( host )){
						
						return( 0 );
					
					}else if ( prompt_decisions.contains( "^" + host )){
						
						return( 2 );
					}
					
					
					String[] bits = host.split( "\\." );
					
					int	bits_num = bits.length;
					
					if ( bits_num > 2 ){
						
						String wild =  "*." + bits[bits_num-2] + "." + bits[bits_num-1];
						
						if ( prompt_decisions.contains( wild )){
							
							return( 0 );
						
						}else if ( prompt_decisions.contains( "^" + wild )){
							
							return( 2 );
						}
					}
				}
				
				return( 1 );
				
			}else{
				
				return( 0 );
			}
		}
	}
	
	private void
	setPromptDecision(
		String		host,
		boolean		accepted )
	{
		boolean	all_domains = host.equals( "*" );
		
		synchronized( this ){
			
			if ( all_domains ){
				
				if ( accepted ){
					
					prompt_on_use_param.setValue( false );
					
					resetPromptDecisions();
					
				}else{
					
					prompt_decisions.clear();
					
					prompt_decisions.add( "^*" );
					
					writePromptDecisions();
				}
			}else{
				
				if ( host.startsWith( "*" )){
					
					String term = host.substring( 1 );
					
					Iterator<String> it = prompt_decisions.iterator();
					
					while( it.hasNext()){
						
						String entry = it.next();
						
						if ( entry.endsWith( term )){
							
							it.remove();
						}
					}
				}
				
				prompt_decisions.add( accepted?host:("^"+host));	
				
				writePromptDecisions();
			}
		}
	}
	
	private AsyncDispatcher prompt_dispatcher = new AsyncDispatcher();
	
	private boolean
	promptUser(
		final String		reason,
		final String		host )
	{	
			// maintain a queue of prompt requests so things don't get out of control
			// timeout callers to prevent hanging the core if user isn't present
		
		final AESemaphore sem = new AESemaphore( "promptAsync" );
		
		final boolean[] result = { false };
		
		final Thread calling_thread = Thread.currentThread();
		
		final boolean[] bad_thread = { false };
		
		prompt_dispatcher.dispatch(
			new AERunnable() 
			{
				@Override
				public void
				runSupport() 
				{
					try{
						boolean	wait_for_ui = false;
						
						synchronized( TorPlugin.this ){
							
							if ( unloaded ){
								
								return;
							}
							
							if ( !ui_attach_sem.isReleasedForever()){
								
								if ( init_time != 0 && SystemTime.getMonotonousTime() - init_time > 60*1000 ){
									
									return;
								}
							}
							
							wait_for_ui = plugin_ui == null;
						}
						
						if ( wait_for_ui ){
							
							ui_attach_sem.reserve( 30*1000 );
							
							if ( plugin_ui == null ){
								
								return;
							}
						}
						
						if ( plugin_ui.isUIThread( calling_thread )){
							
							bad_thread[0] = true;
							
							return;
						}

						int recheck_decision = getPromptDecision( host );
						
						if ( recheck_decision == 0 ){
							
							result[0] = true;
							
						}else if ( recheck_decision == 1 ){
							
								// we're prompting the user, let's assume they're going to go ahead so
								// we should warm up the server if not yet up
							
							if ( !external_tor ){
								
								prepareConnection( "About to prompt" );
							}
														
							PromptResponse response = plugin_ui.promptForHost( reason, host );
							
							boolean	accepted = response.getAccepted();
		
							String remembered = response.getRemembered();
							
							if ( remembered != null ){
								
								setPromptDecision( remembered, accepted );
							}				
							
							result[0] = accepted;
						}
					}finally{
						
						sem.release();
					}
				}
			});
		
		sem.reserve( 60*1000 );
			
		if ( bad_thread[0] ){
			
			Debug.out( "Invocation on UI thread not supported" );
		}
		
		return( result[0] );
	}
	
	private boolean
	isHostAccepted(
		String		reason,
		String		host )
	{
			// filter out any ridiculous domain names (e.g. an i2p destination missing the .i2p for some reason...)
		
		if ( host.indexOf( '.' ) == -1 ){
			
			return( false );
		}
		
		if ( host.equals( "127.0.0.1" )){

			return( false );
		}
		
		String	lc_host = host.toLowerCase( Locale.US );
		
		if ( lc_host.endsWith( ".i2p" )){
			
			return( false );
		}
		
		if ( !checkProxyHistoryOK( host )){
			
			return( false );
		}
		
		if ( lc_host.endsWith( ".onion" )){

			return( true );	
		}
		
		int decision = getPromptDecision( host );
		
		if ( decision == 0 ){
			
			return( true );
			
		}else if ( decision == 1 ){
			
			return( promptUser( reason, host ));
			
		}else{
				
			return( false );
		}
	}
	
	private String
	rewriteHost(
		String		host,
		boolean		do_onions )
	{
		if ( do_onions ){
			
			if ( host.equals( "version.biglybt.com" )){
				
				return( "7zq2rhfhvgcv7pkt.onion" );
				
			}else if ( host.equals( "plugins.biglybt.com" )){
	
				return( "ezhdqq3jjpsqg65l.onion" );
			}
		}
					
		String[]	bits = host.split( "\\." );
		
		synchronized( this ){
		
			for ( int i=bits.length-1; i >= 0; i-- ){
				
				String sub_host = "";
				
				for ( int j=i; j<=bits.length-1; j++ ){
					
					sub_host += (sub_host.length()==0?"":".") + bits[j];
				}
			
				String target = domain_rewrite_map.get( sub_host );
				
				if ( target != null ){
					
					if ( i > 0 ){
						
						String prefix = "";
						
						for ( int j=0;j<i;j++){
							
							prefix += (j==0?"":".") + bits[j];
						}
						
						target = prefix + "." + target;
					}
											
					// log( "Rewriting " + host + " to " + target );
					
					return( target );
				}
			}
		}
		
		return( host );
	}
	
	private String
	getActiveSocksHost()
	{
		if ( !external_tor ){
			
			getConnection( 30*1000, false );
		}
		
		return( active_socks_host );
	}
	
	private int
	getActiveSocksPort()
	{
		if ( !external_tor ){
			
			getConnection( 30*1000, false );
		}
		
		return( active_socks_port );
	}
	
	private Object[]
	getActiveProxy(
		String		reason,
		String		host,
		boolean		requires_intermediate,
		boolean		force )
	{
		if ( !plugin_enabled || unloaded ){
			
			return( null );
		}
		
		if ( !force ){

			if ( !isHostAccepted( reason, host )){
						
				return( null );
			}
		}
			
		String	socks_host;
		int		socks_port;
		
		if ( external_tor ){

			socks_host	= external_socks_host;
			socks_port 	= active_socks_port;
			
		}else{
			
			ControlConnection con = getConnection( 30*1000, false );
	
			if ( con == null ){
		
				return( null );
			}
			
			socks_host	= internal_socks_host;
			socks_port 	= con.getSOCKSPort();
		}
		
		if ( requires_intermediate ){
		
			String 	intermediate_host;
			int		intermediate_port;
	
			synchronized( this ){
				
				if ( socks_proxy == null ){
					
					try{
						if ( unloaded ){
							
							return( null );
						}
						
						socks_proxy = new SOCKSProxy( 0, false, reason );
					
					}catch( Throwable e ){
					
						return( null );
					}
				}
				
				intermediate_port = socks_proxy.getPort();
				
				while( true ){
					
					int	address = 0x0a000000 + RandomUtils.nextInt( 0x00ffffff );
									
					intermediate_host = PRHelpers.intToAddress( address );
					
					if ( !intermediate_host_map.containsKey( intermediate_host )){
						
						intermediate_host_map.put( intermediate_host, new Object[]{ host, socks_host, socks_port });
						
						break;
					}
				}
			}
		
			Proxy proxy = new Proxy( Proxy.Type.SOCKS, new InetSocketAddress( "127.0.0.1", intermediate_port ));	
			
			synchronized( this ){
						
				proxy_map.put( proxy, new ProxyMapEntry( host, intermediate_host ));
			}
		
			last_use_time	= SystemTime.getMonotonousTime();
	
			proxy_request_count.incrementAndGet();
					
			return( new Object[]{ proxy, intermediate_host, rewriteHost( host, false ) });
			
		}else{
			
			Proxy proxy = new Proxy( Proxy.Type.SOCKS, new InetSocketAddress( socks_host, socks_port ));	
			
			synchronized( this ){
						
				proxy_map.put( proxy, new ProxyMapEntry( host, null ));
			}
		
			last_use_time	= SystemTime.getMonotonousTime();
	
			proxy_request_count.incrementAndGet();
					
			return( new Object[]{ proxy, rewriteHost( host, true ) });
		}
	}
	
	private boolean
	checkProxyHistoryOK(
		String		host )
	{
		synchronized( this ){

			ProxyHistory history = proxy_history.get( host );

			if ( history == null ){
				
				history = new ProxyHistory( host );
				
				proxy_history.put( host, history );
			}
			
			return( history.canConnect());
		}
	}
	
	private void
	updateProxyHistory(
		String		host,
		boolean		ok )
	{
		synchronized( this ){
			
			ProxyHistory history = proxy_history.get( host );
			
			if ( history == null ){
				
				history = new ProxyHistory( host );
				
				proxy_history.put( host, history );
			}
			
			history.setOutcome( ok );
		}
	}
	
		// IPC stuff
	
	public Map<String,Object>
	getConfig()
	{
		Map<String,Object>	config = new HashMap<String,Object>();
		
		if ( filtering_proxy != null ){
			
			config.put( "socks_host", "127.0.0.1" );
			config.put( "socks_port", filtering_proxy.getPort());

		}else{
			
			config.put( "socks_host", external_tor?external_socks_host:internal_socks_host );
			config.put( "socks_port", external_tor?external_socks_port:internal_socks_port );
		}
		
		config.put( "i2p_socks_host", filtering_i2p_host );
		config.put( "i2p_socks_port", filtering_i2p_port );

		return( config );
	}
	
	public Map<String,Object>
	setConfig(
		Map<String,Object>		config )
	{
		String	i2p_host	= (String)config.get( "i2p_socks_host" );
		Number	i2p_port 	= (Number)config.get( "i2p_socks_port" );

		if ( i2p_port != null ){
			
			synchronized( this ){
		
				filtering_i2p_port		= i2p_port.intValue();
				
				if ( i2p_host != null ){
					
					filtering_i2p_host	= i2p_host;
					
				}				
				if ( filtering_proxy == null ){
					
					int filtering_proxy_last_port = plugin_config.getPluginIntParameter( "filtering.proxy.port", 0 );
					
					try{
						try{
							filtering_proxy = new SOCKSProxy( filtering_proxy_last_port, true, "Filtering for I2P: " + filtering_i2p_port );
						
						}catch( Throwable e ){
							
							filtering_proxy = new SOCKSProxy( 0, true, "Filtering for I2P: " + filtering_i2p_port );

							filtering_proxy_last_port = filtering_proxy.getPort();
							
							plugin_config.setPluginParameter( "filtering.proxy.port", filtering_proxy_last_port );
						}
						
						log( "Filtering details: " + filtering_proxy.getPort() + " -> " + filtering_i2p_host + ":" + filtering_i2p_port );

					}catch( Throwable e ){
						
						log( "Failed to start filtering proxy", e );
					}
				}
			}
		}
		
		return( getConfig());
	}
	
	public boolean
	requestActivation()
	{
		if ( external_tor ){
			
			return( true );
		}
		
		ControlConnection con = getConnection( 5*1000, true );
		
		boolean active = con != null && con.isConnected();
		
		if ( active ){
			
			last_use_time	= SystemTime.getMonotonousTime();
		}
		
		return( active );
	}
	
	public void
	setProxyStatus(
		Proxy		proxy,
		boolean		good )
	{
		ProxyMapEntry	entry;
		
		synchronized( this ){
			
			entry = proxy_map.remove( proxy );
		}
		
		if ( entry != null ){
				
			String 	host 				= entry.getHost();
			
			if ( good ){
				
				proxy_request_ok.incrementAndGet();
				
			}else{
				
				proxy_request_failed.incrementAndGet();
			}
			
			updateProxyHistory( host, good );
			
			String	intermediate_host	= entry.getIntermediateHost();

			if ( intermediate_host != null ){
				
				synchronized( this ){
					
					intermediate_host_map.remove( intermediate_host );
				}
			}
		}else{
			
			Debug.out( "Proxy entry missing!" );
		}
	}
	
	public Object[]
	getProxy(
		String		reason,
		URL			url )
	
		throws IPCException
	{
		String 	host = url.getHost();
		
		Object[] proxy_details = getActiveProxy( reason, host, true, false );
		
		if ( proxy_details != null ){
						
			url = UrlUtils.setHost( url, (String)proxy_details[1] );
		
			return( new Object[]{ proxy_details[0], url, proxy_details[2] });
		}
		
		return( null );
	}
	
	public Object[]
	getProxy(
		String		reason,
		String		host,
		int			port )
	
		throws IPCException
	{
		Object[] proxy_details = getActiveProxy( reason, host, false, false );
		
		if ( proxy_details != null ){
			
			return( new Object[]{ proxy_details[0], proxy_details[1], port });
		}
		
		return( null );
	}
	
	public Boolean
	testHTTPPseudoProxy(
		URL			url )
	{
		final int TIMEOUT = 30*1000;
		
		String 	host 	= url.getHost();
		int		port	= 443;
		
		try{
			String[]	host_bits = host.split( "\\." );
			
			final String host_match = "." + host_bits[host_bits.length-2] + "." + host_bits[host_bits.length-1];
			
			SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
	
			final SSLSocket socket = (SSLSocket)factory.createSocket();
			
			final boolean[] result = { false };
			
			final AESemaphore sem = new AESemaphore( "ssl:wait" );
			
			try{
				socket.addHandshakeCompletedListener(
					new HandshakeCompletedListener() 
					{	
						@Override
						public void
						handshakeCompleted(
							HandshakeCompletedEvent event ) 
						{
							try{
								java.security.cert.Certificate[] serverCerts = socket.getSession().getPeerCertificates();
								
								if ( serverCerts.length == 0 ){
													
									// no certs :(
									
								}else{
								
									java.security.cert.Certificate	cert = serverCerts[0];
												
									java.security.cert.X509Certificate x509_cert;
									
									if ( cert instanceof java.security.cert.X509Certificate ){
										
										x509_cert = (java.security.cert.X509Certificate)cert;
										
									}else{
										
										java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
										
										x509_cert = (java.security.cert.X509Certificate)cf.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
									}
									
									Collection<List<?>> alt_names = x509_cert.getSubjectAlternativeNames();
									
									for ( List<?> alt_name: alt_names ){
										
										int	type = ((Number)alt_name.get(0)).intValue();
										
										if ( type == 2 ){		// DNS name
											
											String	dns_name = (String)alt_name.get(1);
											
											if ( dns_name.endsWith( host_match )){
												
												result[0] = true;
												
												break;
											}
										}
									}
								}
							}catch( Throwable e ){
								
								e.printStackTrace();
								
							}finally{
								
								sem.releaseForever();
							}
						}
					});
		
				long	start = SystemTime.getMonotonousTime();
				
				socket.setSoTimeout( TIMEOUT );
				
				socket.connect( new InetSocketAddress( host, port  ), TIMEOUT );
			
				OutputStream os = socket.getOutputStream();
				
				os.write( "HEAD / HTTP/1.1\r\n\r\n".getBytes());
				
				os.flush();
				
				long so_far = SystemTime.getMonotonousTime() - start;
				
				long rem = TIMEOUT - so_far;
				
				if ( rem > 0 ){
				
					sem.reserve( TIMEOUT );
				}
			}finally{
				
				try{
					socket.close();
					
				}catch( Throwable e ){
				}
			}
						
			return( result[0] );
			
		}catch( Throwable e ){
			
			return( false );
		}
	}
	
	public Proxy
	createHTTPPseudoProxy(
		String		reason,
		URL			url )

		throws IPCException
	{
		if ( !plugin_enabled || unloaded ){
			
			return( null );
		}
		
		String	host = url.getHost();
				
		if ( !isHostAccepted( reason, host )){
			
			return( null );
		}
		
		last_use_time	= SystemTime.getMonotonousTime();
		
		String key = url.getProtocol() + ":" + host + ":" + url.getPort();
		
		TorPluginHTTPProxy	proxy;
		
		boolean				is_new = false;
		
		int		socks_port = getActiveSocksPort();
		String	socks_host = getActiveSocksHost();
		
		synchronized( this ){
			
			proxy =  http_proxy_map.get( key );
			
			if ( proxy == null ){
				
				is_new = true;
				
				proxy = new TorPluginHTTPProxy( url, new Proxy( Proxy.Type.SOCKS, new InetSocketAddress( socks_host, socks_port )));
				
				http_proxy_map.put( key, proxy );
				
			}else{
				
				proxy.incRefCount();
			}
			
			setUnloadable( false );
		}
		
		if ( is_new ){
			
			final AESemaphore	sem = new AESemaphore( "start_wait" );
			
			final TorPluginHTTPProxy	f_proxy = proxy;
			
			final IPCException[] error = { null };
			
			new AEThread2( "proxystart" )
			{
				@Override
				public void
				run()
				{
					try{
						f_proxy.start();
						
						log( "Created proxy: " + f_proxy.getString());
						
					}catch( Throwable e ){
						
						error[0] = new IPCException( "Failed to start proxy", e );
						
					}finally{
						
						sem.release();
					}
				}
			}.start();
			
			sem.reserve( 5*1000 );
			
			if ( error[0] != null ){
				
				throw( error[0] );
			}
		}
		
		return( new Proxy( Proxy.Type.HTTP, new InetSocketAddress( "127.0.0.1", proxy.getPort())));
	}
	
	public void
	destroyHTTPPseudoProxy(
		Proxy		proxy )
	{
		last_use_time	= SystemTime.getMonotonousTime();
		
		synchronized( this ){

			Iterator<TorPluginHTTPProxy> it =  http_proxy_map.values().iterator();
			
			while( it.hasNext()){
				
				TorPluginHTTPProxy http_proxy = it.next();
				
				if ( http_proxy.getPort() == ((InetSocketAddress)proxy.address()).getPort()){
					
					if ( http_proxy.decRefCount() == 0 ){
					
						it.remove();
						
						http_proxy.destroy();
					}
					
					break;
				}
			}
			
			if ( http_proxy_map.size() == 0 ){
			
				setUnloadable( true );
			}
		}
	}
	
	public Map<String,Object>
	getProxyServer(
		String				reason,
		Map<String,Object>	server_options )
		
		throws IPCException
	{
		String	server_id = (String)server_options.get( "id" );
		
		int		target_port = (Integer)server_options.get( "port" );

		File service_file = new File( services_dir, server_id + ".txt" );
		
		String FS = File.separator;
		
		String bind_ip;
		
		String	bind_option = (String)server_options.get( "bind" );

		if ( bind_option != null ){
			
			bind_ip = bind_option;
			
		}else{
			
			bind_ip = "127.0.0.1";
		}
		
		String[] required_lines = { 
			"HiddenServiceDir ." + FS + "services" + FS + server_id,
			"HiddenServicePort 80 " + bind_ip + ":" + target_port
		};
		
		boolean	config_ok = false;
		
		if ( service_file.exists()){
			
			List<String> lines = readFileAsStrings( service_file );

			if ( 	lines.size() == 2 && 
					lines.get(0).equals( required_lines[0] ) &&
					lines.get(1).equals( required_lines[1])){
				
				config_ok = true;
			}
		}
		
		final File host_file = new File( services_dir, server_id + FS + "hostname" );

		String	host_name = null;
		
		if ( config_ok ){
			
				// this code is below as well
			
			if ( host_file.exists()){
				
				try{
					String host = FileUtil.readFileAsString( host_file, 100 ).trim();
					
					if ( host.endsWith( ".onion" )){
						
						host_name = host;
					}
				}catch( Throwable e ){
					
				}
			}
			
			if ( host_name == null ){
				
				config_ok = false;
			}
		}
		
		if ( !config_ok ){
			
			PrintWriter pw = null;
			
			try{
				pw = new PrintWriter( new OutputStreamWriter( new FileOutputStream( service_file )));
				
				for ( String line: required_lines ){
					
					pw.println( line );
				}
			}catch( Throwable e ){
				
				log( "Failed to write " + service_file, e );
				
				throw( new IPCException( e ));
				
			}finally{
				
				if ( pw != null ){
					
					try{
						pw.close();
						
					}catch( Throwable e ){
					}
				}
			}
		}
		
		if ( external_tor ){
			
			return( null );
		}
		
		if ( !services_enable_param.getValue()){
			
			return( null );
		}

		if ( host_name == null ){
			
			final AESemaphore sem = new AESemaphore( "waiter" );
			
			final String[] f_host = { null };
			
			new AEThread2( "waiter" )
			{
				@Override
				public void
				run()
				{
					long	start = SystemTime.getMonotonousTime();
					
					config_needs_checking	= true;
				
					try{
						while( true ){
							
							if ( host_file.exists()){
								
								try{
									String host = FileUtil.readFileAsString( host_file, 100 ).trim();
									
									if ( host.endsWith( ".onion" )){
										
										f_host[0] = host;
										
										break;
									}
								}catch( Throwable e ){
									
								}
							}
							
							if ( SystemTime.getMonotonousTime() - start > 15*1000 ){
								
								break;
							}
							
							checkServerStatus();
							
							try{
								Thread.sleep( 1000 );
								
							}catch( Throwable e ){
								
							}
						}
					}finally{
						
						sem.release();
					}
				}
			}.start();
			
			sem.reserve( 15*1000 );
			
			host_name = f_host[0];
			
			if ( host_name == null ){
			
				return( null );
			}
		}
		
		Map<String,Object>	reply = new HashMap<String, Object>();
		
		reply.put( "host", host_name );
		
		return( reply );
	}
	
	private List<String>
	readFileAsStrings(
		File		file )
		
		throws IPCException
	{
		List<String>	result = new ArrayList<String>();
		
		LineNumberReader lnr = null;
		
		try{
			lnr = new LineNumberReader( new InputStreamReader( new FileInputStream( file )));
			
			while( true ){
				
				String line = lnr.readLine();
				
				if ( line == null ){
					
					break;
				}
				
				result.add( line.trim());
			}
			
			return( result );
			
		}catch( Throwable e ){
			
			log( "Failed to read " + file, e );
			
			throw( new IPCException( e ));
			
		}finally{
			
			try{
				if ( lnr != null ){
				
					lnr.close();
				}
			}catch( Throwable e ){
			}
		}
	}
	
		// end IPC
	
	public PluginInterface
	getPluginInterface()
	{
		return( plugin_interface );
	}
	
	private class
	ControlConnection
	{
		private Process		process;
		private int			control_port;
		private int			socks_port;
		private File		data_dir;
	
		private Socket				socket;
		private LineNumberReader 	lnr;
		private OutputStream 		os;
		
		private boolean		did_connect;
		private boolean		owns_process;
	
		private TimerEventPeriodic	timer;
		
		private 
		ControlConnection(
			Process		_process,
			File		_data_dir,
			int			_control_port,
			int			_socks_port )
		{
			process			= _process;
			data_dir		= _data_dir;
			control_port	= _control_port;
			socks_port		= _socks_port;
		}
		
		private int
		getSOCKSPort()
		{
			return( socks_port );
		}
		
		private boolean
		connect()
		{
			try{
				socket = new Socket( Proxy.NO_PROXY );

				socket.bind( new InetSocketAddress( "127.0.0.1", 0 ));
				
				socket.connect( new InetSocketAddress( "127.0.0.1", control_port ), 30*1000 );

				did_connect = true;
				
				socket.setSoTimeout( 30*1000 );

				InputStream is = socket.getInputStream();
										
				lnr = new LineNumberReader( new InputStreamReader( is ));

				os = socket.getOutputStream();
							
				byte[] client_nonce = new byte[32];
			
				RandomUtils.nextSecureBytes( client_nonce );
				
				String reply = sendAndReceive( "AUTHCHALLENGE SAFECOOKIE " + ByteFormatter.encodeString( client_nonce ).toUpperCase());
								
				if ( !reply.startsWith( "250 AUTHCHALLENGE " )){
					
					throw( new Exception( "AUTHCHALLENGE response invalid: " + reply ));
				}
				
				File cookie_file = new File( data_dir, "control_auth_cookie" );
				
				byte[] cookie = FileUtil.readFileAsByteArray( cookie_file );
				
				reply = reply.substring( 18 ).trim();
				
				String[] bits = reply.split( " " );
				
				byte[] server_hash 	= ByteFormatter.decodeString( bits[0].substring( 11 ).trim());
				byte[] server_nonce = ByteFormatter.decodeString( bits[1].substring( 12 ).trim());
				
				Mac mac = Mac.getInstance("HmacSHA256");
				
				SecretKeySpec secret_key = new SecretKeySpec( "Tor safe cookie authentication server-to-controller hash".getBytes(Constants.BYTE_ENCODING_CHARSET), "HmacSHA256");
				
				mac.init( secret_key );
				
				mac.update( cookie );
				mac.update( client_nonce );
				mac.update( server_nonce );
				
				byte[] server_digest = mac.doFinal();
				
				if ( !Arrays.equals( server_hash, server_digest )){
					
					throw( new Exception( "AUTHCHALLENGE response server hash incorrect" ));
				}
											
				secret_key = new SecretKeySpec( "Tor safe cookie authentication controller-to-server hash".getBytes(Constants.BYTE_ENCODING_CHARSET), "HmacSHA256");

				mac.init( secret_key );
				
				mac.update( cookie );
				mac.update( client_nonce );
				mac.update( server_nonce );
				
				reply = sendAndReceive( "AUTHENTICATE " + ByteFormatter.encodeString( mac.doFinal()).toUpperCase());
				
				if ( !reply.startsWith( "250 OK" )){
					
					throw( new Exception( "AUTHENTICATE response invalid: " + reply ));
				}
				
				reply = sendAndReceive( "TAKEOWNERSHIP" );
										
				if ( !reply.startsWith( "250 OK" )){
					
					throw( new Exception( "TAKEOWNERSHIP response invalid: " + reply ));
				}
				
				reply = sendAndReceive( "RESETCONF __OwningControllerProcess" );
									
				if ( !reply.startsWith( "250 OK" )){
					
					throw( new Exception( "TAKEOWNERSHIP response invalid: " + reply ));
				}
				
				String info = getInfo();
				
				log( "Connection to control port established - " + info );
				
				timer = SimpleTimer.addPeriodicEvent(
							"keepalive",
							30*1000,
							new TimerEventPerformer() {
								
								private boolean	running = false;
								
								@Override
								public void
								perform(
									TimerEvent event )
								{
									if ( unloaded || !isConnected()){
										
										timer.cancel();
										
										return;
									}
									
									synchronized( ControlConnection.this ){
										
										if ( running ){
											
											return;
										}
										
										running = true;
									}
									
									new AEThread2( "getinfo" )
									{
										@Override
										public void
										run()
										{
											try{
												getInfo();
												
												//System.out.println( info );
												
											}catch( Throwable e ){
												
											}finally{
												
												synchronized( ControlConnection.this ){
													
													running = false;
												}
											}
										}
									}.start();
								}
							});
					
				owns_process = true;
				
				return( true );
				
			}catch( Throwable e ){
				
				if ( did_connect ){
				
					String msg = "Connection error: " + Debug.getNestedExceptionMessage( e );
					
					Debug.out( msg );
					
					close( msg );
					
				}else{
					
					close( null );
				}
				
				
				return( false );
			}	
		}
		
		private String
		getInfo()
		
			throws IOException
		{
			synchronized( ControlConnection.this ){

				writeLine( "GETINFO version" );
				
				String	result = "";
				
				while( true ){
					
					String reply = readLine();
					
					if ( reply.startsWith( "250" )){
						
						if ( reply.equals( "250 OK" )){
							
							return( result );
							
						}else{
							
							result = reply.substring( 4 );
						}
					}else{
						
						throw( new IOException( "Unexpected reply: " + reply ));
					}	
				}
			}
		}
		
		private String
		sendAndReceive(
			String	str )
		
			throws IOException
		{
			synchronized( ControlConnection.this ){
				
				writeLine( str );
				
				return( readLine());
			}
		}
		
		private void
		writeLine(
			String		str )
		
			throws IOException 
		{
			try{
				os.write( ( str + "\r\n" ).getBytes(Constants.BYTE_ENCODING_CHARSET));
			
				os.flush();
				
			}catch( IOException e ){
			
				close( Debug.getNestedExceptionMessage( e ));
				
				throw( e );
			}
		}
		
		private String
		readLine()
		
			throws IOException
		{
			String line = lnr.readLine();
			
			if ( line == null ){
				
				close( "Unexpected end of file" );
				
				throw( new IOException( "Unexpected end of file" ));
			}
			
			return( line.trim());
		}
		
		private boolean
		isConnected()
		{
			return( socket != null );
		}
		
		private void
		shutdown(
			boolean	force )
		{
			try{
				if ( socket != null ){
					
					if ( force ){
						
						sendAndReceive( "SIGNAL HALT" );
						
					}else{
						
						sendAndReceive( "SIGNAL SHUTDOWN" );
					}
				}
			}catch( Throwable e ){
				
			}finally{
				
				close( "Shutdown" );
			}
		}
		
		private void
		close(
			String	reason )
		{
			if ( reason != null ){
				
				log( "Control connection closed: " + reason );
			}
			
			if ( timer != null ){
				
				timer.cancel();
				
				timer = null;
			}
			
			if ( lnr != null ){
				
				try{
					lnr.close();
					
				}catch( Throwable e ){
				}
				
				lnr = null;
			}
			
			if ( os != null ){
				
				try{
					os.close();
					
				}catch( Throwable e ){
				}
				
				os = null;
			}
			
			if ( socket != null ){
				
				try{
					socket.close();
					
				}catch( Throwable e ){
				}
				
				socket = null;
			}
			
			if ( owns_process && process != null ){
				
				process.destroy();
				
				process = null;
			}
		}
	}
	
	private class
	ProxyHistory
	{
		private String	host;
		
		private long	last_connect_time;
		private int		total_fails;
		private int		total_ok;
		
		private int		consec_fails;
		
		private
		ProxyHistory(
			String		_host )
		{
			host		= _host;
		}
		
		private boolean
		canConnect()
		{
			long now = SystemTime.getMonotonousTime();
			
			boolean ok = consec_fails < 5;
			
			if ( !ok ){
				
				int delay = 30*60*1000;
				
				for ( int i=3;i<consec_fails;i++){
					
					delay <<= 1;
					
					if ( delay > 24*60*60*1000 ){
						
						delay = 24*60*60*1000;
						
						break;
					}
				}
				
				if ( now - last_connect_time >= delay ){
					
					ok = true;
				}
			}
			
			if ( ok ){
				
				last_connect_time = now;
			}
			
			return( ok );
		}
		
		private void
		setOutcome(
			boolean		ok )
		{
			if ( ok ){
				
				total_ok++;
				
				consec_fails = 0;
				
			}else{
				
				total_fails++;
				
				consec_fails++;
				
				if ( consec_fails > 2 ){
					
					log( "Failed to connect to '" + host + "' " + consec_fails + " times in a row - backing off (ok=" + total_ok + ", fails=" + total_fails +")" );
				}
			}
		}
	}
	
	private class
	SOCKSProxy
		implements AESocksProxyPlugableConnectionFactory
	{
		private final boolean	filtering;
		
		private InetAddress local_address;
		
		private Set<SOCKSProxyConnection>		connections = new HashSet<SOCKSProxyConnection>();
		
		private ThreadPool	connect_pool = new ThreadPool( "TorConnect", 10 );

		{
			try{
				local_address = InetAddress.getByName( "127.0.0.1" );
				
			}catch( Throwable e ){
				
				Debug.printStackTrace(e);
				
				local_address = null;
			}
		}
		
		private AESocksProxy proxy;
		
		private
		SOCKSProxy(
			int			_port,
			boolean		_filtering,
			String 		_reason )
		
			throws AEProxyException
		{
			filtering	= _filtering;
			
			proxy = AESocksProxyFactory.create( _port, 120*1000, 120*1000, this );
			
			log( "Intermediate SOCKS proxy started on port " + proxy.getPort() + " for " + _reason + ", filtering=" + filtering );
		}
		
		private int
		getPort()
		{
			return( proxy.getPort());
		}
		
		@Override
		public AESocksProxyPlugableConnection
		create(
			AESocksProxyConnection	connection )
		
			throws AEProxyException
		{
			synchronized( this ){
				
				if ( connections.size() > 32 ){
					
					try{
						connection.close();
						
					}catch( Throwable e ){
					}
					
					throw( new AEProxyException( "Too many connections" ));
				}
			
				SOCKSProxyConnection con = new SOCKSProxyConnection( connection );
				
				connections.add( con );
				
				return( con );
			}
		}
		
		private void
		closed(
			SOCKSProxyConnection	connection )
		{
			synchronized( this ){
				
				connections.remove( connection );
			}
		}
		
		private void
		destroy()
		{
			try{
				proxy.destroy();
				
			}catch( Throwable e ){
			}
		}
		
		private class
		SOCKSProxyConnection
			implements AESocksProxyPlugableConnection, SEPasswordListener
		{
			private AESocksProxyConnection	connection;
			private Socket					tor_socket;
			
			private ProxyStateRelayData		relay_state;
			
			private boolean	socket_closed;
			
			private
			SOCKSProxyConnection(
				AESocksProxyConnection		_connection )
			{
				connection = _connection;
				
				connection.disableDNSLookups();
			}
			
			@Override
			public String
			getName()
			{
				return( "TorPluginConnection" );
			}
			
			@Override
			public InetAddress
			getLocalAddress()
			{
				return( local_address );
			}
			
			@Override
			public int
			getLocalPort()
			{
				return( -1 );
			}

			@Override
			public void
			connect(
				AESocksProxyAddress		address )
				
				throws IOException
			{
				String	proxy_host;
				int		proxy_port;
				
				String	final_host;
				int		final_port;

				if ( filtering ){
															
					InetAddress target = address.getAddress();
					
					if ( target != null ){
						
						closed( this );
						
						throw( new IOException( "Address should be unresolved" ));
					}
					
					final_host	= address.getUnresolvedAddress();
					final_port	= address.getPort();

					if ( final_host.endsWith( ".i2p" )){
						
						if ( filtering_i2p_port == 0 ){
							
							throw( new IOException( "I2P proxy not set" ));
						}
						
						proxy_host	= filtering_i2p_host;
						proxy_port	= filtering_i2p_port;
						
					}else{
						
						proxy_host	= active_socks_host;
						proxy_port	= active_socks_port;
					}
				}else{
					
					InetAddress target = address.getAddress();
					
					if ( target == null ){
						
						closed( this );
						
						throw( new IOException( "Address should be set" ));
					}
						
					String intermediate_host = target.getHostAddress();

					Object[] entry;
					
					synchronized( TorPlugin.this ){
						
						entry = intermediate_host_map.get( intermediate_host );
					}
					
					if ( entry == null ){
						
						closed( this );
						
						throw( new IOException( "Intermediate address not found" ));
					}
					
					proxy_host 	= (String)entry[1];
					proxy_port	= (Integer)entry[2];
										
					final_host = (String)entry[0];
					final_port = address.getPort();

					final_host = rewriteHost( final_host, true );
				}
				
				final Proxy proxy = new Proxy( Proxy.Type.SOCKS, new InetSocketAddress( proxy_host, proxy_port ));
						
				final InetSocketAddress final_address = InetSocketAddress.createUnresolved( final_host, final_port );
				
				connect_pool.run(
					new AERunnable()
					{
						@Override
						public void
						runSupport() 
						{
							try{
									// Tor uses SOCKS username/password authentication to manage
									// stream isolation so we need to forward this when delegating
								
								boolean	add_pw_listener = connection.getUsername() != null;
								
								if ( add_pw_listener ){
									
									SESecurityManager.setThreadPasswordHandler( SOCKSProxyConnection.this );
								}
								
								try{
									Socket socket = new Socket( proxy );
									
									socket.connect( final_address );
									
									synchronized( SOCKSProxyConnection.this ){
										
										if ( socket_closed ){
											
											try{
												socket.close();
												
											}catch( Throwable e ){
											
											}
											
											throw( new Exception( "Connection already closed" ));
										}
										
										tor_socket = socket;
									}
									
									connection.connected();
								}finally{
									
									if ( add_pw_listener ){
										
										SESecurityManager.unsetThreadPasswordHandler();
									}
								}
							}catch( Throwable e ){
								
								try{
									connection.close();
									
								}catch( Throwable f ){
									
								}
							}
						}
					});
			}
			
			@Override
			public void
			relayData()
			
				throws IOException
			{
				synchronized( this ){
				
					if ( socket_closed ){
						
						throw( new IOException( "TorPluginConnection::relayData: socket already closed"));
					}
				
					relay_state = new ProxyStateRelayData( connection.getConnection(), tor_socket );
				}
			}
			
			@Override
			public void
			close()
			
				throws IOException
			{
				synchronized( this ){
				
					if ( socket_closed ){
						
						return;
					}
					
					socket_closed	= true;
					
					if ( relay_state != null ){
							
						relay_state.close();
					}
						
					if ( tor_socket != null ){
						
						tor_socket.close();
					}
						
					connection.close();
				}	
				
				
				closed( this );
			}
			
			@Override
			public PasswordAuthentication
			getAuthentication(
				String		realm,
				URL			tracker )
			{
				String username = connection.getUsername();
				String password	= connection.getPassword();
				
				if ( username != null && password != null ){
					
					return( new PasswordAuthentication( username, password.toCharArray()));
					
				}else{
					
					return( null );
				}
			}
			
			@Override
			public void
			setAuthenticationOutcome(
				String		realm,
				URL			tracker,
				boolean		success )
			{
			}
			
			@Override
			public void
			clearPasswords()
			{
			}
		}
		
		protected class
		ProxyStateRelayData
			implements AEProxyState
		{
			private final int	RELAY_BUFFER_SIZE = 32*1024;
			
			private AEProxyConnection		connection;
			private Socket					tor_socket;
			
			private ByteBuffer				source_buffer;
			private ByteBuffer				target_buffer;
					
			private SocketChannel			source_channel;

			private InputStream				tor_input_stream;
			private OutputStream			tor_output_stream;
						
			protected AESemaphore			write_sem = new AESemaphore( "TorSocket write sem" );
						
			protected
			ProxyStateRelayData(
				AEProxyConnection	_connection,
				Socket				_tor_socket )
			
				throws IOException
			{		
				connection	= _connection;
				tor_socket	= _tor_socket;
								
				source_buffer	= ByteBuffer.allocate( RELAY_BUFFER_SIZE );

				source_channel	= connection.getSourceChannel();
				
				tor_input_stream 	= tor_socket.getInputStream();
				tor_output_stream 	= tor_socket.getOutputStream();

				connection.setReadState( this );
				
				connection.setWriteState( this );
				
				connection.requestReadSelect( source_channel );
							
				connection.setConnected();
				
				new AEThread2( "RelayRead" )
				{			
					@Override
					public void
					run()
					{
						byte[]	buffer = new byte[RELAY_BUFFER_SIZE];
											
						while( !connection.isClosed()){
						
							try{
								int	len = tor_input_stream.read( buffer );
								
								if ( len <= 0 ){
									
									break;
								}
																																
								target_buffer = ByteBuffer.wrap( buffer, 0, len );
								
								connection.setTimeStamp();
								
								if ( target_buffer.hasRemaining()){
								
									connection.requestWriteSelect( source_channel );
									
										// sem will only be released once write is complete
									
									write_sem.reserve();
									
								}else{
								
									target_buffer	= null;
								}
							}catch( Throwable e ){
								
								break;
							}
						}
						
						if ( !connection.isClosed()){
							
							connection.close();
						}
					}
				}.start();
			}
			
			protected void
			close()
			{						
				write_sem.releaseForever();
			}
			
			@Override
			public boolean
			read(
				SocketChannel 		sc )
			
				throws IOException
			{
				if ( source_buffer.position() != 0 ){
					
					Debug.out( "TorPluginConnection: source buffer position invalid" );
				}
				
					// data read from source
				
				connection.setTimeStamp();
																
				final int	len = sc.read( source_buffer );
		
				if ( len == 0 ){
					
					return( false );
				}
				
				if ( len == -1 ){
					
					throw( new EOFException( "read channel shutdown" ));
					
				}else{
					
					if ( source_buffer.position() > 0 ){
						
						connection.cancelReadSelect( source_channel );
												
							// offload the write to separate thread as can't afford to block the
							// proxy
					
						new AEThread2( "RelayWrite" )
						{		
							@Override
							public void
							run()
							{
								try{					
									source_buffer.flip();
																												
									tor_output_stream.write( source_buffer.array(), 0, len );
					
									source_buffer.position( 0 );
									
									source_buffer.limit( source_buffer.capacity());
									
									tor_output_stream.flush();
																													
									connection.requestReadSelect( source_channel );								

								}catch( Throwable e ){
									
									connection.failed( e );
								}
							}
						}.start();			
					}
				}
				
				return( true );
			}
			
			@Override
			public boolean
			write(
				SocketChannel 		sc )
			
				throws IOException
			{
				try{
					int written = source_channel.write( target_buffer );
											
					if ( target_buffer.hasRemaining()){
										
						connection.requestWriteSelect( source_channel );
						
					}else{
						
						target_buffer = null;
						
						write_sem.release();
					}
					
					return( written > 0 );
					
				}catch( Throwable e ){
					
					target_buffer = null;
					
					write_sem.release();
					
					if ( e instanceof IOException ){
						
						throw((IOException)e);
					}
					
					throw( new IOException( "write fails: " + Debug.getNestedExceptionMessage(e)));
				}
			}
			
			@Override
			public boolean
			connect(
				SocketChannel	sc )
			
				throws IOException
			{
				throw( new IOException( "Not Supported" ));
			}
			
			@Override
			public String
			getStateName()
			{
				return( "relay" );
			}
		}
	}
	
	private class
	ProxyMapEntry
	{
		private long	created = SystemTime.getMonotonousTime();
		
		private	String	host;
		private String	intermediate_host;
		
		private
		ProxyMapEntry(
			String		_host,
			String		_intermediate_host )
		{
			host				= _host;
			intermediate_host	= _intermediate_host;
		}
		
		private long
		getCreateTime()
		{
			return( created );
		}
		
		private String
		getHost()
		{
			return( host );
		}
		
		private String
		getIntermediateHost()
		{
			return( intermediate_host );
		}
	}
}
