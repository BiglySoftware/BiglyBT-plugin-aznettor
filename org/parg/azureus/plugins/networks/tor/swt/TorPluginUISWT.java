/*
 * Created on Dec 18, 2013
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



package org.parg.azureus.plugins.networks.tor.swt;

import java.util.*;

import org.eclipse.swt.SWT;
import org.eclipse.swt.events.DisposeEvent;
import org.eclipse.swt.events.DisposeListener;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.TraverseEvent;
import org.eclipse.swt.events.TraverseListener;
import org.eclipse.swt.graphics.Point;
import org.eclipse.swt.graphics.Rectangle;
import org.eclipse.swt.layout.FormAttachment;
import org.eclipse.swt.layout.FormData;
import org.eclipse.swt.layout.FormLayout;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Canvas;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Shell;
import com.biglybt.core.internat.MessageText;
import com.biglybt.core.util.AESemaphore;
import com.biglybt.core.util.Debug;
import com.biglybt.pif.utils.LocaleUtilities;
import com.biglybt.ui.swt.Utils;
import com.biglybt.ui.swt.components.shell.ShellFactory;
import com.biglybt.ui.swt.shells.MessageBoxShell;
import org.parg.azureus.plugins.networks.tor.TorPlugin;
import org.parg.azureus.plugins.networks.tor.TorPluginUI;

import com.biglybt.ui.UserPrompterResultListener;

public class 
TorPluginUISWT
	implements TorPluginUI
{
	private LocaleUtilities		lu;
	
	private List<Shell>			active_shells = new ArrayList<Shell>();
	
	private volatile boolean		destroyed;
	
	public
	TorPluginUISWT(
		TorPlugin	_plugin )
	{
		lu	= _plugin.getPluginInterface().getUtilities().getLocaleUtilities();
	}
	
	@Override
	public boolean
	isUIThread(
		Thread	thread )
	{
		Display display = Utils.getDisplay();
		
		if ( display == null ){
			
			Debug.out( "eh? display is null" );
			
			return( true );
		}
		
		return( display.getThread() == thread );
	}
	
	@Override
	public PromptResponse
	promptForHost(
		final String	reason,
		final String	host )
	{
		final boolean[]		result  	= {false};
		final String[]		remembered	= {null};
		
		PromptResponse prompt_response = 
			new PromptResponse()
			{
				@Override
				public boolean
				getAccepted()
				{
					return( result[0] );
				}
				
				@Override
				public String
				getRemembered()
				{
					return( remembered[0] );
				}
			};
			
		if ( Utils.isSWTThread()){
			
			Debug.out( "Invocation on SWT thead not supported" );
			
			return( prompt_response );
		}
		
		if ( destroyed ){
			
			return( prompt_response );
		}
		
		final AESemaphore	wait_sem 	= new AESemaphore( "wait" );
		
		Utils.execSWTThread(
			new Runnable()
			{
				@Override
				public void
				run()
				{
					try{
						final Shell shell = ShellFactory.createMainShell( SWT.DIALOG_TRIM | SWT.RESIZE );
				
						shell.addDisposeListener(
							new DisposeListener()
							{
								@Override
								public void
								widgetDisposed(
									DisposeEvent arg0 ) 
								{
									synchronized( TorPluginUISWT.this ){
										
										active_shells.remove( shell );
									}
									
									wait_sem.release();
								}
							});
						
						synchronized( TorPluginUISWT.this ){
							
							if ( destroyed ){
								
								shell.dispose();
								
								return;
								
							}else{
								
								active_shells.add( shell );
							}
						}
						
						shell.setText( lu.getLocalisedMessageText( "aztorplugin.ask.title" ));
								
						Utils.setShellIcon(shell);
						
						GridLayout shell_layout = new GridLayout();
						shell_layout.numColumns = 1;
						//shell_layout.marginHeight = 0;
						//shell_layout.marginWidth = 0;
						shell.setLayout(shell_layout);
						GridData grid_data = new GridData(GridData.FILL_BOTH );
						shell.setLayoutData(grid_data);
						

						
						Label label = new Label( shell, SWT.NULL );
						label.setText( lu.getLocalisedMessageText( "aztorplugin.ask.info1", new String[]{ host } ));
						
						label = new Label( shell, SWT.NULL );
						label.setText( lu.getLocalisedMessageText( "aztorplugin.ask.info2", new String[]{ reason } ));

						label = new Label( shell, SWT.NULL );
						label.setText( lu.getLocalisedMessageText( "aztorplugin.ask.info3" ));
						
						Composite remember_comp = new Composite( shell, SWT.NULL );
						
						GridLayout rc_layout = new GridLayout();
						rc_layout.numColumns = 4;
						rc_layout.marginTop = 16;
						rc_layout.marginHeight = 0;
						rc_layout.marginWidth = 0;
						remember_comp.setLayout( rc_layout);
						grid_data = new GridData(GridData.FILL_HORIZONTAL);
						remember_comp.setLayoutData(grid_data);	
						
						final Button rc_check = new Button( remember_comp, SWT.CHECK );
						rc_check.setSelection( true );
						
						label = new Label( remember_comp, SWT.NULL );
						label.setText( lu.getLocalisedMessageText( "aztorplugin.ask.remember" ));
						
						final Combo options = new Combo( remember_comp,SWT.SINGLE | SWT.READ_ONLY);
												
						options.add( lu.getLocalisedMessageText( "aztorplugin.ask.remember.all" ));
						
						String[] bits = host.split( "\\." );
						int	bits_num = bits.length;
						if ( bits_num > 2 ){
							options.add( "*." + bits[bits_num-2] + "." + bits[bits_num-1] );
						}
						options.add( host );
						
						options.select( 0 );
						
						rc_check.addSelectionListener(
							new SelectionAdapter() {
								@Override
								public void widgetSelected(SelectionEvent e) {
									options.setEnabled( rc_check.getSelection());
								}
							});
						
						label = new Label( remember_comp, SWT.NULL );
						grid_data = new GridData(GridData.FILL_HORIZONTAL);
						label.setLayoutData(grid_data);	
						
							// buttons
						
						Canvas line = new Canvas(shell,SWT.NO_BACKGROUND);
						line.addListener(SWT.Paint, new Listener() {
							@Override
							public void handleEvent(Event e) {
								Rectangle clientArea = ((Canvas) e.widget).getClientArea();
								e.gc.setForeground(e.display.getSystemColor(SWT.COLOR_WIDGET_NORMAL_SHADOW));
								e.gc.drawRectangle(clientArea);
								clientArea.y++;
								e.gc.setForeground(e.display.getSystemColor(SWT.COLOR_WIDGET_HIGHLIGHT_SHADOW));
								e.gc.drawRectangle(clientArea);
							}
						});
						
						grid_data = new GridData(GridData.FILL_HORIZONTAL);
						grid_data.heightHint = 2;
						line.setLayoutData(grid_data);
						
						Composite cButtons = new Composite(shell, SWT.NONE);
						FormLayout layout = new FormLayout();
				
						cButtons.setLayout(layout);
						grid_data = new GridData(GridData.HORIZONTAL_ALIGN_END);
						cButtons.setLayoutData(grid_data);
				
						Control lastButton = null;
				
						String[] buttons = { MessageText.getString("Button.yes"), MessageText.getString("Button.no") };
						int defaultButtonPos = 0;
						
						Listener buttonListener = 
							new Listener() 
							{
								@Override
								public void
								handleEvent(
									Event event )
								{
									int index = options.getSelectionIndex();
									
									boolean	yes_selected 	= ((Integer) event.widget.getData()).intValue() == 0;
									boolean	all_domains 	= index==0;
									boolean remember		= rc_check.getSelection();
									
									if ( remember && all_domains && !yes_selected ){
										
							        	MessageBoxShell mb = new MessageBoxShell(
							        			SWT.ICON_WARNING | SWT.YES | SWT.NO,
							        			MessageText.getString("aztorplugin.ask.sure.title"),
							        			MessageText.getString("aztorplugin.ask.sure.msg"));
							        	
							        	mb.setDefaultButtonUsingStyle(SWT.NO);
							        	
							        	mb.setParent( shell );
	
							        	mb.open(
							        		new UserPrompterResultListener() 
							        		{
												@Override
												public void
												prompterClosed(
													int returnVal )
												{
													if (returnVal != SWT.YES) {
												
														return;
													}
														
													result[0] 		= false;
													remembered[0] 	= "*";
														
													shell.dispose();
												}
							        	});
	
									}else{
										result[0] = yes_selected;
										
										if ( remember ){
											
											if ( all_domains ){
												remembered[0] = "*";
											}else{
												remembered[0] = options.getItem(index);
											}
										}
										shell.dispose();
									}
								}
							};
				
						List<Button> swtButtons = new ArrayList<Button>();
						
						for (int i = 0; i < buttons.length; i++) {
							Button button = new Button(cButtons, SWT.PUSH);
							swtButtons.add( button );
							button.setData(new Integer(i));
							button.setText(buttons[i]);
							button.addListener(SWT.Selection, buttonListener);
				
							FormData formData = new FormData();
							if (lastButton != null) {
								formData.left = new FormAttachment(lastButton, 5);
							}
				
							button.setLayoutData(formData);
				
							if (i == defaultButtonPos) {
								button.setFocus();
								shell.setDefaultButton(button);
							}
				
							lastButton = button;
						}
				
						Utils.makeButtonsEqualWidth( swtButtons );
						
						
						shell.addTraverseListener(
							new TraverseListener() 
							{
								@Override
								public void
								keyTraversed(
									TraverseEvent e )
								{
									if ( e.detail == SWT.TRAVERSE_ESCAPE ){
										
										shell.dispose();
										
										e.doit = false;
									}
								}
							});						
						
						Point point = shell.computeSize(SWT.DEFAULT, SWT.DEFAULT);
						point.x = Math.max( 400, point.x );
						shell.setSize(point);
						//shell.pack();
					    Utils.centreWindow(shell);
					    shell.open();
					    
					}catch( Throwable e ){
						
						Debug.out( e );
						
						wait_sem.release();
					}
				}
			});
		
		wait_sem.reserve();
		
		return( prompt_response );
	}
	
	@Override
	public void
	destroy()
	{
		synchronized( this ){
			
			destroyed = true;
			
			if ( active_shells.size() > 0 ){
				
				Utils.execSWTThread(
						new Runnable()
						{
							@Override
							public void
							run()
							{
								List<Shell>	copy;
							
								synchronized( TorPluginUISWT.this ){
								
									copy = new ArrayList<Shell>(active_shells);
								}
								
								for ( Shell shell: copy ){
									
									shell.dispose();
								}
							}
						});
			}
		}
	}
}
