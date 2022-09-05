package Gel.core;

import java.util.Comparator;
import java.util.PriorityQueue;
import java.util.function.Consumer;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

/**
 * Gel is  the ghidra emulation layer. This is essentially a scheduler that allows 
 * 		for subscribers. Subscribers allow modification to a EmulatorHelper in a scalable way
 * 		
 * 		GEL is a cake model its really easy to slowly add complexity to emulation and
 * 			most importantly logging and instrumentation. Want to build a Fuzzy on top
 * 			of it go for it. 
 * 		
 * 		Gel is the scheduler / coordinator among subscribers
 * 
 * @author xphos
 *
 */
public class Gel {
	
	GhidraScript gs;
	PriorityQueue<EventSubscriber> subscribers;
	EmulatorHelper gemu;
	boolean isArmed;
	
	public Gel(GhidraScript gs, Program program) {
		this.gs = gs;
		this.gemu = new EmulatorHelper(program);
		subscribers = new PriorityQueue<EventSubscriber>(
			
			new Comparator<EventSubscriber>() {	
				@Override
				public int compare(EventSubscriber o1, EventSubscriber o2) {
					return Integer.compare(o1.getPriority(), o2.getPriority());
				}
			});
	}
	
	// This is indirection which allows for implementing downstream multi thread applications
	// Potentially we want to give a different emulator or prehaps we want to run a context
	// switch
	public EmulatorHelper getGemu() {
		return this.gemu;
	}
	
	public GelState getState() {
		return new GelState(this);
	}
	
	public void registerSubscriber(EventSubscriber e) {
		if(isArmed) {gs.printerr("We are already armed"); return;}
		subscribers.add(e);
	}
	
	public void Arm() {
		if(isArmed) {gs.printerr("We are already armed"); return;}
//		gemu.dispose();
		isArmed = true;
		GelState c = new GelState(this);
		
		Consumer<EventSubscriber> arm = s->{
			try {
				s.Arm(c);
			} catch (SubscriberMultiAccessException e) {
				e.printStackTrace();
		}};
		
		subscribers.stream().forEach(arm);
	}
	
	public void run() throws SubscriberMultiAccessException, CancelledException 
	{
		if(!isArmed) {gs.printerr("We are not armed"); return;}
		
		GelState c = new GelState(this);
		for(EventSubscriber e : subscribers) {
			e.onEmulationStart(c);
		}
		
		c.clearTrackedState();
		
		boolean isError = false;
		GelReturn next = GelReturn.Continue;
		while(next != GelReturn.End) {
			
			if(gs.getMonitor().isCancelled()) {
				return;
			}

			c.clearTrackedState();
			switch(next) 
			{
				case Step:
					gemu.step(gs.getMonitor());
					break;
				case Continue:
					gemu.run(gs.getMonitor());
					break;
				case ContextSwitch:
					break;
				case End:
					break;
			}
			
			EmulateExecutionState state = gemu.getEmulateExecutionState();
			Address execAddr = gemu.getExecutionAddress();
			gs.println("Core: addr: " + execAddr.toString(true) + "EmulatorStateNow: " + state.toString());
			
			if(state == EmulateExecutionState.BREAKPOINT) {
				
				next = subscribers.stream().map(s -> {
					try {
						return s.onAddressHit(c, execAddr);
					} catch (SubscriberMultiAccessException e1) {
						gs.printerr("We had a access collision");
						e1.printStackTrace();
						return GelReturn.End;
					}
				}).reduce( (x,y) -> x.compareTo(y) <= 0 ? x : y).get();			
			
			}else if (state == EmulateExecutionState.FAULT) {				
				
				boolean handled = subscribers.stream().map(s -> {
					
					try {
						return s.onError(c);
					} catch (SubscriberMultiAccessException e1) {
						gs.printerr("We had an access collision");
						e1.printStackTrace();
						return false;
					}	
				}).anyMatch(entry -> entry);
				
				if(!handled) {
					gs.printerr("No one handled a Fault condition");
					gs.printerr("Addr = 0x" + execAddr.toString());
					next = GelReturn.End;
				}	
			}	
		}
	
	}
}
