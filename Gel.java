package gel;

import java.util.Comparator;
import java.util.PriorityQueue;
import java.util.function.Consumer;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;

/**
 * Gel is  the ghidra emulation layer. This is essentially a scheduler that allows 
 * 		for subscribers. Subscribers allow modification to a EmulatorHelper in a scalable way
 * 		
 * 		GEL is a cake model its really easy to slowly add complexity to emulation and
 * 			most importantly logging and instrumentation. Want to build a Fuzzy on top
 * 			of it go for it. 
 * 		
 * 		Geos is the scheduler / coordinator among subscribers
 * 
 * @author xphos
 *
 */
public class Gel 
{
	
	GhidraScript gs;
	PriorityQueue<EventSubscriber> subscribers;
	EmulatorHelper gemu;
	
	public Gel(GhidraScript gs) {
		this.gs = gs;
		gemu = new EmulatorHelper(gs.getCurrentProgram());
		subscribers = new PriorityQueue<EventSubscriber>(
			
			new Comparator<EventSubscriber>() {	
				@Override
				public int compare(EventSubscriber o1, EventSubscriber o2) {
					return Integer.compare(o1.getPriority(), o2.getPriority());
				}
			});
	}
	
	
	public void registerSubscriber(EventSubscriber e) {
		subscribers.add(e);
	}
	
	public void Arm() {
		gemu.dispose();
		GelState c = new GelState(this.gemu);
		
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
		GelState c = new GelState(this.gemu);
		for(EventSubscriber e : subscribers) {
			e.onEmulationStart(c);
		}
		
		c.clearTrackedState();
		
		boolean isError = false;
		GelReturn next = GelReturn.Continue;
		while(next != GelReturn.End) {
			
			
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
			
			if(state == EmulateExecutionState.BREAKPOINT) {
				next = subscribers.stream().map(s -> {
					try {
						return s.onAddressHit(c, execAddr);
					} catch (SubscriberMultiAccessException e1) {
						System.err.print("We had a access collision");
						e1.printStackTrace();
						return GelReturn.End;
					}
				}).reduce( (x,y) -> x.compareTo(y) <= 0 ? x : y).get();			
			
			}else if (state == EmulateExecutionState.FAULT) {
				
				boolean handled = subscribers.stream().map(s -> {
					
					try {
						return s.onError(c);
					} catch (SubscriberMultiAccessException e1) {
						System.err.println("We had an access collision");
						e1.printStackTrace();
						return false;
					}	
				}).anyMatch(entry -> entry);
				
				if(!handled) {
					System.err.println("No one handled a Fault condition");
					next = GelReturn.End;
				}	
			}	
		}
	}
}
