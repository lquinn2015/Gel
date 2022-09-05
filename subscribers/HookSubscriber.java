package Gel.subscribers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.function.BiFunction;

import Gel.core.*;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class HookSubscriber implements EventSubscriber
{

	private int priority;
	private HashMap<Address, ArrayList<GemuScript>> hookList;
	private Gel gel; 
	
	
	public HookSubscriber(int priority) {
		this.priority = priority;
		hookList = new HashMap<Address, ArrayList<GemuScript>>();
	}
	
	@Override
	public int getPriority() {
		
		return priority;
	}

	@Override
	public void Arm(GelState state) throws SubscriberMultiAccessException {
		gel = state.getGel();
		return;	
	}

	@Override
	public void onEmulationStart(GelState state) throws SubscriberMultiAccessException {
		EmulatorHelper gemu = state.getEmulatorHelper();
		for(Address addr : hookList.keySet()) {
			gemu.setBreakpoint(addr); // add script trigger to break points
		}
		return;	
	}

	@Override
	public GelReturn onAddressHit(GelState state, Address hit) throws SubscriberMultiAccessException {
		
		
		if(hookList.containsKey(hit)) {
			return hookList.get(hit).stream()
				.map((GemuScript g) -> { return g.func.apply(hit,this.gel.getGemu());})
				.min((i,j) -> GelReturn.End.compare(i, j)).orElseThrow();
		} 
		return GelReturn.Continue;
	}

	@Override
	public boolean onError(GelState state) throws SubscriberMultiAccessException {
		return false;
	}

	@Override
	public void onEmulationEnd(GelState state, Address last) throws SubscriberMultiAccessException {
		return;
	}

	@Override
	public GelReturn onGelMemoryAccess(GelState state, AddressSet set) {
		return GelReturn.Continue;
	}

	
	public void AddHook(Address addr2hook, String sname, BiFunction<Address,EmulatorHelper, GelReturn> script) 
	{
		ArrayList<GemuScript> scripts;
		GelState state = gel.getState();
		if(hookList.containsKey(addr2hook)) {
			scripts = hookList.get(addr2hook);
		} else {
			scripts = new ArrayList<>();
		}
		scripts.add(new GemuScript(sname, script));
		state.setBreakpoint(addr2hook);
		hookList.put(addr2hook, scripts);
	}
	
	
	private class GemuScript implements Comparable<GemuScript> 
	{

		String name;
		@SuppressWarnings("unused") // used for storage only
		BiFunction<Address, EmulatorHelper, GelReturn> func;
		
		public GemuScript(String n, BiFunction<Address,EmulatorHelper, GelReturn> script) {
			name = n;
			func = script;
		}

		@Override
		public int compareTo(GemuScript o) {
			if(o == null) return -1;
			if(name == null) return -1;
			return name.compareTo(o.name);
		}
		@Override
		public int hashCode() {return name.hashCode();}
		@Override
		public String toString() {
			return name.toString();
		}
		@Override
		public boolean equals(Object o) {
			return name != null 
					&& o != null 
					&& ((GemuScript)o).name != null
					&& name.equals(((GemuScript)o).name);}
		
	}
}
