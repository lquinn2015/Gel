package Gel.subscribers;

import Gel.core.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class DummyPlug implements EventSubscriber{

	
	GhidraScript gs;
	int p;
	
	public DummyPlug(GhidraScript gs, int p) {
		this.p = p;
		this.gs = gs;
	}
	
	@Override
	public int getPriority() {
		
		return p;
	}

	@Override
	public void Arm(GelState state) throws SubscriberMultiAccessException {
		gs.println("Dummy plug Armed");
		
	}

	@Override
	public void onEmulationStart(GelState state) throws SubscriberMultiAccessException {
		gs.println("Dummy plug EmuStart");
	}

	@Override
	public GelReturn onAddressHit(GelState state, Address hit) throws SubscriberMultiAccessException {
		gs.println("Dummy plug onAddrHit");
		return GelReturn.Continue;
	}

	@Override
	public boolean onError(GelState state) throws SubscriberMultiAccessException {
		gs.print("Dummy Plug onError");
		return false;
	}

	@Override
	public void onEmulationEnd(GelState state, Address last) throws SubscriberMultiAccessException {
		gs.println("Dummy Plug onEmuEnder");
	}

	@Override
	public GelReturn onGelMemoryAccess(GelState state, AddressSet set) {
		gs.println("dummy plug GelMemAccess");
		return GelReturn.Continue;
	}

}
