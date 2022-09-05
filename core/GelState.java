package Gel.core;


import java.math.BigInteger;
import java.util.HashSet;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class GelState 
{
	private Gel gel;
	HashSet<String> regMap;
	AddressSet memCover;
	
	public GelState(Gel gel) 
	{		
		this.gel = gel;
		regMap = new HashSet<>();
		memCover = new AddressSet();
	}
	
	public void clearTrackedState() {
		regMap.clear();
		memCover.clear();
	}
	
	/***
	 * This is allows you to by pass the safety that GeosState provides when working with 
	 * 		multiple subscribers. Somethings like installing a custom PCode handler is 
	 * 		better done with an instance of the EmulatorHelper. Mostly useful in setup and tear down
	 * @return EmulatorHelper
	 */
	public EmulatorHelper getEmulatorHelper() {
		return gel.gemu;
	}
	
	
	public void writeReg(String reg, long val) throws SubscriberMultiAccessException {writeReg(reg, BigInteger.valueOf(val));}
	public void writeReg(String reg, BigInteger val) throws SubscriberMultiAccessException {
		
		if(regMap.contains(reg)) 
			throw new SubscriberMultiAccessException(reg + " Was written by two subs");
		regMap.add(reg);
		gel.getGemu().writeRegister(reg, val);
	}
		
	public void writeMem(Address addr, byte[] val) throws SubscriberMultiAccessException {
		
		if(memCover.contains(addr))
			throw new SubscriberMultiAccessException(addr + " Was written by two subs");
		memCover.add(addr, addr.add(val.length));
		
		gel.getGemu().writeMemory(addr, val);
	}
	
	public void setBreakpoint(Address addr) {
		gel.getGemu().setBreakpoint(addr);
	}
	
	public byte[] readMem(Address addr, int len) {
		return gel.getGemu().readMemory(addr, len);
	}
	
	public BigInteger readReg(String reg) {
		return gel.getGemu().readRegister(reg);
	}

	public Gel getGel() {
		return gel;
	}

}
