import Gel.subscribers.*;
import Gel.core.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class EmulateTestProg extends GhidraScript
{

	@Override
	protected void run() throws Exception {
		
		Gel gel = new Gel(this, this.getCurrentProgram());
		DummyPlug dummy = new DummyPlug(this, 2);
		HookSubscriber hooks = new HookSubscriber(1);
		gel.registerSubscriber(dummy);
		gel.registerSubscriber(hooks);
		gel.Arm();
		
		
		for(Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			hooks.AddHook(f.getEntryPoint(), f.getName(), (a,s)->printName(a,s));
		}
		
		GelState s = gel.getState();
		s.writeReg("pc", 0x100e68L);
		s.writeReg("x30", 0);
		s.writeReg("sp", 0xa002000L);
		s.setBreakpoint(toAddr(0x100e6cL));
		s.getEmulatorHelper().enableMemoryWriteTracking(true);
		
		gel.run();
		
		
//		EmulatorHelper gemu = new EmulatorHelper(getCurrentProgram());
//		gemu.writeRegister("pc", 0x100e68L);
//		gemu.writeRegister("x30", 0);
//		gemu.writeRegister("sp", 0xa002000L);
//		gemu.run(getMonitor());
	}
	
	public GelReturn printName(Address hit, EmulatorHelper gemu) {
		String s = "Entering: " + getFunctionAt(hit).getName();
		println(s);
		return GelReturn.Continue;
	}

}
