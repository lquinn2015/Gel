package gel;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;



/***
 * 
 * 
 * 		Execution Life cycle
 * 
 * 			Arm - Emulated Program Memory was reset includes breakpoints
 * 
 * 			onStart		- Emulated Program is starting a emulation path can fire multiple
 * 							times on a single memory state. Imagine thread hopping if
 * 							on thread does a queue put and another does a queue get
 * 
 * 			onAddress 	- When we hit a breakpoint or step we will call your subscriber
 * 							with the address of interest its your job to know if it is	
 * 							a fun address
 * 
 * 			onError		- Error in emulation happend we are letting you know if you can
 * 							handle it we won't kill
 * 
 * 			onEnd		- Emulation has stopped we let you record state if you want
 * 
 * 						/------------------------------
 * 					   \/							  |
 * 			Arm ->  onStart---->onAddress---------->onEnd
 * 			 /\  		|			|
 * 			  \---------/			\<-----onError
 * 
 * @author xphos
 * @return 
 *
 */
public interface EventSubscriber {
	
	/***
	 * This is how you say the order  you want your Event subscriber should be called
	 *	 	If you are transparent and just provide logging set yourself to 0
	 *		If you mutate state you cannot run first because you will confuse other 
	 *		event subscribers. I don't make this mandatory because you might want 
	 *		to do that but its my advice to start
	 * 
	 * @return order2run
	 */
	public int getPriority();
	
	/** When GEL emits the ARM event when it wants dispose the Emulated state
	 * 		This is essential the Init function Setup and register things
	 * 		for your subscriber here that should persist across a Emulated Memory State
	 * 
	 * 		@param {@link GelState} Is the Emulator object you get work with it when its your turn
	 * 				This is a shared object among all Subscribers so beware of directly 
	 * 				Altering state in too places
	 * */
	public void Arm(GelState geos) throws SubscriberMultiAccessException;
	
	/**
	 * 	When GEL sends the onEmulationStart it means you are starting a run of the emulation
	 * 		Multiple Runs can happen over time so beaware this will have multiple invocations
	 * 
	 * 		@param {@link Gel} Emulation Link
	 * */
	public void onEmulationStart(GelState geos) throws SubscriberMultiAccessException;

	/**	When GEL hits a breakpoint it will notify every subscriber so they can react
	 * 		This allows for a laying of work from subscribers and isolating work.
	 * 		This is the only spot you do work. HEY LISTEN UP you 
	 * 	
	 * 		@param {@link GelState} Emulation Link
	 * 		@return {@link GelReturn} 
	 * */
	public GelReturn onAddressHit(GelState geos, Address hit) throws SubscriberMultiAccessException;
	
	/**   GEL Errors are nubulos it could be PCode Emulation error
	 * 			A Memory access Error or anything its your job to ask
	 * 	
	 * 
	 * 		@param {@link GelState} Emulation Link
	 * 		@return true means error was handled false means it was not
	 * */
	public boolean onError(GelState geos) throws SubscriberMultiAccessException;

	/**	GEL emits when you return from the current context or get paused from thread context switch
	 * 		if using threaded mode. You might want to save data here or calculate something before
	 * 		the Emulated state is disposed 
	 * 
	 * 		@param {@link Gel} Emulation Link
	 * */
	public void onEmulationEnd(GelState geos, Address last) throws SubscriberMultiAccessException;

	/***
	 * The needs may exist for things like DMA to trigger events in the context of subscribers
	 * 		Most people should just ignore this but its to allow 
	 * 
	 * @apiNote Not ready for prime time yet experimental 
	 * @param {@link GelState} Emulation Link
	 * @param set This is the addres set that has been effective your job to handle that
	 * @return {@link GelReturn}  If you need to emit a context switch etc etc do it here
	 */
	public GelReturn onGelMemoryAccess(GelState gel, AddressSet set);
}
