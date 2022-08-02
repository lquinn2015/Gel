package gel;


/***
 * When you get to return a GeosReturn GEL gives you a chance to change something about execution
 * 		For example if you have a gdb look alike and do a step emit a step command.
 * 
 * 		Internally Geos will take the LCM of all subscribers return and do that. This gives a natural
 * 			ordering to things  continue < step < contextSwitch < End
 *		
 *		Continue mean just execute
 *		Step means execute one instruction
 *		ContextSwitch means we should execute something different if possible 
 *			(explore race conditions this way)
 *		End means emulation should end because of some reason
 * 
 * @apiNote ContextSwitch is not ready for prime time
 * @author xphos
 *
 */
public enum GelReturn{
	
	Continue(4),
	Step(3),
	ContextSwitch(2),
	End(1);

	int val;
	GelReturn(int i) {
		val = i;
	}

	
}
