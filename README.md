# Gel

GEL - stands for Ghidra Emulation Layer its build to sit a top Ghidra's Existing Pcode Emulation. It is based on a cake model so that
you can successively add subscribers to build up a robust partial emulation enviroment to test and evenually Fuzz Binaries

## Goals of GEL

[] Support Multiple Coordinated Event subsecribers to instrument a given ghidra binary

[] Support Multi-threaded enviroments to investigate race conditions 

[] Support Fuzzing a given target

[] Allow code reuse among subscribers



# Other notes

It might seem odd that we wrap existing API form the emulator helper but this is for error detection from overlaying components smashing
controls over each other. All these controls can be bypassed however 