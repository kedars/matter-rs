* Common Error handling instead of &str
* udp.c: Move the 'in_buf' out of the stack to bss
* AEAD: Check if we are actually using the non-alloc version of AEAD
* How to disable 'prints' in release mode?
* I think we should rename packet.rs and PacketParser{} to matter_msg.rs and MatterMsgParser respectively.
* The whole deal with Parsebuf really needs to be reviewed, particularly for lifetime handling. My initial thought was to keep updating the slice stored in Parsebuf and keep shrinking the offets as headers/footers are consumed. But, that is making it trickier with Rust lifetime handling.
* TLVList:
  * The 'Pointer' could be directly used in the TLVListIterator, makes it common
  * Not too happy with the way iterator_consumer is done for ContainerIterator, we could just zip the internal ListIterator instead?
  * Implement the IntoIterator Trait as well for the TLVElement. This was done earlier, but I backtracker after I ran into same lifetime issues
* Stack Optimisation: Currently the message flows from the bottom to the callback in sequence of callbacks. This may be consuming too much stack.
  * We could restructure this where there is a base function that gets data from the listener, and then makes calls to different layers (parse unencrypted, parse encrypted) in a sequence. Since each layer goes away after getting called, it doesn't end up consuming the stack.
* Need to check the use of the 'unsafe' for accessing static mut variables (sessionMgr). For example, only one entity should ever take from this
* static mut is used, to place structures in BSS instead of heap/stack. Currently an 'init' call is used to indicate this is a singleton. Should enforce some method so that only a single reference to this is acquired.
* Some configurable values like number of exchanges per session, number of sessions supported etc, can be bubbled up to some configurator for this crate. I wonder how that is done.