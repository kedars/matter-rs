* Common Error handling instead of &str
* udp.c: Move the 'in_buf' out of the stack to bss
* AEAD: Check if we are actually using the non-alloc version of AEAD
* How to disable 'prints' in release mode?
* I think we should rename packet.rs and PacketParser{} to matter_msg.rs and MatterMsgParser respectively.
* The whole deal with Parsebuf really needs to be reviewed, particularly for lifetime handling. My initial thought was to keep updating the slice stored in Parsebuf and keep shrinking the offets as headers/footers are consumed. But, that is making it trickier with Rust lifetime handling.

* Need to check the use of the 'unsafe' for accessing static mut variables (sessionMgr). For example, only one entity should ever take from this