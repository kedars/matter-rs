* Common Error handling instead of &str
* udp.c: Move the 'in_buf' out of the stack to bss
* AEAD: Check if we are actually using the non-alloc version of AEAD
* How to disable 'prints' in release mode?
* I think we should rename packet.rs and PacketParser{} to matter_msg.rs and MatterMsgParser respectively.


* Need to check the use of the 'unsafe' for accessing static mut variables (sessionMgr). For example, only one entity should ever take from this