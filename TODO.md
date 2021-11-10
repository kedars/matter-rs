* udp.c: Move the 'in_buf' out of the stack to bss
* AEAD: Check if we are actually using the non-alloc version of AEAD
* How to disable 'prints' in release mode?
* TLVList:
  * The 'Pointer' could be directly used in the TLVListIterator, makes it common
  * Not too happy with the way iterator_consumer is done for ContainerIterator, we could just zip the internal ListIterator instead?
  * Implement the IntoIterator Trait as well for the TLVElement. This was done earlier, but I backtracker after I ran into same lifetime issues
* Some configurable values like number of exchanges per session, number of sessions supported etc, can be bubbled up to some configurator for this crate. I wonder how that is done.
* About outgoing counter, is it incremented if we send mutliple acknowledgements to the same retransmitted packet? So let's say peer retransmits a packet with ctr 4, for 3 times. Our response ctr, is, say 20. Then should we respond with 20, 21, 22, or 20, 20, 20?
* Need to manage the I2R and R2I stuff well, based on who is the Initiator and Responder
* I had to use Box::new() to pin ownership for certain objects. Not yet able to use try_new() in the stable releases, and I am not a fan of APIs that panic. We should mostly look at things like heapless:pool or stuff. These objects should really be in the bss, with a single ownership.
* Session:
  - Session 0 must always be with no-encryption. This is currently violated in the code because we use bypass mode
  - Allow unencrypted messages _only_ for PASE, CASE messages
* ACK:
  - If a command expects no response, we need to send the acknowledgement back to the sender