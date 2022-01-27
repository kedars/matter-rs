* udp.c: Move the 'in_buf' out of the stack to bss
* TLVList:
  * The 'Pointer' could be directly used in the TLVListIterator, makes it common
  * Not too happy with the way iterator_consumer is done for ContainerIterator, we could just zip the internal ListIterator instead?
  * Implement the IntoIterator Trait as well for the TLVElement. This was done earlier, but I backtracker after I ran into same lifetime issues
* Some configurable values like number of exchanges per session, number of sessions supported etc, can be bubbled up to some configurator for this crate. I wonder how that is done.
* About outgoing counter, is it incremented if we send mutliple acknowledgements to the same retransmitted packet? So let's say peer retransmits a packet with ctr 4, for 3 times. Our response ctr, is, say 20. Then should we respond with 20, 21, 22, or 20, 20, 20?
* I had to use Box::new() to pin ownership for certain objects. Not yet able to use try_new() in the stable releases, and I am not a fan of APIs that panic. We should mostly look at things like heapless:pool or stuff. These objects should really be in the bss, with a single ownership.
* Session:
  - Some reaper thread must go through the stale sessions/exchanges and clear them off
* It might be more efficient to avoid using .find_element() on TLVs. Earlier it was created this way because the spec mentions that the order may change, but it appears that this is unlikely, looking at the C++ implementation. If so, we could be faster, by just specifying looking for tag followed by value.
* PASE:
  - Pick some sensible and strong values for PBKDF2{iterCnt and Salt-length} based on SoC capability
  - Verifier should only store w0 and L, w1 shouldn't even be stored 
  - Allow some way to open the PASE window
  - Allow some way to pass in the 'passcode' and 'salt'
  - In case of error in any of the legs, return StatusReport
  - Provide a way to delete the exchange
  - SPAKE2+: the check with I (abort if `h*X == I`), as indicated by the RFC is pending

* Implement the ARM Fail Safe and Regulatory Config properly. Currently we just ack them to proceed further
* Currently AEAD, sha256 etc are directly used from rust crates. Instead use implementations from openssl/mbedtls - Done. Upstream MRs pending
* rust-mbedTLS: We have to do some gymnastics because current APIs only support signature encoded in ASN1 format. Fix this upstream
* The 'async' requiring 2 buffers is just icky! I tried with peek_from(), but somehow that isn't blocking, causing this requirement
* CASE:
  - Handle initial MRP Parameters struct from Sigma1
  - Sigma2: perform signature verification of the sig received from initiator
* FailSafe:
  - Enable timer and expiration handling for fail-safe context
* Cert Verification:
  - Basic certificate chain verification 
  - Time validation (Not Before/Not After)
  - KeyUsage flags and others are pending
* Cert:
  - Create an intermediate cert representation, instead of parsing the TLV array everytime
