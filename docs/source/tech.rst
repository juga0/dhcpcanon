RFC7844 implementation considerations
==========================================

   5. Implementers SHOULD provide a way for clients to control when the
   anonymity profiles are used and when standard behavior is preferred.

This implementation will not support for now the standard behavior as
it would require to implement more functionality and most of the current
tools implement already the standard.
This is intended to be an example of the anonymity profiles implementation.

``SHOULD`` options
----------------

Leases
-------

Retransmission delays
----------------------

Unique identifier (xid) genration
-----------------------------------


RFC2131 functionality not detailed in RFC7844
-------------------------------------------------
   2.2 the allocating
   server SHOULD probe the reused address before allocating the address,
   e.g., with an ICMP echo request, and the client SHOULD probe the
   newly received address, e.g., with ARP.
