message("Starting to make libannex")

add_library(annex SHARED api_if.c asn1.h dup2.c in_cksum.c proctitle.c     \
                         servname.c srpc.c api_if.h bcopy.c erpc_subr.c    \
			 inet.c random.c slip_layer.c srpc.h asn1.c conv.c \
			 hostname.c ip_layer.c sendrecv.c socket_layer.c   \
			 udp_layer.c)
