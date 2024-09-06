#include <sys/types.h>
#include <unistd.h>
#include <sys/locking.h>
#include <io.h>

/* map function names */

#define far 

#define need_sendmsg
#define need_recvmsg
#ifdef NT32_NUT
#define have_msghdr
#endif
#define need_bcopy
#define need_bzero

#define sendmsg_func xylo_sendmsg
#define recvmsg_func xylo_recvmsg
#define bcopy xylo_bcopy
#define bzero xylo_bzero
#define index strchr
#define random rand
#define srandom srand
#define strncasecmp strnicmp
#define lockf _locking
#define F_TLOCK	_LK_LOCK
#define F_ULOCK	_LK_UNLCK

#define BFS "\\bfs"
#define INSTALL_DIR "\\etc"

#include "libannex.h"
