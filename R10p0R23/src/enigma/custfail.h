/*  fail reason indexes for fail log and pblock errcode */

#define NONE        ((short)0)  /* no failure */
#define DPWD        ((short)1)  /* dynamic pwd */
#define FPWD        ((short)2)  /* fixed pwd */
#define TLOCK       ((short)3)  /* time lock */
#define WLOCK       ((short)4)  /* week lock */
#define DLOCK       ((short)5)  /* date lock */
#define HLOCK       ((short)6)  /* hack(attack) lock */
#define QUOTA0      ((short)7)  /* quota = 0 */
#define FPWDEXP     ((short)8)  /* fixed pwd expired */
#define BADID       ((short)9)  /* bad id */
#define DATEBAD     ((short)10) /* computer date b-4 access(database) created */
#define BADIO       ((short)11) /* bad file io */
#define INTEGRITY   ((short)12) /* program intergrity */
#define PRIVILEGE   ((short)13) /* insuffient privilege */
#define RANGE       ((short)14) /* dynamic password out of range */
#define CARDINIT    ((short)15) /* SafeCard initializtion */
#define PINEXP      ((short)16) /* SoftPIN expired */
#define BADPIN      ((short)17) /* Bad Pin entry */
#define DURESSPIN   ((short)18) /* Duress Pin entry */
#define RECLOCK     ((short)19) /* record locked */
#define TIMEOUT     ((short)20) /* input timeout */
#define BADINPUT    ((short)21) /* to many backspace, delete, or overflow */
#define PRNTBAD     ((short)22) /* Bad fingerprint */
