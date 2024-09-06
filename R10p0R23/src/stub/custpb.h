/*
*       custpb.h
*
*       header file with definitions for parameter block stuff
*
*       used by idpasspb and the module that makes calls to it
*
*/

/*  defines for pwd enabled flags   */

#define ENABLED     1
#define DISABLED    0

/*  defines for mode    */

#define CHALLENGE       1
#define EVALUATE_ALL    2
#define RECHALLENGE     3
#define SLI_CHAL_PFX    4
#define SLI_EVAL        5
#define UPDATE_LOGS     6
#define SLI_CHAL_ACE    7
#define SLI_CHAL_PFX_FP 8
#define SLI_CHAL_ACE_FP 9
#define CHANGE_PIN      10
#define VERIFY_PIN      11
#define DO_DYNAMIC      12      /* added for peer-to-peer authentication */

/*  defines for status  */

#define NO_STATUS        0
#define FAIL             1
#define FAIL_MASTER      2
#define PASS             3
#define PASS_MASTER      4
#define GOOD_USER        5
#define BAD_USER         6
#define PASS_PIN         7
#define PIN_FOUND        8
#define PIN_NOT_FOUND    9
#define PIN_VERIFIED     10
#define PIN_NOT_VERIFIED 11
#define GOOD_NO_CHAL     12
#define DYN_PROVIDED     13     /* added for peer-to-peer authentication */
#define DYN_NOT_PROVIDED 14     /* added for peer-to-peer authentication */

/*  The following typedef determines the size of intergers in pblk.
*   16 bit integers are spec'd. Shorts are generally 16 bits.
*/

typedef unsigned short int pbint;

/* - This is the parameter block structure
     (referred to as pblk from here on - */

struct pblk
    {
    char            uport[8],   /* user's port addr (not used this ver.) */
                    id[32],     /* user's name */
                    chal[32],   /* challege data */
                    dynpwd[16], /* dynamic password */
                    fixpwd[32], /* fixed password */
                    nfixpwd[32],/* new fixed password */
                    msg1[80],   /* user message # 1 */
                    msg2[80],   /* user message # 2 */
                    appl[80],   /* application to execute */
                    parm[80],   /* parameter line of application */
                    errcode,    /* typically the reason for failure */
                    source[7],  /* in micom vers, users in coming line */
                    dest[9],    /* in micom vers, users selected resource */
                    pbresrv1;   /* reserved */
    pbint           pbresrv2;   /* for    */
    long            pbresrv3;   /* future */
    pbint           pbresrv4,   /* use    */
                    mode,       /* mode or ID command */
                    fixmin,     /* minimum length for new fixed pwd */
                    dynpwdf,    /* dynamic pwd enabled flag */
                    fixpwdf,    /* fixed pwd enabled flag */
                    echodyn,    /* echo dynamic pwd flag */
                    echofix,    /* echo fixed pwd flag */
                    status;     /* return status */
    };
