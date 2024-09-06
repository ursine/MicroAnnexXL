/*
*    swecapi.h
*
*    Copyright (c) 1995 Enigma Logic Inc.        Concord, CA
*
*    defines and data structures for:
*
*    SafeWord EASSP Client (SWEC) Application Interface (API)
*
*/

typedef unsigned long SwecHdl;  /* type def for handles */

#ifndef PROTOTYPING
# define PROTOTYPING 1
#endif

#if PROTOTYPING
#   define PROTO(x)     x
#else
#   define PROTO(x)     ()
#endif

/* boolean values */
#define SWEC_FALSE   0
#define SWEC_TRUE    1

/* field lengths */
#define SWEC_SWEC_DATA_LENGTH    64
#define SWEC_STATUS_TEXT_LENGTH  256
#define SWEC_APP_CONFIG_LENGTH   80
#define SWEC_ID_SOURCE_LENGTH    32
#define SWEC_HOST_LENGTH         32

/* status codes */
#define SWEC_STATUS_SUCCESS              0
#define SWEC_STATUS_NOT_REGISTERED       27001
#define SWEC_STATUS_INVALID_CONNECT_HDL  27002
#define SWEC_STATUS_ALLOC_ERR            27003
#define SWEC_STATUS_FILE_ERR             27004
#define SWEC_STATUS_NO_SERVER            27005
#define SWEC_STATUS_TIME_OUT             27006
#define SWEC_STATUS_INTERNAL_ERR         27007
#define SWEC_STATUS_INVALID_CONFIG_DATA  27008
#define SWEC_STATUS_CONNECT_FAIL         27009
#define SWEC_STATUS_UNLOADING            27010
#define SWEC_STATUS_DEREGISTERING        27011
#define SWEC_STATUS_USER_ABORT           27012
#define SWEC_STATUS_NO_CALLBACK          27013
#define SWEC_STATUS_NOT_INITIALIZED      27014
#define SWEC_STATUS_APP_REGISTERED       27015
#define SWEC_STATUS_SERVER_BUSY          27016

/* status log codes */
#define SWEC_LOG_NONE       0x0000
#define SWEC_LOG_INFO       0x0001
#define SWEC_LOG_ERROR      0x0002
#define SWEC_LOG_DEBUG      0x0004
#define SWEC_LOG_ALL        0xFFFF

/* dialog types */
#define SWEC_DIALOG_INPUT_ECHO           1
#define SWEC_DIALOG_INPUT_NO_ECHO        2
#define SWEC_DIALOG_INFO                 3

/* input data description codes (used for inputCode) */
#define SWEC_INPUT_NONE                  0
#define SWEC_INPUT_USER_ID               1
#define SWEC_INPUT_PWD                   2
#define SWEC_INPUT_NEW_PWD               3
#define SWEC_INPUT_VERIFY_NEW_PWD        4
#define SWEC_INPUT_AUTHEN_COMBO          5

/* wait callback codes */
#define SWEC_WAIT_CONNECT           1   /* waiting for a server connection */

/* authentication result codes */
#define SWEC_RESULT_INCOMPLETE      0   /* authen process not completed */
#define SWEC_RESULT_PASSED_CHECK    1   /* passed authen,locks,priv,tamper */
#define SWEC_RESULT_BAD_ID          2   /* unknown id */
#define SWEC_RESULT_FAILED_AUTHEN   3   /* failed authentication */
#define SWEC_RESULT_QUOTA_LOCK_ON   4   /* used up usage quota */
#define SWEC_RESULT_TIME_LOCK_ON    5   /* wrong time of day */
#define SWEC_RESULT_DATE_LOCK_ON    6   /* wrong date */
#define SWEC_RESULT_WEEK_LOCK_ON    7   /* wrong day of week */
#define SWEC_RESULT_ATTACK_LOCK_ON  8   /* attack lock triggered */
#define SWEC_RESULT_CLOCK_LOCK_ON   9   /* incorrect system clock setting */
#define SWEC_RESULT_LOW_PRIVILEGE   10  /* insufficent privilege to access */
#define SWEC_RESULT_TAMPER_LOCK_ON  11  /* failed tamper testing */
#define SWEC_RESULT_INPUT_NEEDED    12  /* ok to here, needs more input */
#define SWEC_RESULT_REEVALUATE      13  /* reevaluate */
#define SWEC_RESULT_PASS_DURESS     14  /* passed but used a duress PIN */
#define SWEC_RESULT_PASS_BAD_PIN    15  /* passed but used a bad PIN */
#define SWEC_RESULT_RECORD_LOCKED   16  /* someone else has the record */
#define SWEC_RESULT_INPUT_TIMEOUT   17
#define SWEC_RESULT_LINE_HANGUP     18
#define SWEC_RESULT_BAD_NEW_FIXED   19  /* invalid new fixed password */
#define SWEC_RESULT_PASS_NEED_NEW   20  /* passed but must set new pwd */
#define SWEC_RESULT_SERVER_FAILURE  21  /* server failed during authenticaton */

/* data passed to the dialog callback routine */
typedef struct
{
	int             dialogType;
	char            *dialogMessage;
	char            *dialogInputPrompt;
    int             authenNumber;
    char            *authenName;
    char            *challengeText;
	int             inputCode;
	char            *inputBuffer;
	int             inputBufferLength;
    int             abortFlag;
} SwecDialogRec;

/* Authentication server specification */
typedef struct
{
    char    host[SWEC_HOST_LENGTH];
    int     servicePort;
    int     weight;
    int     maxConnections;
} SwecServerRec;

/* Data and control record for swecRegister() */
typedef struct
{
	int             useSwecDataFileFlag;
	char            *swecData;
	int             useConfigFileFlag;
	char            *configFilePath;
	int             numberOfServers;
    SwecServerRec   *servers;
	char            *systemName;
	char            *dataFilesDir;
	int             consoleLogMask;
	int             userLogMask;
	int             fileLogMask;
	char            *statusFilePath;
	long            maxStatusFileLength;
	char            *textSetName;
    int             textCodeFlag;
    int             maxUsers;
    char            userIdSource[SWEC_ID_SOURCE_LENGTH];
    char            appConfig1000[SWEC_APP_CONFIG_LENGTH];
    char            appConfig1001[SWEC_APP_CONFIG_LENGTH];
    char            appConfig1002[SWEC_APP_CONFIG_LENGTH];
    char            appConfig1003[SWEC_APP_CONFIG_LENGTH];
    void            (*statusLogCallback)PROTO((SwecHdl statusLogContext,
                                         char *statusStr));
    SwecHdl         statusLogContext;
    char            *statusLogLabel;
    void            (*waitCallback)PROTO((int waitCode, int *abortFlag));
	char            statusText[SWEC_STATUS_TEXT_LENGTH];
} SwecRegisterRec;


/* Data and control record for swecOpen() */
typedef struct
{
	int             waitTime;
    int             openAllFlag;
    SwecServerRec   *server;
    int             serverNumber;
    int             numberOfServersOpened;
	char            statusText[SWEC_STATUS_TEXT_LENGTH];
} SwecOpenRec;

/* Data and control record for swecAuthen() */
typedef struct
{
	int             waitTime;
    char            *userId;
    char            *password;
    int             passUserFlag;
	int             resultCode;
	long            actionDataLength;
	char            *actionData;
    void            (*dialogCallback)PROTO((SwecHdl dialogContext,
                                      SwecDialogRec *dialogRecPtr));
    SwecHdl         dialogContext;
	char            statusText[SWEC_STATUS_TEXT_LENGTH];
} SwecAuthenRec;

/* Data and control record for swecClose() */
typedef struct
{
	int             closeAllFlag;
	char            statusText[SWEC_STATUS_TEXT_LENGTH];
} SwecCloseRec;

/* Data and control record for swecDeregister() */
typedef struct
{
	char            swecData[SWEC_SWEC_DATA_LENGTH];
	char            statusText[SWEC_STATUS_TEXT_LENGTH];
} SwecDeregisterRec;

/* Data for swecVersion() */
typedef struct
{
    int     majorVersion;
    int     minorVersion;
    int     revision;
    char    *transport;
    char    *description;
} SwecVersionRec;

/* functions exported by the SWCAPI module */
extern void swecVersion     PROTO((SwecVersionRec *versionRecPtr));
extern int  swecInit        PROTO((void));
extern int  swecRegister    PROTO((SwecHdl *appHandlePtr, 
                                SwecRegisterRec *regRecPtr));
extern int  swecOpen        PROTO((SwecHdl appHandle, SwecHdl 
                                *connectionHandlePtr,
                                SwecOpenRec *openRecPtr));
extern int  swecAuthen      PROTO((SwecHdl appHandle, SwecHdl connectionHandle,
                                SwecAuthenRec *authenRecPtr));
extern int  swecClose       PROTO((SwecHdl appHandle, SwecHdl connectionHandle,
                                SwecCloseRec *closeRecPtr));
extern int  swecDeregister  PROTO((SwecHdl appHandle, 
                                SwecDeregisterRec *deregRecPtr));
extern int  swecLogStatus   PROTO((SwecHdl appHandle, int messageType, 
                                char *message));
extern int  swecUninit      PROTO((int forceDeregisterFlag));
