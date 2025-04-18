#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <semaphore.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <poll.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <resolv.h>

#include "sirik_core.h"
#include "sirik_socket.h"

#ifndef LIB_SIRIK_DIAM_H
#define LIB_SIRIK_DIAM_H
#include "jansson.h"

#define SIRIK_DIAM_OCTET_STRING 				1
#define SIRIK_DIAM_SIGNED_32 					2
#define SIRIK_DIAM_SIGNED_64 					3
#define SIRIK_DIAM_UNSIGNED_32 					4
#define SIRIK_DIAM_UNSIGNED_64 					5
#define SIRIK_DIAM_GROUPED 						6
// #define SIRIK_DIAM_FLOAT_32 					7
// #define SIRIK_DIAM_FLOAT_64 					8


// Informational
#define DIAMETER_MULTI_ROUND_AUTH 								1001

// Success
#define DIAMETER_SUCCESS 										2001
#define DIAMETER_LIMITED_SUCCESS 								2002

// Protocol Errors
#define DIAMETER_COMMAND_UNSUPPORTED 							3001
#define DIAMETER_UNABLE_TO_DELIVER 								3002
#define DIAMETER_REALM_NOT_SERVED 								3003
#define DIAMETER_TOO_BUSY 										3004
#define DIAMETER_LOOP_DETECTED 									3005
#define DIAMETER_REDIRECT_INDICATION 							3006
#define DIAMETER_APPLICATION_UNSUPPORTED 						3007
#define DIAMETER_INVALID_HDR_BITS 								3008
#define DIAMETER_INVALID_AVP_BITS 								3009
#define DIAMETER_UNKNOWN_PEER 									3010

// Transient Failures
#define DIAMETER_AUTHENTICATION_REJECTED 						4001
#define DIAMETER_OUT_OF_SPACE 									4002
#define ELECTION_LOST 											4003
#define DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE				4181		//s6a
#define DIAMETER_ERROR_CAMEL_SUBSCRIPTION_PRESENT				4182		//s6a

// Permanent Failures
#define DIAMETER_AVP_UNSUPPORTED 								5001
#define DIAMETER_UNKNOWN_SESSION_ID 							5002
#define DIAMETER_AUTHORIZATION_REJECTED 						5003
#define DIAMETER_INVALID_AVP_VALUE 								5004
#define DIAMETER_MISSING_AVP 									5005
#define DIAMETER_RESOURCES_EXCEEDED 							5006
#define DIAMETER_CONTRADICTING_AVPS 							5007
#define DIAMETER_AVP_NOT_ALLOWED 								5008
#define DIAMETER_AVP_OCCURS_TOO_MANY_TIMES 						5009
#define DIAMETER_NO_COMMON_APPLICATION 							5010
#define DIAMETER_UNSUPPORTED_VERSION 							5011
#define DIAMETER_UNABLE_TO_COMPLY 								5012
#define DIAMETER_INVALID_BIT_IN_HEADER 							5013
#define DIAMETER_INVALID_AVP_LENGTH 							5014
#define DIAMETER_INVALID_MESSAGE_LENGTH 						5015
#define DIAMETER_INVALID_AVP_BIT_COMBO 							5016
#define DIAMETER_NO_COMMON_SECURITY 							5017

//CXDX
#define DIAMETER_ERROR_IDENTITIES_DONT_MATCH       				5002
#define DIAMETER_ERROR_IDENTITY_NOT_REGISTERED        			5003
#define DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED          		5006
#define DIAMETER_ERROR_IN_ASSIGNMENT_TYPE       				5007
#define DIAMETER_ERROR_TOO_MUCH_DATA       						5008
#define DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA        			5009
#define DIAMETER_ERROR_FEATURE_UNSUPPORTED						5011
#define DIAMETER_ERROR_SERVING_NODE_FEATURE_UNSUPPORTED 		5012

//EXPERIMENTAL
#define DIAMETER_ERROR_USER_UNKNOWN 							5001
#define DIAMETER_ERROR_IDENTITY_NOT_REGISTERED 					5003
#define DIAMETER_ERROR_ROAMING_NOT_ALLOWED 						5004
#define DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED 				5005
#define DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION					5420		//s6a
#define DIAMETER_ERROR_RAT_NOT_ALLOWED							5421		//s6a
#define DIAMETER_ERROR_EQUIPMENT_UNKNOWN						5422		//s6a
#define DIAMETER_ERROR_UNKOWN_SERVING_NODE						5423		//s6a 
#define DIAMETER_ERROR_USER_NO_NON_3GPP_SUBSCRIPTION 			5450
#define DIAMETER_ERROR_USER_NO_APN_SUBSCRIPTION 				5451
#define DIAMETER_ERROR_RAT_TYPE_NOT_ALLOWED 					5452
#define DIAMETER_ERROR_LATE_OVERLAPPING_REQUEST 				5453
#define DIAMETER_ERROR_TIMED_OUT_REQUEST 						5454
#define DIAMETER_ERROR_ILLEGAL_EQUIPMENT 						5554


#define SIRIK_DIAM_AVP_CODE_USERNAME 							1
#define SIRIK_DIAM_AVP_CODE_SESSION_TIME_OUT 					27
#define SIRIK_DIAM_AVP_CODE_ACCT_INTERIM_INTERAVAL 				85
#define SIRIK_DIAM_AVP_CODE_VENDOR_SPEC_APP_ID 					260
#define SIRIK_DIAM_AVP_CODE_SESSION_ID 							263
#define SIRIK_DIAM_AVP_CODE_ORIGIN_HOST 						264
#define SIRIK_DIAM_AVP_CODE_SUPPORTED_VENDOR_ID 				265
#define SIRIK_DIAM_AVP_CODE_VENDOR_ID 							266
#define SIRIK_DIAM_AVP_CODE_RESULT_CODE 						268
#define SIRIK_DIAM_AVP_CODE_AUTH_REQUEST_TYPE 					274
#define SIRIK_DIAM_AVP_CODE_AUTH_SESSION_STATE 					277
#define SIRIK_DIAM_AVP_CODE_ROUTE_RECORD 						282
#define SIRIK_DIAM_AVP_CODE_ORIGIN_REALM 						296
#define SIRIK_DIAM_AVP_CODE_PRODUCT_NAME 						269
#define SIRIK_DIAM_AVP_CODE_AUTH_APPLICATION_ID 				258
#define SIRIK_DIAM_AVP_CODE_ACCT_APPLICATION_ID 				259
#define SIRIK_DIAM_AVP_CODE_HOST_IP_ADDRESS 					257
#define SIRIK_DIAM_AVP_CODE_ORIGIN_STATE_ID 					278
#define SIRIK_DIAM_AVP_CODE_FAILED_AVP 							279
#define SIRIK_DIAM_AVP_CODE_INBAND_SECURITY_ID 					299
#define SIRIK_DIAM_AVP_CODE_FIRMWARE_REVISION 					267
#define SIRIK_DIAM_AVP_CODE_ERROR_MESSAGE 						281
#define SIRIK_DIAM_AVP_CODE_REDIRECT_HOST 						292
#define SIRIK_DIAM_AVP_CODE_DESTINATION_HOST 					293
#define SIRIK_DIAM_AVP_CODE_DESTINATION_REALM 					283
#define SIRIK_DIAM_AVP_CODE_TERMINATION_CAUSE 					295
#define SIRIK_DIAM_AVP_CODE_EXPERIMANTAL_RESULT 				297
#define SIRIK_DIAM_AVP_CODE_EXPERIMANTAL_RESULT_CODE 			298
#define SIRIK_DIAM_AVP_CODE_EAP_MASTER_SESSION_KEY 				464
#define SIRIK_DIAM_AVP_CODE_VISITED_NETWORK_IDENTIFIER 			600
#define SIRIK_DIAM_AVP_CODE_SERVER_ASSIGNMENT_TYPE 				614
#define SIRIK_DIAM_AVP_CODE_RAT_TYPE 							1032
#define SIRIK_DIAM_AVP_CODE_TERMINAL_INFORMATION 				1401
#define SIRIK_DIAM_AVP_CODE_IMEI 								1402
#define SIRIK_DIAM_AVP_CODE_SOFTWARE_VERSION 					1403
#define SIRIK_DIAM_AVP_CODE_VISITED_PLMN_ID 					1407
#define SIRIK_DIAM_AVP_CODE_REQ_EUTRAN_AUTH_INFO 				1408
#define SIRIK_DIAM_AVP_CODE_NO_OF_REQUESTED_VECTORS 			1410
#define SIRIK_DIAM_AVP_CODE_IMMIDIATE_RESPONSE_PREFFERED 		1412
#define SIRIK_DIAM_AVP_CODE_EQUIPMENT_STATUS 					1445
#define SIRIK_DIAM_AVP_CODE_RAND 								1447
#define SIRIK_DIAM_AVP_CODE_XRES 								1448
#define SIRIK_DIAM_AVP_CODE_AUTN 								1449
#define SIRIK_DIAM_AVP_CODE_KASME 								1450

#define SI_DIAM_BUFFER_SIZE										4096
#define SI_DIAM_BUFFER_ERROR_INSUFFICENT						501






#pragma pack(4)
typedef struct __si_diam_buffer
{
	struct __si_diam_buffer * Next;
	
	u_char buffer[SI_DIAM_BUFFER_SIZE];
	//u_char * buffer;
	uint32_t len;
	uint32_t pos;
	uint32_t error;
	
	SI_DiamNode * srcDiamNode;	
	SI_Socket * siSocket;
} SI_DiamBuffer;

#pragma pack(1)
typedef struct __si_diam_cmd_flags
{
	uint8_t Reserved : 4;
	uint8_t Retransmit : 1;
	uint8_t Error: 1;
	uint8_t Proxyable : 1;
	uint8_t Request : 1;
} SI_DiamCmdFlags;

#pragma pack(1)
typedef struct __si_diam_avp_flags
{
	uint8_t Reserved : 5;
	uint8_t Protected : 1;
	uint8_t Mandatory : 1;
	uint8_t VendorSpecific : 1;
} SI_DiamAvpFlags;

#pragma pack(4)
typedef struct __si_diam_avp
{
	int32_t AvpCode;
	int32_t HeaderLen;
	int32_t AvpLength;
	int32_t Padding;
	uint32_t AvpCount;
	
	uint32_t VendorId;	
	uint8_t DataType;
	
	int32_t intVal;
	uint32_t usIntVal;
	
	int64_t int64Val;
	uint64_t usInt64Val;
	
	SI_DiamAvpFlags Flags;
	unsigned char * data;
	//we will use usInt64Val for data-length
	
	struct __si_diam_avp * Head;
	struct __si_diam_avp * Next;

	struct __si_diam_avp * GroupHead;
	struct __si_diam_avp * GroupCurrent;
	
} SI_DiamAvp;

#pragma pack(4)
typedef struct __si_diam_message_info
{
	SI_DiamAvp * SessionId;
	SI_DiamAvp * OriginHost;
	SI_DiamAvp * OriginRealm;
	SI_DiamAvp * DestinationHost;
	SI_DiamAvp * DestinationRealm;
	
	unsigned int ResultCode;
	unsigned int RequestNumber;
	unsigned int RequestType;
	
	long long int IMSI;
	long long int MSISDN;
	long long int IMEI;
	
} SI_DiamMessageInfo;

#pragma pack(4)
typedef struct __si_diam_header
{
	uint8_t Version;
	uint32_t Length : 24;
	SI_DiamCmdFlags Flags;
	uint32_t CommandCode : 24;
	uint32_t ApplicationId;
	uint32_t HBHId;
	uint32_t E2EId;
} SI_DiamHeader;

#pragma pack(4)
typedef struct __si_diam_client_thread
{
	struct __si_diam_client_thread * Next;
	
	SI_DiamNode * diamNode;
	SI_Socket * siSocket;
	uint32_t isActive;
	uint8_t TransportType;
	sem_t sem_lock;
	
} SI_DiamClientThread;

#pragma pack(4)
typedef struct __si_diam_message
{
	SI_DiamHeader Header;
	
	SI_DiamMessageInfo * diamAvpinfo;
	
	struct __si_diam_avp * Head;
	struct __si_diam_avp * Next;
	
	uint32_t AvpCount;
	//pthread_mutex_t Lock;
	
	//SI_DiamNode * diamNode;
	SI_Socket * siSocket;
	SI_DiamNode * srcDiamNode;
} SI_DiamMessage;


#pragma pack(4)
typedef struct __si_diam_peer
{
	SI_DiamAvp HostName;
	SI_DiamAvp RealmName;
	SI_DiamAvp ProductName;
	
	uint32_t ApplicationId;
	
	uint32_t AuthApplicationId[10];
	uint32_t AuthApplicationIdCount;
	
	uint32_t IsCEASuccess;
	uint32_t PendingWatchDogResponse;
	uint64_t RequestNo;
	uint64_t ResponseNo;
	uint32_t IdleTime;
	uint32_t VendorId;
	uint32_t OriginStateId;
	
	SI_Socket * siSocket;
} SI_DiamPeer;

#pragma pack(4)
typedef struct __si_diam_node_result
{
	SI_DiamNode * DiamNodes[10];
	uint32_t NodeCount;
	
	SI_DiamNode * srcNode;
	uint32_t selfTest;
	int findAppServerOrClient;	// -1 Not Set, 0 Client, 1 - Server, 
	
	//uint32_t ApplicationId;
	uint32_t AuthApplicationId;
	uint32_t AcctApplicationId;
	uint32_t VendorId;
	uint32_t CmdCode;
	__si_string200_t destHost;
	__si_string200_t destRealm;
} SI_DiamNodeResult;

#pragma pack(4)
typedef struct __si_diam_address
{
	uint16_t Type; 
	u_char address[16];
	int addressLen;
} SI_DiamAddress;

SI_DiamNode * __si_diam_find_next_node( SI_DiamNodeResult * ptrDiamNodeResult);
void __si_diam_memsetDiamNodeResult( SI_DiamNodeResult * ptrDiamNodeResult);

typedef void ( * app_message_handler)( SI_DiamMessage *);

#pragma pack(4)
typedef struct __si_diam_session_item
{
	uint32_t EndToEndId;
	uint32_t FSMId;
	uint8_t * Object;
} SI_DiamSession_t;

typedef struct __si_diam_request_interface __si_diam_request_interface_t;
typedef struct __si_lte_ue __si_lte_ue_t;

#pragma pack(4)
typedef struct __si_diam_ans_envelope
{
	SI_DiamMessage * dMesg;
	__si_lte_ue_t * uE;
	uint32_t applicationId;
	uint32_t cmdCode;
	uint32_t E2EId;
} SI_DiamAnsEnvelope;

#pragma pack(4)
typedef struct __si_diam_request
{
	struct __si_diam_request * Next;
	
	__si_diam_request_interface_t * interface;
	SI_IndexRow * indexRow;
	
	__si_lte_ue_t * uE;
	uint32_t CmdCode;
	uint32_t E2EId;
	SI_Timer * timer;

} __si_diam_request_t;

typedef void (*__fp_dm_req_onanswer)( SI_DiamMessage * dMsg, __si_lte_ue_t *, uint32_t applicationId, uint32_t commandCode, uint32_t E2EId);
typedef void (*__fp_dm_req_ontimeout)(__si_lte_ue_t *, uint32_t applicationId, uint32_t commandCode, uint32_t E2EId);

#pragma pack(4)
typedef struct __si_diam_request_interface
{
	struct __si_diam_request_interface * Next;
	
	si_sirik_pool_t * diamRequestTable;
	uint64_t ApplicationId;
	uint32_t Count;
	uint32_t Timeout;
	SI_IndexTable * indexTable;
	__fp_dm_req_onanswer onAnswer;
	__fp_dm_req_ontimeout onTimeOut;
	//void (*onAnswer)( SI_DiamMessage * dMsg, __si_lte_ue_t *, uint32_t applicationId, uint32_t commandCode, uint32_t E2EId);
	//void (*onTimeOut)(__si_lte_ue_t *, uint32_t applicationId, uint32_t commandCode, uint32_t E2EId);
	
} __si_diam_request_interface_t;


#pragma pack(4)
typedef struct __si_lte_ue_service_units
{
	uint32_t RatingGroup;
	uint64_t GrantedServiceUnits;
	uint64_t UsedServiceUnits;
} __si_lte_ue_service_units_t;

#pragma pack(4)
typedef struct __si_lte_ue
{
	struct __si_lte_ue * Next;
	
	__si_diam_request_t * requestHead;
	__si_diam_request_t * requestCurrent;
	int requestCount;
	pthread_mutex_t requestLock;
	
	uint16_t mcc;
	uint16_t mnc;
	unsigned char PLMN[4];
	
	char cIMSI[20];
	int cIMSIlen;
	
	uint64_t IMSI;
	uint64_t IMEI;
	char SoftwareVersion[5];
	
	char publicId[150];
	int publicIdLen;

	char privateId[150];
	int privateIdLen;

	char GxSessionId[100];
	uint32_t GxRequestNumber;
	
	uint32_t GxResultCode;
	__si_lte_ue_service_units_t GxUsageMonitoringInfo[2];
	uint32_t GxUsageMonitoringInfoCount;
	
	uint8_t * Parent;
	uint8_t * Object_1;
	uint8_t * Object_2;
	uint8_t * Object_3;
	uint8_t * Object_4;						// for 	
	
	__si_loadtestitem_t * loadtestitem;		// Required for SelfTest
	
} __si_lte_ue_t; 

#pragma pack(4)
typedef struct __si_diam_msg_context
{
	struct __si_diam_msg_context * Next;
	
	uint32_t applicationId;
	uint32_t cmdCode;
	char * destHost;
	char * destRealm;
	char * draRealm;

	char * diamDestHost;		// to fill in Diameter Message
	char * diamDestRealm;		// to fill in Diameter Message
	
} SI_DiamMsgCtx;

#pragma pack(4)
typedef struct __si_diam_stack
{
	uint32_t isDRA;
	int EnableRoutingLog;
	uint32_t ApplicationId[10];
	uint32_t ApplicationCount;
	
	//SI_DiamNode * HostNode;
	//SI_DiamNode * PeerNodeHead;
	
	__si_diam_request_interface_t * interfaceHead;
	__si_diam_request_interface_t * interfaceCurrent;
	
	uint32_t HBHId;
	pthread_mutex_t HBHIdLock;
	
	uint32_t E2EId;	
	pthread_mutex_t E2EIdLock;
	
	uint32_t SessionIdMin;
	uint32_t SessionIdMax;	
	pthread_mutex_t SessionIdLock;
	
	uint32_t OriginStateId;
	
	SI_DiamClientThread * ClientThreadHead;
	SI_DiamClientThread * ClientThreadCurrent;
	pthread_mutex_t ClientThreadLock;
	
	SI_DiamNode * peerTableHead;
	SI_DiamNode * peerTableCurrent;
	pthread_mutex_t peerTableLock;
	
	SI_DiamBuffer * diamBufferPoolHead;
	SI_DiamBuffer * diamBufferPoolCurrent;
	uint32_t diamBufferPoolAvailable;
	uint64_t diamBufferPoolLastUsed;
	uint64_t diamBufferPoolUsed;
	uint32_t diamBufferPoolTotal;
	pthread_mutex_t diamBufferPoolLock;
	
	SI_DiamMessage * diamMessagePoolHead;
	SI_DiamMessage * diamMessagePoolCurrent;
	uint32_t diamMessagePoolAvailable;
	uint32_t diamMessagePoolTotal;
	pthread_mutex_t diamMessagePoolLock;
	
	struct tm * start_time;
	void * decodeQueue;
	uint32_t diamStackThreads;
	uint32_t diamBuffPoolSize;
	
	uint64_t TotalMessagesReceived;
	uint64_t TotalMessagesSent;
	
} SI_DiamStack;

SI_DiamStack * __siDiamStack;

void  __si_diam_create_IndexTable( uint32_t stNumber, uint32_t maxSessions);

typedef int (*app_peer_info_callback)( u_char * hostName);
void __si_diam__set_peerInfoCallback( app_peer_info_callback cb);

void  __si_diam_create_IndexTable( uint32_t stNumber, uint32_t maxSessions);
uint32_t __si_diam_get_data_type( uint32_t avpCode, uint32_t applicationId);
void __si_diam_stack_enable_routing_log( int enable);
void __si_diam__peertable_add( SI_DiamNode * );

void __si_diam_stack_init( json_t * json);
void __si_diam_stack_set_dra();
void __si_diam_stack_set_host_node( SI_DiamNode * ptrHostNode);

uint32_t __si_diam__get_request_number( __si_lte_ue_t * uE);
void  __si_diam__set_request_number( __si_lte_ue_t * uE, uint32_t RequestNumber);

void __si_diam_set_length( uint32_t * len, uint32_t length_val);
uint32_t __si_diam_get_length( uint32_t len);

void __si_diam_add_avp_to_avp( SI_DiamAvp * pDiamAvp, SI_DiamAvp * oDiamAvp);
void __si_diam_add_avp( SI_DiamMessage * msg, SI_DiamAvp * oDiamAvp);

void __si_diam_calc_CurrentTime( u_char * timestamp, int local);
void __si_diam_calc_Time( u_char * timestamp, int addseconds);
void __si_diam_add_time_avp( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, uint32_t secondsFromNow);
void __si_diam_add_time_avp_to_grpavp( SI_DiamAvp * pDiamAvp, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, uint32_t secondsFromNow);

SI_DiamAvp * __si_diam_new_string_avp( uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, unsigned char * data, int len);

void __si_diam_add_uint32_avp( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, uint32_t val);
void __si_diam_add_uint32_avp2( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, SI_U32 * u32);

void __si_diam_add_uint64_avp( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, uint64_t val);
void __si_diam_add_uint64_avp2( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, SI_U64 * u64);

void __si_diam_set_string_avp( SI_DiamAvp * oDiamAvp, unsigned char * data, int len);
void __si_diam_add_string_avp( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, unsigned char * data, int len);
void __si_diam_add_string_avp2( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, __si_stringv_t * strv);

void __si_diam_add_int32_avp( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, int32_t len);
void __si_diam_add_int32_avp2( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, SI_I32 * i32);

void __si_diam_add_int64_avp( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, int64_t len);
void __si_diam_add_int64_avp2( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, SI_I64 * i64);

SI_DiamAvp * __si_diam_add_grouped_avp( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory);
SI_DiamAvp * __si_diam_add_grouped_avp_toavp( SI_DiamAvp * pDiamAvp, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory);

void __si_diam_add_uint32_avp_to_grpavp( SI_DiamAvp * pDiamAvp, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, uint32_t val);
void __si_diam_add_uint32_avp_to_grpavp2( SI_DiamAvp * pDiamAvp, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, SI_U32 * u32);

void __si_diam_add_string_avp_to_grpavp( SI_DiamAvp * pDiamAvp, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, unsigned char * data, int len);
void __si_diam_add_string_avp_to_grpavp2( SI_DiamAvp * pDiamAvp, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, __si_stringv_t * strp);

void __si_diam_add_uint64_avp_to_grpavp( SI_DiamAvp * pDiamAvp, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, int64_t val);
void __si_diam_add_uint64_avp_to_grpavp2( SI_DiamAvp * pDiamAvp, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, SI_U64 * u64);

void __si_diam_add_ipV4address_avp( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, u_char * ipadd);
void __si_diam_add_ipV4address_avp_to_grouped_avp( SI_DiamAvp * oDiamAvp, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, u_char * ipadd);
void __si_diam_add_ipV6address_avp_to_grouped_avp( SI_DiamAvp * oDiamAvp, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, uint8_t ipv6[]);

typedef void ( * app_diambuffer_handler)( SI_DiamBuffer *);
typedef uint8_t ( * app_diam_dict_handler)( uint32_t avpCode, uint32_t applicationId);

void __si_diam_set_dict_pre_handler( app_diam_dict_handler dictHandler);
void __si_diam_set_dict_post_handler( app_diam_dict_handler dictHandler);

void __si_diam_set_msg_handler( app_message_handler msgHandler);
void __si_diam_set_diambuffer_handler( app_diambuffer_handler diamBuffHandler);

SI_DiamMessage * __si_diam_create_request( uint32_t commandCode, uint32_t applicationId);
SI_DiamMessage * __si_diam_create_request2( uint32_t commandCode, uint32_t applicationId, uint32_t E2EId);
SI_DiamMessage * __si_diam_create_request3( uint32_t commandCode, uint32_t applicationId, uint8_t * obj1, timer_handler handler, int timeout_secs);
uint8_t * __si_diam_create_request3_getobject( uint32_t E2EId);
uint8_t * __si_diam_create_request3_findobject( uint32_t E2EId);
void __si_diam_create__request3__clear_timer( SI_DiamMessage * dMesg);

SI_DiamMessage * __si_diam_create_answer( SI_DiamMessage * dmRequest);
SI_DiamMessage * __si_diam_create_message();
SI_DiamMessage * __si_diam_create_message2( uint32_t cmdCode, uint32_t applicationId, uint32_t hbhId, uint32_t e2eId, uint32_t isRequest);

void __si_diam_start_host( SI_DiamNode * prtDiamNode);
void __si_diam_start_peer( SI_DiamNode * prtDiamNode);

uint32_t __si_diam_getE2EId();
uint32_t __si_diam_getHBHId();

void __si_diam_find_node( SI_DiamNodeResult * ptrDiamNodeResult);
SI_DiamNode * __si_diam_find_byid( char * id);
SI_DiamNode * __si_diam_find_node2( uint32_t cmdCode , uint32_t applicationId, uint32_t iLoadInfo);
SI_DiamNode * __si_diam_getPeerNodeByApplicationId1( uint32_t applicationId);
SI_DiamNode * __si_diam_getPeerNodeByApplicationId2( uint32_t applicationId, uint64_t imsi);
SI_DiamNode * __si_diam_getPeerNodeByApplicationId3( uint32_t applicationId, char * realm);


void __si_diam_add_host_name( SI_DiamMessage * msg, SI_DiamNode * hostNode);
void __si_diam_add_host_realm( SI_DiamMessage * msg, SI_DiamNode * hostNode);
void __si_diam_generate_sessionid( u_char * sessionId, SI_DiamNode * hostNode);
void __si_diam_generate_sessionid2( __si_string100_t * sessionId, SI_DiamNode * hostNode);
void __si_diam_generate_sessionid3( __si_stringv_t * sessionId, SI_DiamNode * hostNode);
void __si_diam_add_peer_name( SI_DiamMessage * msg, SI_DiamNode * diamNode);
void __si_diam_add_peer_realm( SI_DiamMessage * msg, SI_DiamNode * diamNode);
void __si_diam_add_peer_realm2( SI_DiamMessage * msg, char * destRealm, SI_DiamNode * diamNode);

int __si_diam_send_message( SI_DiamMessage * dMsg, SI_DiamNode * prtDiamNode);


uint32_t __si_diam_get_cmdcode( SI_DiamMessage * dMsg);
SI_DiamCmdFlags * __si_diam_get_cmdflags( SI_DiamMessage * dMsg);
uint32_t __si_diam_get_applicationid( SI_DiamMessage * dMsg);
uint32_t __si_diam_get_hbhid( SI_DiamMessage * dMsg);
uint32_t __si_diam_get_e2eid( SI_DiamMessage * dMsg);

void __si_diam_log_message( SI_DiamMessage * dMsg);
void __si_diam_print_message( SI_DiamMessage * dmMsg);

int __si_diam_get_diam_address_g( uint32_t avpCode, SI_DiamAvp * dmGroupedAvp, int index, SI_DiamAddress * address);

SI_DiamAvp * __si_diam_find_avp( uint32_t avpCode, uint32_t index, SI_DiamMessage * dmMsg);
uint32_t __si_diam_find_avp_count( uint32_t avpCode, SI_DiamMessage * dmMsg);
uint32_t __si_diam_find_avp_count_in_group( uint32_t avpCode, SI_DiamAvp * pDmAvp);
uint8_t __si_diam_copy_stringAvpVal_tostring( uint32_t avpCode, uint32_t index, SI_DiamMessage * dmSource, u_char * dPtr, int max);
uint8_t __si_diam_copy_string_avp( uint32_t avpCode, uint32_t index, SI_DiamMessage * dmSource, SI_DiamMessage * dmTarget);
uint8_t __si_diam_copy_avp( uint32_t avpCode, uint32_t index, SI_DiamMessage * dmSource, SI_DiamMessage * dmTarget);
SI_Socket * __si_diam_get_socket( SI_DiamMessage * dmReq);
int __si_diam_send_answer( SI_DiamMessage * dmReq, SI_DiamMessage * dmAns);

void __si_diam_add_vendor_specific_auth_applicationid_avp( SI_DiamMessage * msg, uint32_t vendorId, uint32_t authAppId);
void __si_diam_add_experimental_result_code_avp( SI_DiamMessage * msg, uint32_t vendorId, uint32_t resultCode);
void __si_diam_add_experimental_result_code_avp2( SI_DiamMessage * msg, uint32_t vendorId, SI_U32 * resultCode);

void __si_diam_freeMessage( SI_DiamMessage * oDiamMsg);
void __si_diam_freeMessage2( SI_DiamMessage * oDiamMsg);
void __si_diam_freeBuffer( SI_DiamBuffer * oDiamBuffer);

int __si_diam_send_message_by_socket( SI_DiamMessage * dmMsg, SI_Socket * siSocket);
int __si_diam_send_message_by_diamnode( SI_DiamMessage * dmMsg, SI_DiamNode * prtDiamNode);
uint32_t __si_diam_send_error( SI_DiamMessage * dMesg, uint32_t resultCode, uint32_t failedAvp, uint32_t experimantalResultCode, SI_DiamNode * hostNode);
int __si_diam_send_error2( SI_DiamMessage * dMesg, uint32_t resultCode, uint32_t failedAvp, uint32_t experimantalResultCode, uint32_t count, uint32_t avpCodes[], SI_DiamNode * hostNode);
int __si_diam_send_error3( SI_DiamMessage * dMesg, uint32_t resultCode, uint32_t failedAvp, uint32_t experimantalResultCode, uint32_t count, uint32_t avpCodes[], SI_DiamNode * hostNode, SI_DiamAvp * diamAvp);
int __si_diam_send_redirect_indication( SI_DiamMessage * dMesg, SI_DiamNode * hostNode, u_char * redirectHostName, uint32_t redirectHostName_len);

u_char * __si_diam_get_sessionid( SI_DiamMessage * dmMsg);
u_char * __si_diam_get_username( SI_DiamMessage * dmMsg);

void __si_diam_add_imsi_username( __si_lte_ue_t * uE, SI_DiamMessage * dmMsg);

SI_DiamAvp * __si_diam_find_avp_in_group( uint32_t avpCode, uint32_t index, SI_DiamAvp * dmAvp);

int __si_diam_get_uint32_avp_value( uint32_t avpCode, SI_DiamMessage * dmMsg, uint32_t * val);
int __si_diam_get_uint32_avp_value_g( uint32_t avpCode, SI_DiamAvp * dmAvp, uint32_t * val);

int __si_diam_get_int32_avp_value( uint32_t avpCode, SI_DiamMessage * dmMsg, int32_t * val);
int __si_diam_get_int32_avp_value_g( uint32_t avpCode, SI_DiamAvp * dmAvp, int32_t * val);

int __si_diam_get_int64_avp_value( uint32_t avpCode, SI_DiamMessage * dmMsg, int64_t * val);
int __si_diam_get_int64_avp_value_g( uint32_t avpCode, SI_DiamAvp * dmAvp, int64_t * val);

int __si_diam_get_uint64_avp_value( uint32_t avpCode, SI_DiamMessage * dmMsg, uint64_t * val);
int __si_diam_get_uint64_avp_value_g( uint32_t avpCode, SI_DiamAvp * dmAvp, uint64_t * val);

int __si_diam_get_string_avp_value( uint32_t avpCode, SI_DiamMessage * dmMsg, u_char ** ptrData, uint32_t * len);
int __si_diam_get_string_avp_value2( uint32_t avpCode, SI_DiamMessage * dmMsg, int index, u_char ** ptrData, uint32_t * len);
int __si_diam_get_string_avp_value_g( uint32_t avpCode, SI_DiamAvp * dmAvp, u_char ** ptrData, uint32_t * len);

int __si_diam_get_diam_address( uint32_t avpCode, SI_DiamMessage * dmMsg, int index, SI_DiamAddress * address);


uint32_t __si_diam_validate_mandatory_avps( uint32_t count, uint32_t avpCodes[], SI_DiamMessage * dmMsg);


SI_DiamMessage * __si_diam_compose_error( SI_DiamMessage * dMesg, uint32_t resultCode, uint32_t failedAvp, uint32_t experimantalResultCode, SI_DiamNode * hostNode);
void __si_diam_set_header_e_bit( SI_DiamMessage * dmMsg);

uint32_t __si_diam_get_experimental_result_code( SI_DiamMessage * dMesg);
uint32_t __si_diam_get_result_code( SI_DiamMessage * dMesg);

void __si_diam_copy_e2eid( SI_DiamMessage * dmMsgTarget, SI_DiamMessage * dmMsgSource);

SI_DiamNode * __si_diam__find_node3( uint32_t authAppId, char * sHost, char * sRealm, uint32_t cmdCode, SI_DiamNode * srcNode, int findAppServerOrClient);
SI_DiamNode * __si_diam__find_node4( uint32_t authAppId, char * sHost, char * sRealm, uint32_t cmdCode);
void __si_diam_find_node_by_appid_or_dra( SI_DiamNodeResult * ptrDiamNodeResult, uint32_t applicationId, char * appDestRealm, int appDestRealmLen, char * draDestRealm, int draDestRealmLen);
void __si_diam_find_node_by_appid_or_dra2( SI_DiamNodeResult * ptrDiamNodeResult, uint32_t applicationId, char * appDestHost, char * appDestRealm, char * draDestRealm);

typedef void (*pfCallBack)();
void __si_diam_stack__set_performace_log_cbf( pfCallBack pcb);



//mgmt
void __si_diam_stack__getStartTime( char * datestring);
void __si_diam_stack__get_peer_msg_count( uint64_t * TotalMessagesReceived, uint64_t * TotalMessagesSent);

//__fp_dm_req_onanswer onAnswer;
//	__fp_dm_req_ontimeout onTimeOut;

__si_diam_request_interface_t * __si_diam_stack__interface__find( uint32_t appId);

__si_diam_request_interface_t * __si_diam_stack__create_request_interface( 
											uint32_t request_count, uint64_t ApplicationId, uint32_t Timeout, 
											__fp_dm_req_onanswer onAnswer, __fp_dm_req_ontimeout onTimeOut);
									

int __si_diam_stack__interface__send_message( __si_diam_request_interface_t * interface, SI_DiamNode * diamNode, SI_DiamMessage * dMesg, __si_lte_ue_t * uE, uint32_t * E2EId);
int __si_diam_stack__interface__route_answer( SI_DiamMessage * dAnswer);

SI_DiamAvp * __si_diam__iterator_begin( SI_DiamMessage * dmMsg);
SI_DiamAvp * __si_diam__iterator_next( SI_DiamAvp * diamAvp);
SI_DiamAvp * __si_diam__iterator_begin_grp( SI_DiamAvp * diamAvp);

int __si_diam__decode_stringv_avp( __si_stringv_t * str, SI_DiamAvp * diamAvp);
int __si_diam__decode_string100_avp( __si_string100_t * str, SI_DiamAvp * diamAvp);
int __si_diam__decode_u32_avp( SI_U32 * u32, SI_DiamAvp * diamAvp);
int __si_diam__decode_u64_avp( SI_U64 * u64, SI_DiamAvp * diamAvp);
int __si_diam__decode_i32_avp( SI_I32 * u32, SI_DiamAvp * diamAvp);
int __si_diam__decode_i64_avp( SI_I64 * u64, SI_DiamAvp * diamAvp);

void __si_diam__decode_experimental_result( SI_U32 * uExperimentalResultCode, SI_DiamAvp * diamGrpAvp);

int __si_diam_get__is_peer_connected_to_stack( SI_DiamNode * node);
int __si_diam_get__is_peer_application_server( SI_DiamNode * node);
int __si_diam_get__is_peer_connected_to_stack__diam_buffer( SI_DiamBuffer * diamBuffer);
int __si_diam_get__is_peer_application_server__diam_buffer( SI_DiamBuffer * diamBuffer);

SI_DiamNode * __si_diam__find_node5( uint32_t authAppId, char * sHost, char * sRealm, uint32_t cmdCode, SI_DiamNode * diamNode);
SI_DiamNode * __si_diam__find_appservers( uint32_t authAppId, char * sHost, char * sRealm, uint32_t cmdCode, SI_DiamNode * diamNode);
SI_DiamNode * __si_diam__find_appclients( uint32_t authAppId, char * sHost, char * sRealm, uint32_t cmdCode, SI_DiamNode * diamNode);

void __si_diam__sentbytes_counter( int iSentBytes, SI_DiamNode * diamNode);

uint32_t __si_diam__get_peer_status( SI_DiamNode * diamPeer);
void __si_diam_stack__performace_stats();
void * __si_diam_stack__performace_thread( void * args);

SI_DiamAvp * __si_diam_add_int32_avp3( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, int32_t val);
SI_DiamAvp * __si_diam_add_int64_avp3( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, int64_t val);
SI_DiamAvp * __si_diam_add_uint32_avp3( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, uint32_t val);
SI_DiamAvp * __si_diam_add_uint64_avp3( SI_DiamMessage * msg, uint32_t avpCode, uint32_t VendorId, uint32_t isMandatory, uint64_t val);


int64_t __si_diam__decode_i64_avpv( SI_I64 * i64, SI_DiamAvp * diamAvp);
int32_t __si_diam__decode_i32_avpv( SI_I32 * i32, SI_DiamAvp * diamAvp);
uint64_t __si_diam__decode_u64_avpv( SI_DiamAvp * diamAvp);
uint32_t __si_diam__decode_u32_avpv( SI_DiamAvp * diamAvp);

#endif

















