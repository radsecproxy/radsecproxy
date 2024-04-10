/* Copyright (c) 2007-2008, UNINETT AS
 * Copyright (c) 2015, NORDUnet A/S
 * Copyright (c) 2023, SWITCH */
/* See LICENSE for licensing information. */

#ifndef _RADMSG_H
#define _RADMSG_H

#include "tlv11.h"

#define RAD_Min_Length 20
#define RAD_Max_Length 4096
#define RAD_Max_Attr_Value_Length 253

#define RAD_Access_Request 1
#define RAD_Access_Accept 2
#define RAD_Access_Reject 3
#define RAD_Accounting_Request 4
#define RAD_Accounting_Response 5
#define RAD_Access_Challenge 11
#define RAD_Status_Server 12
#define RAD_Status_Client 13

#define RAD_Attr_User_Name 1
#define RAD_Attr_User_Password 2
#define RAD_Attr_CHAP_Password 3
#define RAD_Attr_NAS_IP_Address 4
#define RAD_Attr_Framed_IP_Address 8
#define RAD_Attr_Reply_Message 18
#define RAD_Attr_Vendor_Specific 26
#define RAD_Attr_Called_Station_Id 30
#define RAD_Attr_Calling_Station_Id 31
#define RAD_Attr_Proxy_State 33
#define RAD_Attr_Acct_Status_Type 40
#define RAD_Attr_Acct_Input_Octets 42
#define RAD_Attr_Acct_Output_Octets 43
#define RAD_Attr_Acct_Session_Id 44
#define RAD_Attr_Acct_Session_Time 46
#define RAD_Attr_Acct_Input_Packets 47
#define RAD_Attr_Acct_Output_Packets 48
#define RAD_Attr_Acct_Terminate_Cause 49
#define RAD_Attr_Event_Timestamp 55
#define RAD_Attr_CHAP_Challenge 60
#define RAD_Attr_Tunnel_Password 69
#define RAD_Attr_Message_Authenticator 80
#define RAD_Attr_CUI 89
#define RAD_Attr_Operator_Name 126

#define RAD_Acct_Status_Start 1
#define RAD_Acct_Status_Stop 2
#define RAD_Acct_Status_Alive 3
#define RAD_Acct_Status_Interim_Update 3
#define RAD_Acct_Status_Accounting_On 7
#define RAD_Acct_Status_Accounting_Off 8
#define RAD_Acct_Status_Failed 15


#define RAD_VS_ATTR_MS_MPPE_Send_Key 16
#define RAD_VS_ATTR_MS_MPPE_Recv_Key 17

struct radmsg {
    uint8_t code;
    uint8_t id;
    uint8_t auth[20];
    struct list *attrs; /*struct tlv*/
};

#define ATTRTYPE(x) ((x)[0])
#define ATTRLEN(x) ((x)[1])
#define ATTRVAL(x) ((x) + 2)
#define ATTRVALLEN(x) ((x)[1] - 2)

int get_checked_rad_length(uint8_t *buf);
void radmsg_free(struct radmsg *);
struct radmsg *radmsg_init(uint8_t, uint8_t, uint8_t *);
int radmsg_add(struct radmsg *, struct tlv *, uint8_t front);
struct tlv *radmsg_gettype(struct radmsg *, uint8_t);
struct list *radmsg_getalltype(const struct radmsg *msg, uint8_t type);
int radmsg_copy_attrs(struct radmsg *dst,
                      const struct radmsg *src,
                      uint8_t type);
uint8_t *tlv2buf(uint8_t *p, const struct tlv *tlv);
int radmsg2buf(struct radmsg *msg, uint8_t *, int, uint8_t **);
struct radmsg *buf2radmsg(uint8_t *, int, uint8_t *, int, uint8_t *);
uint8_t attrname2val(char *attrname);
int vattrname2val(char *attrname, uint32_t *vendor, uint32_t *type);
int attrvalidate(unsigned char *attrs, int length);
struct tlv *makevendortlv(uint32_t vendor, struct tlv *attr);
int resizeattr(struct tlv *attr, uint8_t newlen);

/**
 * convert the attribute value to its string representation form the dictionary 
 * (see raddict.h)
 * 
 * @param attr the attribute to convert
 * @return the string representation or NULL, if the attribute/value is not in the 
 * dictionary
 */
const char* attrval2strdict(struct tlv *attr);

#endif /*_RADMSG_H*/

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
