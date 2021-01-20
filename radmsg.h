/* Copyright (c) 2007-2008, UNINETT AS */
/* Copyright (c) 2015, NORDUnet A/S */
/* See LICENSE for licensing information. */

#ifndef _RADMSG_H
#define _RADMSG_H

#include "tlv11.h"

#define RAD_Max_Attr_Value_Length 253

#define RAD_Access_Request 1
#define RAD_Access_Accept 2
#define RAD_Access_Reject 3
#define RAD_Accounting_Request 4
#define RAD_Accounting_Response 5
#define RAD_Access_Challenge 11
#define RAD_Status_Server 12
#define RAD_Status_Client 13
#define RAD_Disconnect_Request 40
#define RAD_Disconnect_ACK 41
#define RAD_Disconnect_NAK 42
#define RAD_CoA_Request 43
#define RAD_CoA_ACK 44
#define RAD_CoA_NAK 45

#define RAD_Attr_User_Name 1
#define RAD_Attr_User_Password 2
#define RAD_Attr_CHAP_Password 3
#define RAD_Attr_Reply_Message 18
#define RAD_Attr_Vendor_Specific 26
#define RAD_Attr_Calling_Station_Id 31
#define RAD_Attr_Proxy_State 33
#define RAD_Attr_CHAP_Challenge 60
#define RAD_Attr_Tunnel_Password 69
#define RAD_Attr_Message_Authenticator 80
#define RAD_Attr_Error_Cause 101
#define RAD_Attr_Operator_Name 126

#define RAD_VS_ATTR_MS_MPPE_Send_Key 16
#define RAD_VS_ATTR_MS_MPPE_Recv_Key 17

#define RAD_Err_Request_Not_Routable 502

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
#define DYNAUTH_REQ(code) (code == RAD_CoA_Request || code == RAD_Disconnect_Request)
#define DYNAUTH_RES(code) (code == RAD_CoA_ACK || code == RAD_CoA_NAK || \
                           code == RAD_Disconnect_ACK || code == RAD_Disconnect_NAK)

void radmsg_free(struct radmsg *);
struct radmsg *radmsg_init(uint8_t, uint8_t, uint8_t *);
int radmsg_add(struct radmsg *, struct tlv *);
struct tlv *radmsg_gettype(struct radmsg *, uint8_t);
struct list *radmsg_getalltype(const struct radmsg *msg, uint8_t type);
int radmsg_copy_attrs(struct radmsg *dst,
                      const struct radmsg *src,
                      uint8_t type);
uint8_t *tlv2buf(uint8_t *p, const struct tlv *tlv);
uint8_t *radmsg2buf(struct radmsg *msg, uint8_t *, int);
struct radmsg *buf2radmsg(uint8_t *, uint8_t *, int, uint8_t *);
uint8_t attrname2val(char *attrname);
int vattrname2val(char *attrname, uint32_t *vendor, uint32_t *type);
int attrvalidate(unsigned char *attrs, int length);
struct tlv *makevendortlv(uint32_t vendor, struct tlv *attr);
int resizeattr(struct tlv *attr, uint8_t newlen);

#endif /*_RADMSG_H*/

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
