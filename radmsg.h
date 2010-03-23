/*
 * Copyright (C) 2006-2008 Stig Venaas <venaas@uninett.no>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

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
#define RAD_Attr_Reply_Message 18
#define RAD_Attr_Vendor_Specific 26
#define RAD_Attr_Calling_Station_Id 31
#define RAD_Attr_Tunnel_Password 69
#define RAD_Attr_Message_Authenticator 80

#define RAD_VS_ATTR_MS_MPPE_Send_Key 16
#define RAD_VS_ATTR_MS_MPPE_Recv_Key 17

struct radmsg {
    uint8_t code;
    uint8_t id;
    uint8_t auth[20];
    struct list *attrs;
};

void radmsg_free(struct radmsg *);
struct radmsg *radmsg_init(uint8_t, uint8_t, uint8_t *);
int radmsg_add(struct radmsg *, struct tlv *);
struct tlv *radmsg_gettype(struct radmsg *, uint8_t);
uint8_t *radmsg2buf(struct radmsg *msg, uint8_t *);
struct radmsg *buf2radmsg(uint8_t *, uint8_t *, uint8_t *);

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
