/* Copyright (c) 2006-2010, UNINETT AS
 * Copyright (c) 2010-2012, NORDUnet A/S */
/* See LICENSE for licensing information. */

#include "radsecproxy.h"
#include "debug.h"
#include "fticks.h"
#include "fticks_hashmac.h"

int
fticks_configure(struct options *options,
		 uint8_t **reportingp,
		 uint8_t **macp,
		 uint8_t **keyp)
{
    int r = 0;
    const char *reporting = (const char *) *reportingp;
    const char *mac = (const char *) *macp;

    /* Set defaults.  */
    options->fticks_reporting = RSP_FTICKS_REPORTING_NONE;
    options->fticks_mac = RSP_FTICKS_MAC_VENDOR_KEY_HASHED;

    if (reporting != NULL) {
	if (strcasecmp(reporting, "None") == 0)
	    options->fticks_reporting = RSP_FTICKS_REPORTING_NONE;
	else if (strcasecmp(reporting, "Basic") == 0)
	    options->fticks_reporting = RSP_FTICKS_REPORTING_BASIC;
	else if (strcasecmp(reporting, "Full") == 0)
	    options->fticks_reporting = RSP_FTICKS_REPORTING_FULL;
	else {
	    debugx(1, DBG_ERR,
		   "config error: invalid FTicksReporting value: %s",
		   reporting);
	    r = 1;
	}
    }

    if (mac != NULL) {
	if (strcasecmp(mac, "Static") == 0)
	    options->fticks_mac = RSP_FTICKS_MAC_STATIC;
	else if (strcasecmp(mac, "Original") == 0)
	    options->fticks_mac = RSP_FTICKS_MAC_ORIGINAL;
	else if (strcasecmp(mac, "VendorHashed") == 0)
	    options->fticks_mac = RSP_FTICKS_MAC_VENDOR_HASHED;
	else if (strcasecmp(mac, "VendorKeyHashed") == 0)
	    options->fticks_mac = RSP_FTICKS_MAC_VENDOR_KEY_HASHED;
	else if (strcasecmp(mac, "FullyHashed") == 0)
	    options->fticks_mac = RSP_FTICKS_MAC_FULLY_HASHED;
	else if (strcasecmp(mac, "FullyKeyHashed") == 0)
	    options->fticks_mac = RSP_FTICKS_MAC_FULLY_KEY_HASHED;
	else {
	    debugx(1, DBG_ERR,
		   "config error: invalid FTicksMAC value: %s", mac);
	    r = 1;
	}
    }

    if (*keyp != NULL) {
	options->fticks_key = *keyp;
	if (options->fticks_mac != RSP_FTICKS_MAC_VENDOR_KEY_HASHED
	    && options->fticks_mac != RSP_FTICKS_MAC_FULLY_KEY_HASHED)
	    debugx(1, DBG_WARN, "config warning: FTicksKey not used");
    }
    else if (options->fticks_reporting != RSP_FTICKS_REPORTING_NONE
	     && (options->fticks_mac == RSP_FTICKS_MAC_VENDOR_KEY_HASHED
		 || options->fticks_mac == RSP_FTICKS_MAC_FULLY_KEY_HASHED)) {
	debugx(1, DBG_ERR,
	       "config error: FTicksMAC values VendorKeyHashed and "
	       "FullyKeyHashed require an FTicksKey");
	options->fticks_reporting = RSP_FTICKS_REPORTING_NONE;
	r = 1;
    }

    if (*reportingp != NULL) {
	free(*reportingp);
	*reportingp = NULL;
    }
    if (*macp != NULL) {
	free(*macp);
	*macp = NULL;
    }
    return r;
}

void
fticks_log(const struct options *options,
	   const struct client *client,
	   const struct radmsg *msg,
	   const struct rqout *rqout)
{
    uint8_t *username = NULL;
    uint8_t *realm = NULL;
    uint8_t visinst[8+40+1+1]; /* Room for 40 octets of VISINST.  */
    uint8_t *macin = NULL;
    uint8_t macout[2*32+1]; /* Room for ASCII representation of SHA256.  */

    username = radattr2ascii(radmsg_gettype(rqout->rq->msg,
					    RAD_Attr_User_Name));
    if (username != NULL) {
	realm = (uint8_t *) strrchr((char *) username, '@');
	if (realm != NULL)
	    realm++;
    }
    if (realm == NULL)
	realm = (uint8_t *) "";

    memset(visinst, 0, sizeof(visinst));
    if (options->fticks_reporting == RSP_FTICKS_REPORTING_FULL) {
        if (client->conf->fticks_visinst != NULL ) {
	    snprintf((char *) visinst, sizeof(visinst), "VISINST=%s#",
                     client->conf->fticks_visinst);
        } else {
	    snprintf((char *) visinst, sizeof(visinst), "VISINST=%s#",
                     client->conf->name);
        }
    }

    memset(macout, 0, sizeof(macout));
    if (options->fticks_mac == RSP_FTICKS_MAC_STATIC) {
	strncpy((char *) macout, "undisclosed", sizeof(macout) - 1);
    }
    else {
	macin = radattr2ascii(radmsg_gettype(rqout->rq->msg,
					     RAD_Attr_Calling_Station_Id));
	if (macin) {
	    switch (options->fticks_mac)
	    {
	    case RSP_FTICKS_MAC_ORIGINAL:
		memcpy(macout, macin, sizeof(macout));
		break;
	    case RSP_FTICKS_MAC_VENDOR_HASHED:
		memcpy(macout, macin, 9);
		fticks_hashmac(macin, NULL, sizeof(macout) - 9, macout + 9);
		break;
	    case RSP_FTICKS_MAC_VENDOR_KEY_HASHED:
		memcpy(macout, macin, 9);
		/* We are hashing the first nine octets too for easier
		 * correlation between vendor-key-hashed and
		 * fully-key-hashed log records.  This opens up for a
		 * known plaintext attack on the key but the
		 * consequences of that is considered outweighed by
		 * the convenience gained.  */
		fticks_hashmac(macin, options->fticks_key,
			       sizeof(macout) - 9, macout + 9);
		break;
	    case RSP_FTICKS_MAC_FULLY_HASHED:
		fticks_hashmac(macin, NULL, sizeof(macout), macout);
		break;
	    case RSP_FTICKS_MAC_FULLY_KEY_HASHED:
		fticks_hashmac(macin, options->fticks_key, sizeof(macout),
			       macout);
		break;
	    default:
		debugx(2, DBG_ERR, "invalid fticks mac configuration: %d",
		       options->fticks_mac);
	    }
	}
    }
    fticks_debug(
	  "F-TICKS/eduroam/1.0#REALM=%s#VISCOUNTRY=%s#%sCSI=%s#RESULT=%s#",
	  realm,
	  client->conf->fticks_viscountry,
	  visinst,
	  macout,
	  msg->code == RAD_Access_Accept ? "OK" : "FAIL");
    if (macin != NULL)
	free(macin);
    if (username != NULL)
	free(username);
}

/* Local Variables: */
/* c-file-style: "stroustrup" */
/* End: */
