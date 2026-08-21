#ifndef _RADDICT_H
#define _RADDICT_H

const char *RAD_Attr_Acct_Terminate_Cause_Dict[] = {
    [1] = "User-Request",
    "Lost-Carrier",
    "Lost-Service",
    "Idle-Timeout",
    "Session-Timeout",
    "Admin-Reset",
    "Admin-Reboot",
    "Port-Error",
    "NAS-Error",
    "NAS-Request",
    "NAS-Reboot",
    "Port-Unneeded",
    "Port-Preempted",
    "Port-Suspended",
    "Service-Unavailable",
    "Callback",
    "User-Error",
    "Host-Request",
};

const char *RAD_Attr_Acct_Status_Type_Dict[] = {
    [1] = "Start",
    [2] = "Stop",
    [3] = "Interim-Update",
    [7] = "Accounting-On",
    [8] = "Accounting-Off",
    [9] = "Tunnel-Start",
    [10] = "Tunnel-Stop",
    [11] = "Tunnel-Reject",
    [12] = "Tunnel-Link-Start",
    [13] = "Tunnel-Link-Stop",
    [14] = "Tunnel-Link-Reject",
    [15] = "Failed",
};

const char *RAD_Attr_Error_Cause_Dict[] = {
    [201] = "Residual Session Context Removed",
    [202] = "Invalid EAP Packet",
    [401] = "Unsupported Attribute",
    [402] = "Missing Attribute",
    [403] = "NAS Identification Mismatch",
    [404] = "Invalid Request",
    [405] = "Unsupported Service",
    [406] = "Unsupported Extension",
    [407] = "Invalid Attribute Value",
    [501] = "Administratively Prohibited",
    [502] = "Request Not Routable",
    [503] = "Session Context Not Found",
    [504] = "Session Context Not Removable",
    [505] = "Other Proxy Processing Error",
    [506] = "Resources Unavailable",
    [507] = "Request Initiated",
    [508] = "Multiple Session Selection Unsupported",
    [509] = "Location-Info-Required",
    [601] = "Response Too Big",
};

#define RAD_Attr_Dict_Undef "UNKNOWN"

#endif /*_RADDICT_H*/
