#ifndef RAD_DICT
#define RAD_DICT

char* RAD_Attr_Acct_Terminate_Cause_Dict[] = {
        "User-Request",
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

char* RAD_Attr_Acct_Status_Type_Dict[] = {
        "Start",
        "Stop",
        "Interim-Update",
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

#endif