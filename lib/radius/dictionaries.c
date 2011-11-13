const DICT_VENDOR nr_dict_vendors[] = {
  { 
    .name = "Microsoft", 
    .vendor = 311, 
    .type = 1,
    .length = 1,
  },
  { 
    .name = "example", 
    .vendor = 65535, 
    .type = 1,
    .length = 1,
  },

  { .name = NULL, }
};

const DICT_ATTR nr_dict_attrs[] = {
  { /* 0 */ 
    .name = NULL, 
  },
  { /* 1 */ 
    .name = "User-Name", 
    .attr = 1, 
    .type = NR_TYPE_STRING, 
  },
  { /* 2 */ 
    .name = "User-Password", 
    .attr = 2, 
    .type = NR_TYPE_STRING, 
    .flags = {
      .encrypt = FLAG_ENCRYPT_USER_PASSWORD,
    },
  },
  { /* 3 */ 
    .name = "CHAP-Password", 
    .attr = 3, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 4 */ 
    .name = "NAS-IP-Address", 
    .attr = 4, 
    .type = NR_TYPE_IPADDR, 
    .flags = {
      .length = 4,
    },
  },
  { /* 5 */ 
    .name = "NAS-Port", 
    .attr = 5, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 6 */ 
    .name = "Service-Type", 
    .attr = 6, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 7 */ 
    .name = "Framed-Protocol", 
    .attr = 7, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 8 */ 
    .name = "Framed-IP-Address", 
    .attr = 8, 
    .type = NR_TYPE_IPADDR, 
    .flags = {
      .length = 4,
    },
  },
  { /* 9 */ 
    .name = "Framed-IP-Netmask", 
    .attr = 9, 
    .type = NR_TYPE_IPADDR, 
    .flags = {
      .length = 4,
    },
  },
  { /* 10 */ 
    .name = "Framed-Routing", 
    .attr = 10, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 11 */ 
    .name = "Filter-Id", 
    .attr = 11, 
    .type = NR_TYPE_STRING, 
  },
  { /* 12 */ 
    .name = "Framed-MTU", 
    .attr = 12, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 13 */ 
    .name = "Framed-Compression", 
    .attr = 13, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 14 */ 
    .name = "Login-IP-Host", 
    .attr = 14, 
    .type = NR_TYPE_IPADDR, 
    .flags = {
      .length = 4,
    },
  },
  { /* 15 */ 
    .name = "Login-Service", 
    .attr = 15, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 16 */ 
    .name = "Login-TCP-Port", 
    .attr = 16, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 17 */ 
    .name = NULL, 
  },
  { /* 18 */ 
    .name = "Reply-Message", 
    .attr = 18, 
    .type = NR_TYPE_STRING, 
  },
  { /* 19 */ 
    .name = "Callback-Number", 
    .attr = 19, 
    .type = NR_TYPE_STRING, 
  },
  { /* 20 */ 
    .name = "Callback-Id", 
    .attr = 20, 
    .type = NR_TYPE_STRING, 
  },
  { /* 21 */ 
    .name = NULL, 
  },
  { /* 22 */ 
    .name = "Framed-Route", 
    .attr = 22, 
    .type = NR_TYPE_STRING, 
  },
  { /* 23 */ 
    .name = "Framed-IPX-Network", 
    .attr = 23, 
    .type = NR_TYPE_IPADDR, 
    .flags = {
      .length = 4,
    },
  },
  { /* 24 */ 
    .name = "State", 
    .attr = 24, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 25 */ 
    .name = "Class", 
    .attr = 25, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 26 */ 
    .name = "Vendor-Specific", 
    .attr = 26, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 27 */ 
    .name = "Session-Timeout", 
    .attr = 27, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 28 */ 
    .name = "Idle-Timeout", 
    .attr = 28, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 29 */ 
    .name = "Termination-Action", 
    .attr = 29, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 30 */ 
    .name = "Called-Station-Id", 
    .attr = 30, 
    .type = NR_TYPE_STRING, 
  },
  { /* 31 */ 
    .name = "Calling-Station-Id", 
    .attr = 31, 
    .type = NR_TYPE_STRING, 
  },
  { /* 32 */ 
    .name = "NAS-Identifier", 
    .attr = 32, 
    .type = NR_TYPE_STRING, 
  },
  { /* 33 */ 
    .name = "Proxy-State", 
    .attr = 33, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 34 */ 
    .name = "Login-LAT-Service", 
    .attr = 34, 
    .type = NR_TYPE_STRING, 
  },
  { /* 35 */ 
    .name = "Login-LAT-Node", 
    .attr = 35, 
    .type = NR_TYPE_STRING, 
  },
  { /* 36 */ 
    .name = "Login-LAT-Group", 
    .attr = 36, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 37 */ 
    .name = "Framed-AppleTalk-Link", 
    .attr = 37, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 38 */ 
    .name = "Framed-AppleTalk-Network", 
    .attr = 38, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 39 */ 
    .name = "Framed-AppleTalk-Zone", 
    .attr = 39, 
    .type = NR_TYPE_STRING, 
  },
  { /* 40 */ 
    .name = "Acct-Status-Type", 
    .attr = 40, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 41 */ 
    .name = "Acct-Delay-Time", 
    .attr = 41, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 42 */ 
    .name = "Acct-Input-Octets", 
    .attr = 42, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 43 */ 
    .name = "Acct-Output-Octets", 
    .attr = 43, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 44 */ 
    .name = "Acct-Session-Id", 
    .attr = 44, 
    .type = NR_TYPE_STRING, 
  },
  { /* 45 */ 
    .name = "Acct-Authentic", 
    .attr = 45, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 46 */ 
    .name = "Acct-Session-Time", 
    .attr = 46, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 47 */ 
    .name = "Acct-Input-Packets", 
    .attr = 47, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 48 */ 
    .name = "Acct-Output-Packets", 
    .attr = 48, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 49 */ 
    .name = "Acct-Terminate-Cause", 
    .attr = 49, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 50 */ 
    .name = "Acct-Multi-Session-Id", 
    .attr = 50, 
    .type = NR_TYPE_STRING, 
  },
  { /* 51 */ 
    .name = "Acct-Link-Count", 
    .attr = 51, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 52 */ 
    .name = "Acct-Input-Gigawords", 
    .attr = 52, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 53 */ 
    .name = "Acct-Output-Gigawords", 
    .attr = 53, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 54 */ 
    .name = NULL, 
  },
  { /* 55 */ 
    .name = "Event-Timestamp", 
    .attr = 55, 
    .type = NR_TYPE_DATE, 
    .flags = {
      .length = 4,
    },
  },
  { /* 56 */ 
    .name = "Egress-VLANID", 
    .attr = 56, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 57 */ 
    .name = "Ingress-Filters", 
    .attr = 57, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 58 */ 
    .name = "Egress-VLAN-Name", 
    .attr = 58, 
    .type = NR_TYPE_STRING, 
  },
  { /* 59 */ 
    .name = "User-Priority-Table", 
    .attr = 59, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 60 */ 
    .name = "CHAP-Challenge", 
    .attr = 60, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 61 */ 
    .name = "NAS-Port-Type", 
    .attr = 61, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 62 */ 
    .name = "Port-Limit", 
    .attr = 62, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 63 */ 
    .name = "Login-LAT-Port", 
    .attr = 63, 
    .type = NR_TYPE_STRING, 
  },
  { /* 64 */ 
    .name = "Tunnel-Type", 
    .attr = 64, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
      .has_tag = 1,
    },
  },
  { /* 65 */ 
    .name = "Tunnel-Medium-Type", 
    .attr = 65, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
      .has_tag = 1,
    },
  },
  { /* 66 */ 
    .name = "Tunnel-Client-Endpoint", 
    .attr = 66, 
    .type = NR_TYPE_STRING, 
    .flags = {
      .has_tag = 1,
    },
  },
  { /* 67 */ 
    .name = "Tunnel-Server-Endpoint", 
    .attr = 67, 
    .type = NR_TYPE_STRING, 
    .flags = {
      .has_tag = 1,
    },
  },
  { /* 68 */ 
    .name = "Acct-Tunnel-Connection", 
    .attr = 68, 
    .type = NR_TYPE_STRING, 
  },
  { /* 69 */ 
    .name = "Tunnel-Password", 
    .attr = 69, 
    .type = NR_TYPE_STRING, 
    .flags = {
      .encrypt = FLAG_ENCRYPT_TUNNEL_PASSWORD,
      .has_tag = 1,
    },
  },
  { /* 70 */ 
    .name = "ARAP-Password", 
    .attr = 70, 
    .type = NR_TYPE_OCTETS, 
    .flags = {
      .length = 16,
    },
  },
  { /* 71 */ 
    .name = "ARAP-Features", 
    .attr = 71, 
    .type = NR_TYPE_OCTETS, 
    .flags = {
      .length = 14,
    },
  },
  { /* 72 */ 
    .name = "ARAP-Zone-Access", 
    .attr = 72, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 73 */ 
    .name = "ARAP-Security", 
    .attr = 73, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 74 */ 
    .name = "ARAP-Security-Data", 
    .attr = 74, 
    .type = NR_TYPE_STRING, 
  },
  { /* 75 */ 
    .name = "Password-Retry", 
    .attr = 75, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 76 */ 
    .name = "Prompt", 
    .attr = 76, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 77 */ 
    .name = "Connect-Info", 
    .attr = 77, 
    .type = NR_TYPE_STRING, 
  },
  { /* 78 */ 
    .name = "Configuration-Token", 
    .attr = 78, 
    .type = NR_TYPE_STRING, 
  },
  { /* 79 */ 
    .name = "EAP-Message", 
    .attr = 79, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 80 */ 
    .name = "Message-Authenticator", 
    .attr = 80, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 81 */ 
    .name = "Tunnel-Private-Group-Id", 
    .attr = 81, 
    .type = NR_TYPE_STRING, 
    .flags = {
      .has_tag = 1,
    },
  },
  { /* 82 */ 
    .name = "Tunnel-Assignment-Id", 
    .attr = 82, 
    .type = NR_TYPE_STRING, 
    .flags = {
      .has_tag = 1,
    },
  },
  { /* 83 */ 
    .name = "Tunnel-Preference", 
    .attr = 83, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
      .has_tag = 1,
    },
  },
  { /* 84 */ 
    .name = "ARAP-Challenge-Response", 
    .attr = 84, 
    .type = NR_TYPE_OCTETS, 
    .flags = {
      .length = 8,
    },
  },
  { /* 85 */ 
    .name = "Acct-Interim-Interval", 
    .attr = 85, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 86 */ 
    .name = "Acct-Tunnel-Packets-Lost", 
    .attr = 86, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 87 */ 
    .name = "NAS-Port-Id", 
    .attr = 87, 
    .type = NR_TYPE_STRING, 
  },
  { /* 88 */ 
    .name = "Framed-Pool", 
    .attr = 88, 
    .type = NR_TYPE_STRING, 
  },
  { /* 89 */ 
    .name = "Chargeable-User-Identity", 
    .attr = 89, 
    .type = NR_TYPE_STRING, 
  },
  { /* 90 */ 
    .name = "Tunnel-Client-Auth-Id", 
    .attr = 90, 
    .type = NR_TYPE_STRING, 
    .flags = {
      .has_tag = 1,
    },
  },
  { /* 91 */ 
    .name = "Tunnel-Server-Auth-Id", 
    .attr = 91, 
    .type = NR_TYPE_STRING, 
    .flags = {
      .has_tag = 1,
    },
  },
  { /* 92 */ 
    .name = "NAS-Filter-Rule", 
    .attr = 92, 
    .type = NR_TYPE_STRING, 
  },
  { /* 93 */ 
    .name = NULL, 
  },
  { /* 94 */ 
    .name = NULL, 
  },
  { /* 95 */ 
    .name = "NAS-IPv6-Address", 
    .attr = 95, 
    .type = NR_TYPE_IPV6ADDR, 
    .flags = {
      .length = 16,
    },
  },
  { /* 96 */ 
    .name = "Framed-Interface-Id", 
    .attr = 96, 
    .type = NR_TYPE_IFID, 
    .flags = {
      .length = 8,
    },
  },
  { /* 97 */ 
    .name = "Framed-IPv6-Prefix", 
    .attr = 97, 
    .type = NR_TYPE_IPV6PREFIX, 
  },
  { /* 98 */ 
    .name = "Login-IPv6-Host", 
    .attr = 98, 
    .type = NR_TYPE_IPV6ADDR, 
    .flags = {
      .length = 16,
    },
  },
  { /* 99 */ 
    .name = "Framed-IPv6-Route", 
    .attr = 99, 
    .type = NR_TYPE_STRING, 
  },
  { /* 100 */ 
    .name = "Framed-IPv6-Pool", 
    .attr = 100, 
    .type = NR_TYPE_STRING, 
  },
  { /* 101 */ 
    .name = "Error-Cause", 
    .attr = 101, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 102 */ 
    .name = "EAP-Key-Name", 
    .attr = 102, 
    .type = NR_TYPE_STRING, 
  },
  { /* 103 */ 
    .name = "Digest-Response", 
    .attr = 103, 
    .type = NR_TYPE_STRING, 
  },
  { /* 104 */ 
    .name = "Digest-Realm", 
    .attr = 104, 
    .type = NR_TYPE_STRING, 
  },
  { /* 105 */ 
    .name = "Digest-Nonce", 
    .attr = 105, 
    .type = NR_TYPE_STRING, 
  },
  { /* 106 */ 
    .name = "Digest-Response-Auth", 
    .attr = 106, 
    .type = NR_TYPE_STRING, 
  },
  { /* 107 */ 
    .name = "Digest-Nextnonce", 
    .attr = 107, 
    .type = NR_TYPE_STRING, 
  },
  { /* 108 */ 
    .name = "Digest-Method", 
    .attr = 108, 
    .type = NR_TYPE_STRING, 
  },
  { /* 109 */ 
    .name = "Digest-URI", 
    .attr = 109, 
    .type = NR_TYPE_STRING, 
  },
  { /* 110 */ 
    .name = "Digest-Qop", 
    .attr = 110, 
    .type = NR_TYPE_STRING, 
  },
  { /* 111 */ 
    .name = "Digest-Algorithm", 
    .attr = 111, 
    .type = NR_TYPE_STRING, 
  },
  { /* 112 */ 
    .name = "Digest-Entity-Body-Hash", 
    .attr = 112, 
    .type = NR_TYPE_STRING, 
  },
  { /* 113 */ 
    .name = "Digest-CNonce", 
    .attr = 113, 
    .type = NR_TYPE_STRING, 
  },
  { /* 114 */ 
    .name = "Digest-Nonce-Count", 
    .attr = 114, 
    .type = NR_TYPE_STRING, 
  },
  { /* 115 */ 
    .name = "Digest-Username", 
    .attr = 115, 
    .type = NR_TYPE_STRING, 
  },
  { /* 116 */ 
    .name = "Digest-Opaque", 
    .attr = 116, 
    .type = NR_TYPE_STRING, 
  },
  { /* 117 */ 
    .name = "Digest-Auth-Param", 
    .attr = 117, 
    .type = NR_TYPE_STRING, 
  },
  { /* 118 */ 
    .name = "Digest-AKA-Auts", 
    .attr = 118, 
    .type = NR_TYPE_STRING, 
  },
  { /* 119 */ 
    .name = "Digest-Domain", 
    .attr = 119, 
    .type = NR_TYPE_STRING, 
  },
  { /* 120 */ 
    .name = "Digest-Stale", 
    .attr = 120, 
    .type = NR_TYPE_STRING, 
  },
  { /* 121 */ 
    .name = "Digest-HA1", 
    .attr = 121, 
    .type = NR_TYPE_STRING, 
  },
  { /* 122 */ 
    .name = "SIP-AOR", 
    .attr = 122, 
    .type = NR_TYPE_STRING, 
  },
  { /* 123 */ 
    .name = "Delegated-IPv6-Prefix", 
    .attr = 123, 
    .type = NR_TYPE_IPV6PREFIX, 
  },
  { /* 124 */ 
    .name = NULL, 
  },
  { /* 125 */ 
    .name = NULL, 
  },
  { /* 126 */ 
    .name = "Operator-Name", 
    .attr = 126, 
    .type = NR_TYPE_STRING, 
  },
  { /* 127 */ 
    .name = "Location-Information", 
    .attr = 127, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 128 */ 
    .name = "Location-Data", 
    .attr = 128, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 129 */ 
    .name = "Basic-Location-Policy-Rules", 
    .attr = 129, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 130 */ 
    .name = "Extended-Location-Policy-Rules", 
    .attr = 130, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 131 */ 
    .name = "Location-Capable", 
    .attr = 131, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 132 */ 
    .name = "Requested-Location-Info", 
    .attr = 132, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 133 */ 
    .name = "Framed-Management", 
    .attr = 133, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 134 */ 
    .name = "Management-Transport-Protection", 
    .attr = 134, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 135 */ 
    .name = "Management-Policy-Id", 
    .attr = 135, 
    .type = NR_TYPE_STRING, 
  },
  { /* 136 */ 
    .name = "Management-Privilege-Level", 
    .attr = 136, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 137 */ 
    .name = "PKM-SS-Cert", 
    .attr = 137, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 138 */ 
    .name = "PKM-CA-Cert", 
    .attr = 138, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 139 */ 
    .name = "PKM-Config-Settings", 
    .attr = 139, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 140 */ 
    .name = "PKM-Cryptosuite-List", 
    .attr = 140, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 141 */ 
    .name = "PKM-SAID", 
    .attr = 141, 
    .type = NR_TYPE_SHORT, 
    .flags = {
      .length = 2,
    },
  },
  { /* 142 */ 
    .name = "PKM-SA-Descriptor", 
    .attr = 142, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 143 */ 
    .name = "PKM-Auth-Key", 
    .attr = 143, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 144 */ 
    .name = NULL, 
  },
  { /* 145 */ 
    .name = NULL, 
  },
  { /* 146 */ 
    .name = NULL, 
  },
  { /* 147 */ 
    .name = NULL, 
  },
  { /* 148 */ 
    .name = NULL, 
  },
  { /* 149 */ 
    .name = NULL, 
  },
  { /* 150 */ 
    .name = NULL, 
  },
  { /* 151 */ 
    .name = NULL, 
  },
  { /* 152 */ 
    .name = NULL, 
  },
  { /* 153 */ 
    .name = NULL, 
  },
  { /* 154 */ 
    .name = NULL, 
  },
  { /* 155 */ 
    .name = NULL, 
  },
  { /* 156 */ 
    .name = NULL, 
  },
  { /* 157 */ 
    .name = NULL, 
  },
  { /* 158 */ 
    .name = NULL, 
  },
  { /* 159 */ 
    .name = NULL, 
  },
  { /* 160 */ 
    .name = NULL, 
  },
  { /* 161 */ 
    .name = NULL, 
  },
  { /* 162 */ 
    .name = NULL, 
  },
  { /* 163 */ 
    .name = NULL, 
  },
  { /* 164 */ 
    .name = NULL, 
  },
  { /* 165 */ 
    .name = NULL, 
  },
  { /* 166 */ 
    .name = NULL, 
  },
  { /* 167 */ 
    .name = NULL, 
  },
  { /* 168 */ 
    .name = NULL, 
  },
  { /* 169 */ 
    .name = NULL, 
  },
  { /* 170 */ 
    .name = NULL, 
  },
  { /* 171 */ 
    .name = NULL, 
  },
  { /* 172 */ 
    .name = NULL, 
  },
  { /* 173 */ 
    .name = NULL, 
  },
  { /* 174 */ 
    .name = NULL, 
  },
  { /* 175 */ 
    .name = NULL, 
  },
  { /* 176 */ 
    .name = NULL, 
  },
  { /* 177 */ 
    .name = NULL, 
  },
  { /* 178 */ 
    .name = NULL, 
  },
  { /* 179 */ 
    .name = NULL, 
  },
  { /* 180 */ 
    .name = NULL, 
  },
  { /* 181 */ 
    .name = NULL, 
  },
  { /* 182 */ 
    .name = NULL, 
  },
  { /* 183 */ 
    .name = NULL, 
  },
  { /* 184 */ 
    .name = NULL, 
  },
  { /* 185 */ 
    .name = NULL, 
  },
  { /* 186 */ 
    .name = NULL, 
  },
  { /* 187 */ 
    .name = NULL, 
  },
  { /* 188 */ 
    .name = NULL, 
  },
  { /* 189 */ 
    .name = NULL, 
  },
  { /* 190 */ 
    .name = NULL, 
  },
  { /* 191 */ 
    .name = NULL, 
  },
  { /* 192 */ 
    .name = NULL, 
  },
  { /* 193 */ 
    .name = NULL, 
  },
  { /* 194 */ 
    .name = NULL, 
  },
  { /* 195 */ 
    .name = NULL, 
  },
  { /* 196 */ 
    .name = NULL, 
  },
  { /* 197 */ 
    .name = NULL, 
  },
  { /* 198 */ 
    .name = NULL, 
  },
  { /* 199 */ 
    .name = NULL, 
  },
  { /* 200 */ 
    .name = NULL, 
  },
  { /* 201 */ 
    .name = NULL, 
  },
  { /* 202 */ 
    .name = NULL, 
  },
  { /* 203 */ 
    .name = NULL, 
  },
  { /* 204 */ 
    .name = NULL, 
  },
  { /* 205 */ 
    .name = NULL, 
  },
  { /* 206 */ 
    .name = NULL, 
  },
  { /* 207 */ 
    .name = NULL, 
  },
  { /* 208 */ 
    .name = NULL, 
  },
  { /* 209 */ 
    .name = NULL, 
  },
  { /* 210 */ 
    .name = NULL, 
  },
  { /* 211 */ 
    .name = NULL, 
  },
  { /* 212 */ 
    .name = NULL, 
  },
  { /* 213 */ 
    .name = NULL, 
  },
  { /* 214 */ 
    .name = NULL, 
  },
  { /* 215 */ 
    .name = NULL, 
  },
  { /* 216 */ 
    .name = NULL, 
  },
  { /* 217 */ 
    .name = NULL, 
  },
  { /* 218 */ 
    .name = NULL, 
  },
  { /* 219 */ 
    .name = NULL, 
  },
  { /* 220 */ 
    .name = NULL, 
  },
  { /* 221 */ 
    .name = NULL, 
  },
  { /* 222 */ 
    .name = NULL, 
  },
  { /* 223 */ 
    .name = NULL, 
  },
  { /* 224 */ 
    .name = NULL, 
  },
  { /* 225 */ 
    .name = NULL, 
  },
  { /* 226 */ 
    .name = NULL, 
  },
  { /* 227 */ 
    .name = NULL, 
  },
  { /* 228 */ 
    .name = NULL, 
  },
  { /* 229 */ 
    .name = NULL, 
  },
  { /* 230 */ 
    .name = NULL, 
  },
  { /* 231 */ 
    .name = NULL, 
  },
  { /* 232 */ 
    .name = NULL, 
  },
  { /* 233 */ 
    .name = NULL, 
  },
  { /* 234 */ 
    .name = NULL, 
  },
  { /* 235 */ 
    .name = NULL, 
  },
  { /* 236 */ 
    .name = NULL, 
  },
  { /* 237 */ 
    .name = NULL, 
  },
  { /* 238 */ 
    .name = NULL, 
  },
  { /* 239 */ 
    .name = NULL, 
  },
  { /* 240 */ 
    .name = NULL, 
  },
  { /* 241 */ 
    .name = NULL, 
  },
  { /* 242 */ 
    .name = NULL, 
  },
  { /* 243 */ 
    .name = NULL, 
  },
  { /* 244 */ 
    .name = NULL, 
  },
  { /* 245 */ 
    .name = NULL, 
  },
  { /* 246 */ 
    .name = NULL, 
  },
  { /* 247 */ 
    .name = NULL, 
  },
  { /* 248 */ 
    .name = NULL, 
  },
  { /* 249 */ 
    .name = NULL, 
  },
  { /* 250 */ 
    .name = NULL, 
  },
  { /* 251 */ 
    .name = NULL, 
  },
  { /* 252 */ 
    .name = NULL, 
  },
  { /* 253 */ 
    .name = NULL, 
  },
  { /* 254 */ 
    .name = NULL, 
  },
  { /* 255 */ 
    .name = NULL, 
  },
  { /* 256 */ 
    .name = "MS-CHAP-Response", 
    .vendor = 311, 
    .attr = 1, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 257 */ 
    .name = "MS-CHAP-Error", 
    .vendor = 311, 
    .attr = 2, 
    .type = NR_TYPE_STRING, 
  },
  { /* 258 */ 
    .name = "MS-MPPE-Encryption-Policy", 
    .vendor = 311, 
    .attr = 7, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 259 */ 
    .name = "MS-MPPE-Encryption-Types", 
    .vendor = 311, 
    .attr = 8, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 260 */ 
    .name = "MS-CHAP-Domain", 
    .vendor = 311, 
    .attr = 10, 
    .type = NR_TYPE_STRING, 
  },
  { /* 261 */ 
    .name = "MS-CHAP-Challenge", 
    .vendor = 311, 
    .attr = 11, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 262 */ 
    .name = "MS-CHAP-MPPE-Keys", 
    .vendor = 311, 
    .attr = 12, 
    .type = NR_TYPE_OCTETS, 
    .flags = {
      .encrypt = FLAG_ENCRYPT_USER_PASSWORD,
    },
  },
  { /* 263 */ 
    .name = "MS-MPPE-Send-Key", 
    .vendor = 311, 
    .attr = 16, 
    .type = NR_TYPE_OCTETS, 
    .flags = {
      .encrypt = FLAG_ENCRYPT_TUNNEL_PASSWORD,
    },
  },
  { /* 264 */ 
    .name = "MS-MPPE-Recv-Key", 
    .vendor = 311, 
    .attr = 17, 
    .type = NR_TYPE_OCTETS, 
    .flags = {
      .encrypt = FLAG_ENCRYPT_TUNNEL_PASSWORD,
    },
  },
  { /* 265 */ 
    .name = "MS-CHAP2-Response", 
    .vendor = 311, 
    .attr = 25, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 266 */ 
    .name = "MS-CHAP2-Success", 
    .vendor = 311, 
    .attr = 26, 
    .type = NR_TYPE_OCTETS, 
  },
  { /* 267 */ 
    .name = "Example-Integer", 
    .vendor = 65535, 
    .attr = 1, 
    .type = NR_TYPE_INTEGER, 
    .flags = {
      .length = 4,
    },
  },
  { /* 268 */ 
    .name = "Example-String", 
    .vendor = 65535, 
    .attr = 2, 
    .type = NR_TYPE_STRING, 
  },
  { /* 269 */ 
    .name = "Example-IP-Address", 
    .vendor = 65535, 
    .attr = 3, 
    .type = NR_TYPE_IPADDR, 
    .flags = {
      .length = 4,
    },
  },
};

const int nr_dict_num_attrs = 269;

const int nr_dict_num_names = 149;

const DICT_ATTR *nr_dict_attr_names[] = {
    &nr_dict_attrs[45], /* Acct-Authentic */
    &nr_dict_attrs[41], /* Acct-Delay-Time */
    &nr_dict_attrs[52], /* Acct-Input-Gigawords */
    &nr_dict_attrs[42], /* Acct-Input-Octets */
    &nr_dict_attrs[47], /* Acct-Input-Packets */
    &nr_dict_attrs[85], /* Acct-Interim-Interval */
    &nr_dict_attrs[51], /* Acct-Link-Count */
    &nr_dict_attrs[50], /* Acct-Multi-Session-Id */
    &nr_dict_attrs[53], /* Acct-Output-Gigawords */
    &nr_dict_attrs[43], /* Acct-Output-Octets */
    &nr_dict_attrs[48], /* Acct-Output-Packets */
    &nr_dict_attrs[44], /* Acct-Session-Id */
    &nr_dict_attrs[46], /* Acct-Session-Time */
    &nr_dict_attrs[40], /* Acct-Status-Type */
    &nr_dict_attrs[49], /* Acct-Terminate-Cause */
    &nr_dict_attrs[68], /* Acct-Tunnel-Connection */
    &nr_dict_attrs[86], /* Acct-Tunnel-Packets-Lost */
    &nr_dict_attrs[84], /* ARAP-Challenge-Response */
    &nr_dict_attrs[71], /* ARAP-Features */
    &nr_dict_attrs[70], /* ARAP-Password */
    &nr_dict_attrs[73], /* ARAP-Security */
    &nr_dict_attrs[74], /* ARAP-Security-Data */
    &nr_dict_attrs[72], /* ARAP-Zone-Access */
    &nr_dict_attrs[129], /* Basic-Location-Policy-Rules */
    &nr_dict_attrs[20], /* Callback-Id */
    &nr_dict_attrs[19], /* Callback-Number */
    &nr_dict_attrs[30], /* Called-Station-Id */
    &nr_dict_attrs[31], /* Calling-Station-Id */
    &nr_dict_attrs[60], /* CHAP-Challenge */
    &nr_dict_attrs[3], /* CHAP-Password */
    &nr_dict_attrs[89], /* Chargeable-User-Identity */
    &nr_dict_attrs[25], /* Class */
    &nr_dict_attrs[78], /* Configuration-Token */
    &nr_dict_attrs[77], /* Connect-Info */
    &nr_dict_attrs[123], /* Delegated-IPv6-Prefix */
    &nr_dict_attrs[118], /* Digest-AKA-Auts */
    &nr_dict_attrs[111], /* Digest-Algorithm */
    &nr_dict_attrs[117], /* Digest-Auth-Param */
    &nr_dict_attrs[113], /* Digest-CNonce */
    &nr_dict_attrs[119], /* Digest-Domain */
    &nr_dict_attrs[112], /* Digest-Entity-Body-Hash */
    &nr_dict_attrs[121], /* Digest-HA1 */
    &nr_dict_attrs[108], /* Digest-Method */
    &nr_dict_attrs[107], /* Digest-Nextnonce */
    &nr_dict_attrs[105], /* Digest-Nonce */
    &nr_dict_attrs[114], /* Digest-Nonce-Count */
    &nr_dict_attrs[116], /* Digest-Opaque */
    &nr_dict_attrs[110], /* Digest-Qop */
    &nr_dict_attrs[104], /* Digest-Realm */
    &nr_dict_attrs[103], /* Digest-Response */
    &nr_dict_attrs[106], /* Digest-Response-Auth */
    &nr_dict_attrs[120], /* Digest-Stale */
    &nr_dict_attrs[109], /* Digest-URI */
    &nr_dict_attrs[115], /* Digest-Username */
    &nr_dict_attrs[102], /* EAP-Key-Name */
    &nr_dict_attrs[79], /* EAP-Message */
    &nr_dict_attrs[58], /* Egress-VLAN-Name */
    &nr_dict_attrs[56], /* Egress-VLANID */
    &nr_dict_attrs[101], /* Error-Cause */
    &nr_dict_attrs[55], /* Event-Timestamp */
    &nr_dict_attrs[267], /* Example-Integer */
    &nr_dict_attrs[269], /* Example-IP-Address */
    &nr_dict_attrs[268], /* Example-String */
    &nr_dict_attrs[130], /* Extended-Location-Policy-Rules */
    &nr_dict_attrs[11], /* Filter-Id */
    &nr_dict_attrs[37], /* Framed-AppleTalk-Link */
    &nr_dict_attrs[38], /* Framed-AppleTalk-Network */
    &nr_dict_attrs[39], /* Framed-AppleTalk-Zone */
    &nr_dict_attrs[13], /* Framed-Compression */
    &nr_dict_attrs[96], /* Framed-Interface-Id */
    &nr_dict_attrs[8], /* Framed-IP-Address */
    &nr_dict_attrs[9], /* Framed-IP-Netmask */
    &nr_dict_attrs[100], /* Framed-IPv6-Pool */
    &nr_dict_attrs[97], /* Framed-IPv6-Prefix */
    &nr_dict_attrs[99], /* Framed-IPv6-Route */
    &nr_dict_attrs[23], /* Framed-IPX-Network */
    &nr_dict_attrs[133], /* Framed-Management */
    &nr_dict_attrs[12], /* Framed-MTU */
    &nr_dict_attrs[88], /* Framed-Pool */
    &nr_dict_attrs[7], /* Framed-Protocol */
    &nr_dict_attrs[22], /* Framed-Route */
    &nr_dict_attrs[10], /* Framed-Routing */
    &nr_dict_attrs[28], /* Idle-Timeout */
    &nr_dict_attrs[57], /* Ingress-Filters */
    &nr_dict_attrs[131], /* Location-Capable */
    &nr_dict_attrs[128], /* Location-Data */
    &nr_dict_attrs[127], /* Location-Information */
    &nr_dict_attrs[14], /* Login-IP-Host */
    &nr_dict_attrs[98], /* Login-IPv6-Host */
    &nr_dict_attrs[36], /* Login-LAT-Group */
    &nr_dict_attrs[35], /* Login-LAT-Node */
    &nr_dict_attrs[63], /* Login-LAT-Port */
    &nr_dict_attrs[34], /* Login-LAT-Service */
    &nr_dict_attrs[15], /* Login-Service */
    &nr_dict_attrs[16], /* Login-TCP-Port */
    &nr_dict_attrs[135], /* Management-Policy-Id */
    &nr_dict_attrs[136], /* Management-Privilege-Level */
    &nr_dict_attrs[134], /* Management-Transport-Protection */
    &nr_dict_attrs[80], /* Message-Authenticator */
    &nr_dict_attrs[261], /* MS-CHAP-Challenge */
    &nr_dict_attrs[260], /* MS-CHAP-Domain */
    &nr_dict_attrs[257], /* MS-CHAP-Error */
    &nr_dict_attrs[262], /* MS-CHAP-MPPE-Keys */
    &nr_dict_attrs[256], /* MS-CHAP-Response */
    &nr_dict_attrs[265], /* MS-CHAP2-Response */
    &nr_dict_attrs[266], /* MS-CHAP2-Success */
    &nr_dict_attrs[258], /* MS-MPPE-Encryption-Policy */
    &nr_dict_attrs[259], /* MS-MPPE-Encryption-Types */
    &nr_dict_attrs[264], /* MS-MPPE-Recv-Key */
    &nr_dict_attrs[263], /* MS-MPPE-Send-Key */
    &nr_dict_attrs[92], /* NAS-Filter-Rule */
    &nr_dict_attrs[32], /* NAS-Identifier */
    &nr_dict_attrs[4], /* NAS-IP-Address */
    &nr_dict_attrs[95], /* NAS-IPv6-Address */
    &nr_dict_attrs[5], /* NAS-Port */
    &nr_dict_attrs[87], /* NAS-Port-Id */
    &nr_dict_attrs[61], /* NAS-Port-Type */
    &nr_dict_attrs[126], /* Operator-Name */
    &nr_dict_attrs[75], /* Password-Retry */
    &nr_dict_attrs[143], /* PKM-Auth-Key */
    &nr_dict_attrs[138], /* PKM-CA-Cert */
    &nr_dict_attrs[139], /* PKM-Config-Settings */
    &nr_dict_attrs[140], /* PKM-Cryptosuite-List */
    &nr_dict_attrs[142], /* PKM-SA-Descriptor */
    &nr_dict_attrs[141], /* PKM-SAID */
    &nr_dict_attrs[137], /* PKM-SS-Cert */
    &nr_dict_attrs[62], /* Port-Limit */
    &nr_dict_attrs[76], /* Prompt */
    &nr_dict_attrs[33], /* Proxy-State */
    &nr_dict_attrs[18], /* Reply-Message */
    &nr_dict_attrs[132], /* Requested-Location-Info */
    &nr_dict_attrs[6], /* Service-Type */
    &nr_dict_attrs[27], /* Session-Timeout */
    &nr_dict_attrs[122], /* SIP-AOR */
    &nr_dict_attrs[24], /* State */
    &nr_dict_attrs[29], /* Termination-Action */
    &nr_dict_attrs[82], /* Tunnel-Assignment-Id */
    &nr_dict_attrs[90], /* Tunnel-Client-Auth-Id */
    &nr_dict_attrs[66], /* Tunnel-Client-Endpoint */
    &nr_dict_attrs[65], /* Tunnel-Medium-Type */
    &nr_dict_attrs[69], /* Tunnel-Password */
    &nr_dict_attrs[83], /* Tunnel-Preference */
    &nr_dict_attrs[81], /* Tunnel-Private-Group-Id */
    &nr_dict_attrs[91], /* Tunnel-Server-Auth-Id */
    &nr_dict_attrs[67], /* Tunnel-Server-Endpoint */
    &nr_dict_attrs[64], /* Tunnel-Type */
    &nr_dict_attrs[1], /* User-Name */
    &nr_dict_attrs[2], /* User-Password */
    &nr_dict_attrs[59], /* User-Priority-Table */
    &nr_dict_attrs[26], /* Vendor-Specific */
};

