#ifndef _CLOUD_TOA_SENDER_UAPI_H
#define _CLOUD_TOA_SENDER_UAPI_H

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/types.h>

#define CLOUD_TOA_SENDER_GENL_NAME "CLOUD_TOA_SENDER"
#define CLOUD_TOA_SENDER_GENL_VERSION 1

#define CLOUD_TOA_TCPOPT 254
#define CLOUD_TOA_OPT_LEN_V4 8
#define CLOUD_TOA_OPT_LEN_V6 20

enum cloud_toa_sender_cmd {
	CLOUD_TOA_SENDER_CMD_UNSPEC = 0,
	CLOUD_TOA_SENDER_CMD_ADD = 1,
	CLOUD_TOA_SENDER_CMD_DEL = 2,
	CLOUD_TOA_SENDER_CMD_GET = 3,
	CLOUD_TOA_SENDER_CMD_FLUSH = 4,
};

enum cloud_toa_sender_attr {
	CLOUD_TOA_SENDER_ATTR_UNSPEC = 0,
	CLOUD_TOA_SENDER_ATTR_LOCAL_PORT = 1,
	CLOUD_TOA_SENDER_ATTR_CLIENT_FAMILY = 2,
	CLOUD_TOA_SENDER_ATTR_CLIENT_PORT = 3,
	CLOUD_TOA_SENDER_ATTR_CLIENT_ADDR4 = 4,
	CLOUD_TOA_SENDER_ATTR_CLIENT_ADDR6 = 5,
	CLOUD_TOA_SENDER_ATTR_CREATED_AT_NS = 6,
	CLOUD_TOA_SENDER_ATTR_BACKEND_FAMILY = 7,
	CLOUD_TOA_SENDER_ATTR_BACKEND_PORT = 8,
	CLOUD_TOA_SENDER_ATTR_BACKEND_ADDR4 = 9,
	CLOUD_TOA_SENDER_ATTR_BACKEND_ADDR6 = 10,
};

struct cloud_toa_sender_opt_v4 {
	__u8 opcode;
	__u8 opsize;
	__be16 port;
	__be32 ip;
} __attribute__((packed));

struct cloud_toa_sender_opt_v6 {
	__u8 opcode;
	__u8 opsize;
	__be16 port;
	struct in6_addr ip6;
} __attribute__((packed));

#endif
