#ifndef __CONNMAN_VPND_PLUGIN_IPSEC_H
#define __CONNMAN_VPND_PLUGIN_IPSEC_H

#define IPSEC_AUTH_PSK		"PSK"
#define IPSEC_AUTH_RSA		"RSA"
#define IPSEC_AUTH_XAUTH	"XAUTH"

#define VICI_SHARED_TYPE_PSK	"IKE"
#define VICI_SHARED_TYPE_XAUTH	"xauth"

#define IPSEC_ERROR_CHECK_GOTO(err, target, fmt, arg...) do { \
	if (err < 0) { \
		connman_error(fmt, ## arg); \
		goto target; \
	} \
} while (0)

#define IPSEC_ERROR_CHECK_RETURN(err, fmt, arg...) do { \
	if (err < 0) { \
		connman_error(fmt, ## arg); \
		return; \
	} \
} while (0)

#define IPSEC_ERROR_CHECK_RETURN_VAL(err, ret, fmt, arg...) do { \
	if (err < 0) { \
		connman_error(fmt, ## arg); \
		return ret; \
	} \
} while (0)

#endif /* __CONNMAN_VPND_PLUGIN_IPSEC_H */
