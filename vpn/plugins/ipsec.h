/*
 *
 *  ConnMan VPN daemon
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

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
