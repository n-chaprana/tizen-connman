/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
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

#ifndef __CONNMAN_NETWORK_H
#define __CONNMAN_NETWORK_H

#include <stdbool.h>
#include <stdint.h>

#include <dbus/dbus.h>

#include <connman/device.h>
#include <connman/ipconfig.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined TIZEN_EXT
#define WIFI_ENCYPTION_MODE_LEN_MAX 6
#define WIFI_BSSID_LEN_MAX 6
#define MAC_ADDRESS_LENGTH 18
#endif

/**
 * SECTION:network
 * @title: Network premitives
 * @short_description: Functions for handling networks
 */

enum connman_network_type {
	CONNMAN_NETWORK_TYPE_UNKNOWN       = 0,
	CONNMAN_NETWORK_TYPE_ETHERNET      = 1,
	CONNMAN_NETWORK_TYPE_WIFI          = 2,
	CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN = 8,
	CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN = 9,
	CONNMAN_NETWORK_TYPE_CELLULAR      = 10,
	CONNMAN_NETWORK_TYPE_GADGET        = 11,
	CONNMAN_NETWORK_TYPE_VENDOR        = 10000,
};

enum connman_network_error {
	CONNMAN_NETWORK_ERROR_UNKNOWN         = 0,
	CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL  = 1,
	CONNMAN_NETWORK_ERROR_CONFIGURE_FAIL  = 2,
	CONNMAN_NETWORK_ERROR_INVALID_KEY     = 3,
	CONNMAN_NETWORK_ERROR_CONNECT_FAIL    = 4,
#if defined TIZEN_EXT
	CONNMAN_NETWORK_ERROR_DHCP_FAIL       = 5,
	CONNMAN_NETWORK_ERROR_BLOCKED	      = 6,
#else
	CONNMAN_NETWORK_ERROR_BLOCKED         = 5,
#endif
};

#if defined TIZEN_EXT
struct connman_bssids {
	unsigned char bssid[WIFI_BSSID_LEN_MAX];
	uint16_t strength;
	uint16_t frequency;
};

/* Backward compatible
 * modes of available network */
typedef enum {
	IEEE80211_UNKNOWN,
	IEEE80211_MODE_B,
	IEEE80211_MODE_BG,
	IEEE80211_MODE_BGN,
	IEEE80211_MODE_A,
	IEEE80211_MODE_AN,
	IEEE80211_MODE_ANAC,
} ieee80211_modes_e;

/* connection mode of connected network
 * based on current linkspeed */
typedef enum {
	CONNECTION_MODE_IEEE80211_UNKNOWN,
	CONNECTION_MODE_IEEE80211B,
	CONNECTION_MODE_IEEE80211G,
	CONNECTION_MODE_IEEE80211N,
	CONNECTION_MODE_IEEE80211A,
	CONNECTION_MODE_IEEE80211AC,
} connection_mode_e;
#endif

#define CONNMAN_NETWORK_PRIORITY_LOW      -100
#define CONNMAN_NETWORK_PRIORITY_DEFAULT     0
#define CONNMAN_NETWORK_PRIORITY_HIGH      100

struct connman_network;

struct connman_network *connman_network_create(const char *identifier,
					enum connman_network_type type);

#define connman_network_ref(network) \
	connman_network_ref_debug(network, __FILE__, __LINE__, __func__)

#define connman_network_unref(network) \
	connman_network_unref_debug(network, __FILE__, __LINE__, __func__)

struct connman_network *
connman_network_ref_debug(struct connman_network *network,
			const char *file, int line, const char *caller);
void connman_network_unref_debug(struct connman_network *network,
			const char *file, int line, const char *caller);

enum connman_network_type connman_network_get_type(struct connman_network *network);
const char *connman_network_get_identifier(struct connman_network *network);

void connman_network_set_index(struct connman_network *network, int index);
int connman_network_get_index(struct connman_network *network);

void connman_network_set_group(struct connman_network *network,
						const char *group);
const char *connman_network_get_group(struct connman_network *network);

bool connman_network_get_connecting(struct connman_network *network);
#if defined TIZEN_EXT
void connman_network_set_connecting(struct connman_network *network);
#endif
int connman_network_set_available(struct connman_network *network,
						bool available);
bool connman_network_get_available(struct connman_network *network);
int connman_network_set_associating(struct connman_network *network,
						bool associating);
void connman_network_set_error(struct connman_network *network,
					enum connman_network_error error);
int connman_network_set_connected(struct connman_network *network,
						bool connected);
bool connman_network_get_connected(struct connman_network *network);
void connman_network_set_connected_dhcp_later(struct connman_network *network,
		uint32_t sec);

bool connman_network_get_associating(struct connman_network *network);

void connman_network_clear_hidden(void *user_data);
int connman_network_connect_hidden(struct connman_network *network,
			char *identity, char* passphrase, void *user_data);

void connman_network_set_ipv4_method(struct connman_network *network,
					enum connman_ipconfig_method method);
void connman_network_set_ipv6_method(struct connman_network *network,
					enum connman_ipconfig_method method);
int connman_network_set_ipaddress(struct connman_network *network,
				struct connman_ipaddress *ipaddress);
int connman_network_set_nameservers(struct connman_network *network,
				const char *nameservers);
int connman_network_set_domain(struct connman_network *network,
			             const char *domain);
#if defined TIZEN_EXT
/*
 * Description: Network client requires additional wifi specific info
 */
int connman_network_set_bssid(struct connman_network *network,
				const unsigned char *bssid);
unsigned char *connman_network_get_bssid(struct connman_network *network);

int connman_network_set_maxrate(struct connman_network *network,
				unsigned int maxrate);

int connman_network_set_maxspeed(struct connman_network *network,
				int maxrate);

unsigned int connman_network_get_maxrate(struct connman_network *network);

int connman_network_get_maxspeed(struct connman_network *network);

int connman_network_set_enc_mode(struct connman_network *network,
				const char *encryption_mode);
const char *connman_network_get_enc_mode(struct connman_network *network);

int connman_network_set_rsn_mode(struct connman_network *network,
				bool rsn_mode);

int connman_network_set_proxy(struct connman_network *network,
                               const char *proxies);

void connman_network_clear_associating(struct connman_network *network);

int connman_network_set_keymgmt(struct connman_network *network,
				unsigned int keymgmt);
unsigned int connman_network_get_keymgmt(struct connman_network *network);
int connman_network_set_disconnect_reason(struct connman_network *network,
				int reason_code);
int connman_network_get_disconnect_reason(struct connman_network *network);
int connman_network_get_assoc_status_code(struct connman_network *network);
int connman_network_set_assoc_status_code(struct connman_network *network,
				int assoc_status_code);
int connman_network_set_countrycode(struct connman_network *network, const
				    unsigned char *country_code);
unsigned char *connman_network_get_countrycode(struct connman_network *network);
int connman_network_set_bssid_list(struct connman_network *network,
					GSList *bssids);
void *connman_network_get_bssid_list(struct connman_network *network);
int connman_network_set_phy_mode(struct connman_network *network,
				ieee80211_modes_e mode);
ieee80211_modes_e connman_network_get_phy_mode(struct connman_network *network);
int connman_network_set_connection_mode(struct connman_network *network,
				connection_mode_e mode);
connection_mode_e connman_network_get_connection_mode(struct connman_network *network);
#endif

int connman_network_set_name(struct connman_network *network,
							const char *name);
int connman_network_set_strength(struct connman_network *network,
						uint8_t strength);
uint8_t connman_network_get_strength(struct connman_network *network);
int connman_network_set_frequency(struct connman_network *network,
					uint16_t frequency);
uint16_t connman_network_get_frequency(struct connman_network *network);
int connman_network_set_wifi_channel(struct connman_network *network,
					uint16_t channel);
uint16_t connman_network_get_wifi_channel(struct connman_network *network);

int connman_network_set_string(struct connman_network *network,
					const char *key, const char *value);
const char *connman_network_get_string(struct connman_network *network,
							const char *key);
int connman_network_set_bool(struct connman_network *network,
					const char *key, bool value);
bool connman_network_get_bool(struct connman_network *network,
							const char *key);
int connman_network_set_blob(struct connman_network *network,
			const char *key, const void *data, unsigned int size);
const void *connman_network_get_blob(struct connman_network *network,
					const char *key, unsigned int *size);
#if defined TIZEN_EXT
void connman_network_set_vsie_list(struct connman_network *network, GSList *vsie_list);
void *connman_network_get_vsie_list(struct connman_network *network);
#endif

struct connman_device *connman_network_get_device(struct connman_network *network);

void *connman_network_get_data(struct connman_network *network);
void connman_network_set_data(struct connman_network *network, void *data);

void connman_network_update(struct connman_network *network);

struct connman_network_driver {
	const char *name;
	enum connman_network_type type;
	int priority;
	int (*probe) (struct connman_network *network);
	void (*remove) (struct connman_network *network);
	int (*connect) (struct connman_network *network);
	int (*disconnect) (struct connman_network *network);
#if defined TIZEN_EXT
	int (*merge) (struct connman_network *network);
#endif
};

int connman_network_driver_register(struct connman_network_driver *driver);
void connman_network_driver_unregister(struct connman_network_driver *driver);

void connman_network_append_acddbus(DBusMessageIter *dict,
		struct connman_network *network);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_NETWORK_H */
