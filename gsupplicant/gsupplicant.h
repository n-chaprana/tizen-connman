/*
 *
 *  WPA supplicant library with GLib integration
 *
 *  Copyright (C) 2012-2013  Intel Corporation. All rights reserved.
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
#ifndef __G_SUPPLICANT_H
#define __G_SUPPLICANT_H

#ifdef __cplusplus
extern "C" {
#endif

#define G_SUPPLICANT_EAP_METHOD_MD5	(1 << 0)
#define G_SUPPLICANT_EAP_METHOD_TLS	(1 << 1)
#define G_SUPPLICANT_EAP_METHOD_MSCHAPV2	(1 << 2)
#define G_SUPPLICANT_EAP_METHOD_PEAP	(1 << 3)
#define G_SUPPLICANT_EAP_METHOD_TTLS	(1 << 4)
#define G_SUPPLICANT_EAP_METHOD_GTC	(1 << 5)
#define G_SUPPLICANT_EAP_METHOD_OTP	(1 << 6)
#define G_SUPPLICANT_EAP_METHOD_LEAP	(1 << 7)
#define G_SUPPLICANT_EAP_METHOD_WSC	(1 << 8)

#define G_SUPPLICANT_CAPABILITY_AUTHALG_OPEN	(1 << 0)
#define G_SUPPLICANT_CAPABILITY_AUTHALG_SHARED	(1 << 1)
#define G_SUPPLICANT_CAPABILITY_AUTHALG_LEAP	(1 << 2)

#define G_SUPPLICANT_CAPABILITY_PROTO_WPA		(1 << 0)
#define G_SUPPLICANT_CAPABILITY_PROTO_RSN		(1 << 1)

#define G_SUPPLICANT_CAPABILITY_SCAN_ACTIVE	(1 << 0)
#define G_SUPPLICANT_CAPABILITY_SCAN_PASSIVE	(1 << 1)
#define G_SUPPLICANT_CAPABILITY_SCAN_SSID		(1 << 2)

#define G_SUPPLICANT_CAPABILITY_MODE_INFRA	(1 << 0)
#define G_SUPPLICANT_CAPABILITY_MODE_IBSS		(1 << 1)
#define G_SUPPLICANT_CAPABILITY_MODE_AP		(1 << 2)
#define G_SUPPLICANT_CAPABILITY_MODE_P2P	(1 << 3)
#if defined TIZEN_EXT_WIFI_MESH
#define G_SUPPLICANT_CAPABILITY_MODE_MESH      (1 << 4)
#endif

#define G_SUPPLICANT_KEYMGMT_NONE		(1 << 0)
#define G_SUPPLICANT_KEYMGMT_IEEE8021X	(1 << 1)
#define G_SUPPLICANT_KEYMGMT_WPA_NONE	(1 << 2)
#define G_SUPPLICANT_KEYMGMT_WPA_PSK	(1 << 3)
#define G_SUPPLICANT_KEYMGMT_WPA_PSK_256	(1 << 4)
#if defined TIZEN_EXT
#define G_SUPPLICANT_KEYMGMT_WPA_FT_EAP	(1 << 5)
#define G_SUPPLICANT_KEYMGMT_WPA_FT_PSK	(1 << 6)
#else
#define G_SUPPLICANT_KEYMGMT_WPA_FT_PSK	(1 << 5)
#define G_SUPPLICANT_KEYMGMT_WPA_FT_EAP	(1 << 6)
#endif
#define G_SUPPLICANT_KEYMGMT_WPA_EAP	(1 << 7)
#define G_SUPPLICANT_KEYMGMT_WPA_EAP_256	(1 << 8)
#define G_SUPPLICANT_KEYMGMT_WPS		(1 << 9)
#if defined TIZEN_EXT
#define G_SUPPLICANT_KEYMGMT_SAE		(1 << 10)
#define G_SUPPLICANT_KEYMGMT_OWE		(1 << 22)
#define G_SUPPLICANT_KEYMGMT_DPP		(1 << 23)
#endif

#define G_SUPPLICANT_PROTO_WPA		(1 << 0)
#define G_SUPPLICANT_PROTO_RSN		(1 << 1)

#define G_SUPPLICANT_GROUP_WEP40		(1 << 0)
#define G_SUPPLICANT_GROUP_WEP104		(1 << 1)
#define G_SUPPLICANT_GROUP_TKIP		(1 << 2)
#define G_SUPPLICANT_GROUP_CCMP		(1 << 3)

#define G_SUPPLICANT_PAIRWISE_NONE	(1 << 0)
#define G_SUPPLICANT_PAIRWISE_TKIP	(1 << 1)
#define G_SUPPLICANT_PAIRWISE_CCMP	(1 << 2)

#define G_SUPPLICANT_WPS_CONFIGURED     (1 << 0)
#define G_SUPPLICANT_WPS_PBC            (1 << 1)
#define G_SUPPLICANT_WPS_PIN            (1 << 2)
#define G_SUPPLICANT_WPS_REGISTRAR      (1 << 3)

#define G_SUPPLICANT_WPS_CONFIG_PBC	0x0080

#define G_SUPPLICANT_GROUP_ROLE_CLIENT	(1 << 0)
#define G_SUPPLICANT_GROUP_ROLE_GO      (1 << 1)

typedef enum {
	G_SUPPLICANT_MODE_UNKNOWN,
	G_SUPPLICANT_MODE_INFRA,
	G_SUPPLICANT_MODE_IBSS,
	G_SUPPLICANT_MODE_MASTER,
#if defined TIZEN_EXT_WIFI_MESH
	G_SUPPLICANT_MODE_MESH,
#endif
} GSupplicantMode;

#if defined TIZEN_EXT_WIFI_MESH
typedef enum {
	G_SUPPLICANT_IEEE80211W_UNKNOWN,
	G_SUPPLICANT_IEEE80211W_OPTIONAL,
	G_SUPPLICANT_IEEE80211W_REQUIRED,
} GSupplicantPmf;
#endif

typedef enum {
	G_SUPPLICANT_SECURITY_UNKNOWN,
	G_SUPPLICANT_SECURITY_NONE,
	G_SUPPLICANT_SECURITY_WEP,
	G_SUPPLICANT_SECURITY_PSK,
	G_SUPPLICANT_SECURITY_IEEE8021X,
#if defined TIZEN_EXT
	G_SUPPLICANT_SECURITY_FT_PSK,
	G_SUPPLICANT_SECURITY_FT_IEEE8021X,
	G_SUPPLICANT_SECURITY_SAE,
	G_SUPPLICANT_SECURITY_OWE,
	G_SUPPLICANT_SECURITY_DPP,
#endif
} GSupplicantSecurity;

#if defined TIZEN_EXT
typedef enum {
	G_SUPPLICANT_EAP_KEYMGMT_NONE,
	G_SUPPLICANT_EAP_KEYMGMT_FT,
	G_SUPPLICANT_EAP_KEYMGMT_CCKM,
	G_SUPPLICANT_EAP_KEYMGMT_OKC,
} GSupplicantEapKeymgmt;

typedef enum {
	G_SUPPLICANT_MODE_IEEE80211_UNKNOWN,
	G_SUPPLICANT_MODE_IEEE80211B,
	G_SUPPLICANT_MODE_IEEE80211BG,
	G_SUPPLICANT_MODE_IEEE80211BGN,
	G_SUPPLICANT_MODE_IEEE80211A,
	G_SUPPLICANT_MODE_IEEE80211AN,
	G_SUPPLICANT_MODE_IEEE80211ANAC,
} GSupplicantPhy_mode;
#endif

typedef enum {
	G_SUPPLICANT_STATE_UNKNOWN,
	G_SUPPLICANT_STATE_DISABLED,
	G_SUPPLICANT_STATE_DISCONNECTED,
	G_SUPPLICANT_STATE_INACTIVE,
	G_SUPPLICANT_STATE_SCANNING,
	G_SUPPLICANT_STATE_AUTHENTICATING,
	G_SUPPLICANT_STATE_ASSOCIATING,
	G_SUPPLICANT_STATE_ASSOCIATED,
	G_SUPPLICANT_STATE_4WAY_HANDSHAKE,
	G_SUPPLICANT_STATE_GROUP_HANDSHAKE,
	G_SUPPLICANT_STATE_COMPLETED,
} GSupplicantState;

typedef enum {
	G_SUPPLICANT_WPS_STATE_UNKNOWN,
	G_SUPPLICANT_WPS_STATE_SUCCESS,
	G_SUPPLICANT_WPS_STATE_FAIL,
} GSupplicantWpsState;

typedef enum {
	G_SUPPLICANT_PEER_SERVICES_CHANGED,
	G_SUPPLICANT_PEER_GROUP_CHANGED,
	G_SUPPLICANT_PEER_GROUP_STARTED,
	G_SUPPLICANT_PEER_GROUP_FINISHED,
	G_SUPPLICANT_PEER_GROUP_JOINED,
	G_SUPPLICANT_PEER_GROUP_DISCONNECTED,
	G_SUPPLICANT_PEER_GROUP_FAILED,
} GSupplicantPeerState;

#if defined TIZEN_EXT
typedef enum {
	G_SUPPLICANT_INS_PREFERRED_FREQ_UNKNOWN,
	G_SUPPLICANT_INS_PREFERRED_FREQ_24GHZ,
	G_SUPPLICANT_INS_PREFERRED_FREQ_5GHZ,
} GSupplicantINSPreferredFreq;
#endif

struct _GSupplicantSSID {
#if defined TIZEN_EXT
	void *ssid;
#else
	const void *ssid;
#endif
	unsigned int ssid_len;
	unsigned int scan_ssid;
	GSupplicantMode mode;
	GSupplicantSecurity security;
	unsigned int protocol;
	unsigned int pairwise_cipher;
	unsigned int group_cipher;
	unsigned int freq;
	const char *eap;
	const char *passphrase;
	const char *identity;
	const char *anonymous_identity;
	const char *ca_cert_path;
	const char *subject_match;
	const char *altsubject_match;
	const char *domain_suffix_match;
	const char *domain_match;
	const char *client_cert_path;
	const char *private_key_path;
	const char *private_key_passphrase;
	const char *phase2_auth;
	dbus_bool_t use_wps;
	const char *pin_wps;
	const char *bgscan;
#if defined TIZEN_EXT
	unsigned char *bssid;
	unsigned int bssid_for_connect_len;
	unsigned char bssid_for_connect[6];
	GSupplicantEapKeymgmt eap_keymgmt;
	const char *phase1;
	const char *pac_file;
	uint16_t ieee80211w;
	const char *connector;
	const char *c_sign_key;
	const char *net_access_key;
#endif
};

typedef struct _GSupplicantSSID GSupplicantSSID;

/*
 * Max number of SSIDs that can be scanned.
 * In wpa_s 0.7x the limit is 4.
 * In wps_s 0.8 or later it is 16.
 * The value is only used if wpa_supplicant does not return any max limit
 * for number of scannable SSIDs.
 */
#define WPAS_MAX_SCAN_SSIDS 4

struct scan_ssid {
	unsigned char ssid[32];
	uint8_t ssid_len;
};

struct _GSupplicantScanParams {
	GSList *ssids;

	uint8_t num_ssids;

	uint8_t num_freqs;
	uint16_t *freqs;
};

typedef struct _GSupplicantScanParams GSupplicantScanParams;

struct _GSupplicantPeerParams {
	bool master;
	char *wps_pin;
	char *path;
};

typedef struct _GSupplicantPeerParams GSupplicantPeerParams;

struct _GSupplicantP2PServiceParams {
	int version;
	char *service;
	unsigned char *query;
	int query_length;
	unsigned char *response;
	int response_length;
	unsigned char *wfd_ies;
	int wfd_ies_length;
};

typedef struct _GSupplicantP2PServiceParams GSupplicantP2PServiceParams;

/* global API */
typedef void (*GSupplicantCountryCallback) (int result,
						const char *alpha2,
							void *user_data);

int g_supplicant_set_country(const char *alpha2,
				GSupplicantCountryCallback callback,
						const void *user_data);

/* Interface API */
struct _GSupplicantInterface;
struct _GSupplicantPeer;

typedef struct _GSupplicantInterface GSupplicantInterface;
typedef struct _GSupplicantPeer GSupplicantPeer;
#if defined TIZEN_EXT_WIFI_MESH
typedef struct _GSupplicantMeshPeer GSupplicantMeshPeer;
#endif

typedef void (*GSupplicantInterfaceCallback) (int result,
					GSupplicantInterface *interface,
							void *user_data);

#if defined TIZEN_EXT
typedef void (*GSupplicantMaxSpeedCallback) (int result, int maxspeed,
					     int strength, void *user_data);
#endif

#if defined TIZEN_EXT && defined TIZEN_EXT_EAP_ON_ETHERNET
void g_supplicant_replace_config_file(const char* ifname, const char *config_file);
#endif /* defined TIZEN_EXT && defined TIZEN_EXT_EAP_ON_ETHERNET */

void g_supplicant_interface_cancel(GSupplicantInterface *interface);

int g_supplicant_interface_create(const char *ifname, const char *driver,
					const char *bridge,
					GSupplicantInterfaceCallback callback,
							void *user_data);
int g_supplicant_interface_remove(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback,
							void *user_data);
int g_supplicant_interface_scan(GSupplicantInterface *interface,
					GSupplicantScanParams *scan_data,
					GSupplicantInterfaceCallback callback,
							void *user_data);

#if defined TIZEN_EXT
int g_supplicant_interface_signalpoll(GSupplicantInterface *interface,
					GSupplicantMaxSpeedCallback callback,
					void *user_data);
#endif

int g_supplicant_interface_p2p_find(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback,
							void *user_data);

int g_supplicant_interface_p2p_stop_find(GSupplicantInterface *interface);

int g_supplicant_interface_p2p_connect(GSupplicantInterface *interface,
					GSupplicantPeerParams *peer_params,
					GSupplicantInterfaceCallback callback,
					void *user_data);

int g_supplicant_interface_p2p_disconnect(GSupplicantInterface *interface,
					GSupplicantPeerParams *peer_params);

int g_supplicant_interface_p2p_listen(GSupplicantInterface *interface,
						int period, int interval);

int g_supplicant_interface_p2p_add_service(GSupplicantInterface *interface,
				GSupplicantInterfaceCallback callback,
				GSupplicantP2PServiceParams *p2p_service_params,
				void *user_data);

int g_supplicant_interface_p2p_del_service(GSupplicantInterface *interface,
				GSupplicantP2PServiceParams *p2p_service_params);

int g_supplicant_set_widi_ies(GSupplicantP2PServiceParams *p2p_service_params,
					GSupplicantInterfaceCallback callback,
					void *user_data);

int g_supplicant_interface_connect(GSupplicantInterface *interface,
					GSupplicantSSID *ssid,
					GSupplicantInterfaceCallback callback,
							void *user_data);

int g_supplicant_interface_disconnect(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback,
							void *user_data);

int g_supplicant_interface_set_apscan(GSupplicantInterface *interface,
							unsigned int ap_scan);

void g_supplicant_interface_set_data(GSupplicantInterface *interface,
								void *data);
void *g_supplicant_interface_get_data(GSupplicantInterface *interface);
const char *g_supplicant_interface_get_ifname(GSupplicantInterface *interface);
#if defined TIZEN_EXT
bool g_supplicant_interface_get_is_5_0_ghz_supported(GSupplicantInterface *interface);
#endif
const char *g_supplicant_interface_get_driver(GSupplicantInterface *interface);
GSupplicantState g_supplicant_interface_get_state(GSupplicantInterface *interface);
const char *g_supplicant_interface_get_wps_key(GSupplicantInterface *interface);
const void *g_supplicant_interface_get_wps_ssid(GSupplicantInterface *interface,
							unsigned int *ssid_len);
GSupplicantWpsState g_supplicant_interface_get_wps_state(GSupplicantInterface *interface);
unsigned int g_supplicant_interface_get_mode(GSupplicantInterface *interface);
dbus_bool_t g_supplicant_interface_get_ready(GSupplicantInterface *interface);
unsigned int g_supplicant_interface_get_max_scan_ssids(
					GSupplicantInterface *interface);

int g_supplicant_interface_enable_selected_network(GSupplicantInterface *interface,
							dbus_bool_t enable);
int g_supplicant_interface_set_country(GSupplicantInterface *interface,
					GSupplicantCountryCallback callback,
							const char *alpha2,
							void *user_data);
bool g_supplicant_interface_has_p2p(GSupplicantInterface *interface);
int g_supplicant_interface_set_p2p_device_config(GSupplicantInterface *interface,
						const char *device_name,
						const char *primary_dev_type);
GSupplicantPeer *g_supplicant_interface_peer_lookup(GSupplicantInterface *interface,
						const char *identifier);
bool g_supplicant_interface_is_p2p_finding(GSupplicantInterface *interface);

#if defined TIZEN_EXT_WIFI_MESH
bool g_supplicant_interface_has_mesh(GSupplicantInterface *interface);
int g_supplicant_mesh_interface_create(const char *ifname, const char *driver,
						const char *bridge, const char *parent_ifname,
						GSupplicantInterfaceCallback callback, void *user_data);
const void *g_supplicant_interface_get_mesh_group_ssid(
							GSupplicantInterface *interface,
							unsigned int *ssid_len);
int g_supplicant_mesh_get_disconnect_reason(GSupplicantInterface *interface);
const char *g_supplicant_mesh_peer_get_address(GSupplicantMeshPeer *mesh_peer);
int g_supplicant_mesh_peer_get_disconnect_reason(
							GSupplicantMeshPeer *mesh_peer);
int g_supplicant_interface_abort_scan(GSupplicantInterface *interface,
				GSupplicantInterfaceCallback callback, void *user_data);
int g_supplicant_interface_mesh_peer_change_status(
				GSupplicantInterface *interface,
				GSupplicantInterfaceCallback callback, const char *peer_address,
				const char *method, void *user_data);
#endif

/* Network and Peer API */
struct _GSupplicantNetwork;
struct _GSupplicantGroup;

typedef struct _GSupplicantNetwork GSupplicantNetwork;
typedef struct _GSupplicantGroup GSupplicantGroup;

GSupplicantInterface *g_supplicant_network_get_interface(GSupplicantNetwork *network);
const char *g_supplicant_network_get_name(GSupplicantNetwork *network);
const char *g_supplicant_network_get_identifier(GSupplicantNetwork *network);
const char *g_supplicant_network_get_path(GSupplicantNetwork *network);
const void *g_supplicant_network_get_ssid(GSupplicantNetwork *network,
							unsigned int *ssid_len);
const char *g_supplicant_network_get_mode(GSupplicantNetwork *network);
const char *g_supplicant_network_get_security(GSupplicantNetwork *network);
dbus_int16_t g_supplicant_network_get_signal(GSupplicantNetwork *network);
dbus_uint16_t g_supplicant_network_get_frequency(GSupplicantNetwork *network);
dbus_bool_t g_supplicant_network_get_wps(GSupplicantNetwork *network);
dbus_bool_t g_supplicant_network_is_wps_active(GSupplicantNetwork *network);
dbus_bool_t g_supplicant_network_is_wps_pbc(GSupplicantNetwork *network);
dbus_bool_t g_supplicant_network_is_wps_advertizing(GSupplicantNetwork *network);

GSupplicantInterface *g_supplicant_peer_get_interface(GSupplicantPeer *peer);
const char *g_supplicant_peer_get_path(GSupplicantPeer *peer);
const char *g_supplicant_peer_get_identifier(GSupplicantPeer *peer);
const void *g_supplicant_peer_get_device_address(GSupplicantPeer *peer);
const void *g_supplicant_peer_get_iface_address(GSupplicantPeer *peer);
const char *g_supplicant_peer_get_name(GSupplicantPeer *peer);
const unsigned char *g_supplicant_peer_get_widi_ies(GSupplicantPeer *peer,
								int *length);
bool g_supplicant_peer_is_wps_pbc(GSupplicantPeer *peer);
bool g_supplicant_peer_is_wps_pin(GSupplicantPeer *peer);
bool g_supplicant_peer_is_in_a_group(GSupplicantPeer *peer);
GSupplicantInterface *g_supplicant_peer_get_group_interface(GSupplicantPeer *peer);
bool g_supplicant_peer_is_client(GSupplicantPeer *peer);
bool g_supplicant_peer_has_requested_connection(GSupplicantPeer *peer);

#if defined TIZEN_EXT
/*
* Description: Network client requires additional wifi specific info
*/
const unsigned char *g_supplicant_network_get_bssid(
						GSupplicantNetwork *network);
unsigned int g_supplicant_network_get_maxrate(GSupplicantNetwork *network);
const char *g_supplicant_network_get_enc_mode(GSupplicantNetwork *network);
bool g_supplicant_network_get_rsn_mode(GSupplicantNetwork *network);
bool g_supplicant_network_is_hs20AP(GSupplicantNetwork *network);
const char *g_supplicant_network_get_eap(GSupplicantNetwork *network);
const char *g_supplicant_network_get_identity(GSupplicantNetwork *network);
const char *g_supplicant_network_get_phase2(GSupplicantNetwork *network);
unsigned int g_supplicant_network_get_keymgmt(GSupplicantNetwork *network);
void *g_supplicant_network_get_wifi_vsie(GSupplicantNetwork *network);
const unsigned char *g_supplicant_network_get_countrycode(GSupplicantNetwork
							  *network);
void *g_supplicant_network_get_bssid_list(GSupplicantNetwork *network);
GSupplicantPhy_mode g_supplicant_network_get_phy_mode(GSupplicantNetwork *network);
#endif
#if defined TIZEN_EXT
void g_supplicant_network_set_last_connected_bssid(GSupplicantNetwork *network, const unsigned char *bssid);
const unsigned char *g_supplicant_network_get_last_connected_bssid(GSupplicantNetwork *network);
void g_supplicant_network_update_assoc_reject(GSupplicantInterface *interface,
		GSupplicantNetwork *network);
GHashTable *g_supplicant_network_get_assoc_reject_table(GSupplicantNetwork *network);
GSupplicantNetwork *g_supplicant_interface_get_network(GSupplicantInterface *interface,
		const char *group);
#endif

struct _GSupplicantCallbacks {
	void (*system_ready) (void);
	void (*system_killed) (void);
	void (*interface_added) (GSupplicantInterface *interface);
	void (*interface_state) (GSupplicantInterface *interface);
	void (*interface_removed) (GSupplicantInterface *interface);
	void (*p2p_support) (GSupplicantInterface *interface);
	void (*scan_started) (GSupplicantInterface *interface);
	void (*scan_finished) (GSupplicantInterface *interface);
	void (*ap_create_fail) (GSupplicantInterface *interface);
	void (*network_added) (GSupplicantNetwork *network);
	void (*network_removed) (GSupplicantNetwork *network);
#if defined TIZEN_EXT
	void (*network_merged) (GSupplicantNetwork *network);
#endif
	void (*network_changed) (GSupplicantNetwork *network,
					const char *property);
	void (*network_associated) (GSupplicantNetwork *network);
#if defined TIZEN_EXT
	void (*system_power_off) (void);
	void (*assoc_failed) (void *user_data);
	void (*scan_done) (GSupplicantInterface *interface);
#endif
	void (*sta_authorized) (GSupplicantInterface *interface,
					const char *addr);
	void (*sta_deauthorized) (GSupplicantInterface *interface,
					const char *addr);
	void (*peer_found) (GSupplicantPeer *peer);
	void (*peer_lost) (GSupplicantPeer *peer);
	void (*peer_changed) (GSupplicantPeer *peer,
					GSupplicantPeerState state);
	void (*peer_request) (GSupplicantPeer *peer);
	void (*debug) (const char *str);
	void (*disconnect_reasoncode)(GSupplicantInterface *interface,
				int reasoncode);
	void (*assoc_status_code)(GSupplicantInterface *interface,
				int reasoncode);
#if defined TIZEN_EXT_WIFI_MESH
	void (*mesh_support) (GSupplicantInterface *interface);
	void (*mesh_group_started) (GSupplicantInterface *interface);
	void (*mesh_group_removed) (GSupplicantInterface *interface);
	void (*mesh_peer_connected) (GSupplicantMeshPeer *mesh_peer);
	void (*mesh_peer_disconnected) (GSupplicantMeshPeer *mesh_peer);
#endif
};

typedef struct _GSupplicantCallbacks GSupplicantCallbacks;

#if defined TIZEN_EXT
void g_supplicant_set_ins_settings(GSupplicantINSPreferredFreq preferred_freq_bssid,
		bool last_connected_bssid, bool assoc_reject, bool signal_bssid,
		unsigned int preferred_freq_bssid_score, unsigned int last_connected_bssid_score,
		unsigned int assoc_reject_score, int signal_level3_5ghz, int signal_level3_24ghz);
#endif

int g_supplicant_register(const GSupplicantCallbacks *callbacks);
void g_supplicant_unregister(const GSupplicantCallbacks *callbacks);

static inline
void g_supplicant_free_scan_params(GSupplicantScanParams *scan_params)
{
	g_slist_free_full(scan_params->ssids, g_free);
	g_free(scan_params->freqs);
	g_free(scan_params);
}

#ifdef __cplusplus
}
#endif

#endif /* __G_SUPPLICANT_H */
