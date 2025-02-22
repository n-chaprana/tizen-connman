/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2014  Intel Corporation. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <gdbus.h>
#include <ctype.h>
#include <stdint.h>

#include <connman/storage.h>
#include <connman/setting.h>
#include <connman/agent.h>

#include "connman.h"

#define CONNECT_TIMEOUT		120

#if defined TIZEN_EXT
#define WIFI_BSSID_STR_LEN	18
#define MAX_WIFI_PROFILES	200
#endif

#if defined TIZEN_EXT
#define FREQ_RANGE_24GHZ_CHANNEL_1   2412
#define FREQ_RANGE_24GHZ_CHANNEL_14  2484
#define FREQ_RANGE_5GHZ_CHANNEL_32   5160
#define FREQ_RANGE_5GHZ_CHANNEL_165  5825
#endif

static DBusConnection *connection = NULL;

static GList *service_list = NULL;
static GHashTable *service_hash = NULL;
static GSList *counter_list = NULL;
static unsigned int autoconnect_id = 0;
static unsigned int vpn_autoconnect_id = 0;
static struct connman_service *current_default = NULL;
static bool services_dirty = false;

#if defined TIZEN_EXT
static bool auto_connect_mode = TRUE;

struct saved_profiles {
	GTimeVal modified;
	gchar *profile_name;
};

#endif

#if defined TIZEN_EXT
enum connman_ins_preferred_freq {
	CONNMAN_INS_PREFERRED_FREQ_UNKNOWN,
	CONNMAN_INS_PREFERRED_FREQ_24GHZ,
	CONNMAN_INS_PREFERRED_FREQ_5GHZ,
};

struct connman_ins_settings {
	bool last_user_selection;
	unsigned int last_user_selection_time;
	unsigned int last_user_selection_score;
	bool last_connected;
	unsigned int last_connected_score;
	enum connman_ins_preferred_freq preferred_freq;
	unsigned int preferred_freq_score;
	unsigned int security_priority[CONNMAN_SERVICE_SECURITY_MAX];
	unsigned int security_priority_count;
	unsigned int security_priority_score;
	bool signal;
	bool internet;
	unsigned int internet_score;
	int signal_level3_5ghz;
	int signal_level3_24ghz;
};

static struct connman_ins_settings ins_settings;

static unsigned char invalid_bssid[WIFI_BSSID_LEN_MAX] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#endif

struct connman_stats {
	bool valid;
	bool enabled;
	struct connman_stats_data data_last;
	struct connman_stats_data data;
	GTimer *timer;
};

struct connman_stats_counter {
	bool append_all;
	struct connman_stats stats;
	struct connman_stats stats_roaming;
};

struct connman_service {
	int refcount;
	char *identifier;
	char *path;
	enum connman_service_type type;
	enum connman_service_security security;
	enum connman_service_state state;
	enum connman_service_state state_ipv4;
	enum connman_service_state state_ipv6;
	enum connman_service_error error;
	enum connman_service_connect_reason connect_reason;
	uint8_t strength;
	bool favorite;
	bool immutable;
	bool hidden;
	bool ignore;
	bool autoconnect;
	GTimeVal modified;
	unsigned int order;
	char *name;
	char *passphrase;
	bool roaming;
	struct connman_ipconfig *ipconfig_ipv4;
	struct connman_ipconfig *ipconfig_ipv6;
	struct connman_network *network;
	struct connman_provider *provider;
	char **nameservers;
	char **nameservers_config;
	char **nameservers_auto;
	int nameservers_timeout;
	char **domains;
	bool mdns;
	bool mdns_config;
	char *hostname;
	char *domainname;
	char **timeservers;
	char **timeservers_config;
	/* 802.1x settings from the config files */
	char *eap;
	char *identity;
	char *anonymous_identity;
	char *agent_identity;
	char *ca_cert_file;
	char *subject_match;
	char *altsubject_match;
	char *domain_suffix_match;
	char *domain_match;
	char *client_cert_file;
	char *private_key_file;
	char *private_key_passphrase;
	char *phase2;
	DBusMessage *pending;
	DBusMessage *provider_pending;
	guint timeout;
	struct connman_stats stats;
	struct connman_stats stats_roaming;
	GHashTable *counter_table;
	enum connman_service_proxy_method proxy;
	enum connman_service_proxy_method proxy_config;
	char **proxies;
	char **excludes;
	char *pac;
	bool wps;
	bool wps_advertizing;
	guint online_timeout;
	int online_check_interval_ipv4;
	int online_check_interval_ipv6;
	bool do_split_routing;
	bool new_service;
	bool hidden_service;
	char *config_file;
	char *config_entry;
#if defined TIZEN_EXT
	/*
	 * Description: TIZEN implements system global connection management.
	 *              It's only for PDP (cellular) bearer. Wi-Fi is managed
	 *		by ConnMan automatically. Reference count can help to
	 *		manage open/close connection requests by each application.
	 */
	int user_pdn_connection_refcount;
	bool storage_reload;
	/*
	 * Description: In case of EAP security type,
	 * 				  user can select the keymgmt type for roaming(802.11r).
	 * 				  - FT, CCKM, OKC, ...
	 */
	char *keymgmt_type;
	int disconnect_reason;
	int assoc_status_code;
	/*
	 * Only for EAP-FAST
	 */
	char *phase1;
	/*
	 * Description: To indicate that disconnection triggered by user.
	 */
	bool disconnection_requested;

	enum connman_dnsconfig_method dns_config_method_ipv4;
	enum connman_dnsconfig_method dns_config_method_ipv6;
#endif
#if defined TIZEN_EXT
	char *connector;
	char *c_sign_key;
	char *net_access_key;
#endif
#if defined TIZEN_EXT
	unsigned char last_connected_bssid[WIFI_BSSID_LEN_MAX];
	bool is_internet_connection;
	int assoc_reject_count;
	int ins_score;
#endif
};

static bool allow_property_changed(struct connman_service *service);

static struct connman_ipconfig *create_ip4config(struct connman_service *service,
		int index, enum connman_ipconfig_method method);
static struct connman_ipconfig *create_ip6config(struct connman_service *service,
		int index);
static void dns_changed(struct connman_service *service);

struct find_data {
	const char *path;
	struct connman_service *service;
};

#if defined TIZEN_EXT
struct assoc_reject_data {
	char *bssid;
	GSList *reject_time_list;
};
#endif

#if defined TIZEN_EXT
/*
 * Public APIs to use user_pdn_connection_refcount
 */
void connman_service_user_pdn_connection_ref(struct connman_service *service)
{
	__sync_fetch_and_add(&service->user_pdn_connection_refcount, 1);

	DBG("User made PDN connection referenced: %d",
				service->user_pdn_connection_refcount);
}

gboolean connman_service_user_pdn_connection_unref_and_test(
					struct connman_service *service)
{
	__sync_synchronize();

	DBG("User made PDN connection referenced: %d, which will be decreased",
				service->user_pdn_connection_refcount);

	if (service->user_pdn_connection_refcount < 1)
		return TRUE;

	if (__sync_sub_and_fetch(&service->user_pdn_connection_refcount, 1) == 0)
		return TRUE;

	return FALSE;
}

gboolean connman_service_is_no_ref_user_pdn_connection(
					struct connman_service *cellular)
{
	if (cellular == NULL)
		return TRUE;

	__sync_synchronize();
	if (cellular->type == CONNMAN_SERVICE_TYPE_CELLULAR &&
			cellular->user_pdn_connection_refcount == 0)
		return TRUE;

	return FALSE;
}
#endif

static void compare_path(gpointer value, gpointer user_data)
{
	struct connman_service *service = value;
	struct find_data *data = user_data;

	if (data->service)
		return;

	if (g_strcmp0(service->path, data->path) == 0)
		data->service = service;
}

static struct connman_service *find_service(const char *path)
{
	struct find_data data = { .path = path, .service = NULL };

	DBG("path %s", path);

	g_list_foreach(service_list, compare_path, &data);

	return data.service;
}

static const char *reason2string(enum connman_service_connect_reason reason)
{

	switch (reason) {
	case CONNMAN_SERVICE_CONNECT_REASON_NONE:
		return "none";
	case CONNMAN_SERVICE_CONNECT_REASON_USER:
		return "user";
	case CONNMAN_SERVICE_CONNECT_REASON_AUTO:
		return "auto";
	case CONNMAN_SERVICE_CONNECT_REASON_SESSION:
		return "session";
	}

	return "unknown";
}

const char *__connman_service_type2string(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_TYPE_SYSTEM:
		return "system";
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "wifi";
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return "bluetooth";
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return "cellular";
	case CONNMAN_SERVICE_TYPE_GPS:
		return "gps";
	case CONNMAN_SERVICE_TYPE_VPN:
		return "vpn";
	case CONNMAN_SERVICE_TYPE_GADGET:
		return "gadget";
	case CONNMAN_SERVICE_TYPE_P2P:
		return "p2p";
#if defined TIZEN_EXT_WIFI_MESH
	case CONNMAN_SERVICE_TYPE_MESH:
		return "mesh";
#endif
	}

	return NULL;
}

enum connman_service_type __connman_service_string2type(const char *str)
{
	if (!str)
		return CONNMAN_SERVICE_TYPE_UNKNOWN;

	if (strcmp(str, "ethernet") == 0)
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	if (strcmp(str, "gadget") == 0)
		return CONNMAN_SERVICE_TYPE_GADGET;
	if (strcmp(str, "wifi") == 0)
		return CONNMAN_SERVICE_TYPE_WIFI;
	if (strcmp(str, "cellular") == 0)
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	if (strcmp(str, "bluetooth") == 0)
		return CONNMAN_SERVICE_TYPE_BLUETOOTH;
	if (strcmp(str, "vpn") == 0)
		return CONNMAN_SERVICE_TYPE_VPN;
	if (strcmp(str, "gps") == 0)
		return CONNMAN_SERVICE_TYPE_GPS;
	if (strcmp(str, "system") == 0)
		return CONNMAN_SERVICE_TYPE_SYSTEM;
	if (strcmp(str, "p2p") == 0)
		return CONNMAN_SERVICE_TYPE_P2P;

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

enum connman_service_security __connman_service_string2security(const char *str)
{
	if (!str)
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;

	if (!strcmp(str, "psk"))
		return CONNMAN_SERVICE_SECURITY_PSK;
	if (!strcmp(str, "ieee8021x") || !strcmp(str, "8021x"))
		return CONNMAN_SERVICE_SECURITY_8021X;
	if (!strcmp(str, "none") || !strcmp(str, "open"))
		return CONNMAN_SERVICE_SECURITY_NONE;
	if (!strcmp(str, "wep"))
		return CONNMAN_SERVICE_SECURITY_WEP;
#if defined TIZEN_EXT
	if (!strcmp(str, "rsn"))
		return CONNMAN_SERVICE_SECURITY_RSN;
	if (!strcmp(str, "sae"))
		return CONNMAN_SERVICE_SECURITY_SAE;
	if (!strcmp(str, "owe"))
		return CONNMAN_SERVICE_SECURITY_OWE;
	if (!strcmp(str, "dpp"))
		return CONNMAN_SERVICE_SECURITY_DPP;
#endif

	return CONNMAN_SERVICE_SECURITY_UNKNOWN;
}

static const char *security2string(enum connman_service_security security)
{
	switch (security) {
	case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		break;
	case CONNMAN_SERVICE_SECURITY_NONE:
		return "none";
	case CONNMAN_SERVICE_SECURITY_WEP:
		return "wep";
	case CONNMAN_SERVICE_SECURITY_PSK:
	case CONNMAN_SERVICE_SECURITY_WPA:
#if defined TIZEN_EXT
		return "psk";
	case CONNMAN_SERVICE_SECURITY_RSN:
		return "rsn";
	case CONNMAN_SERVICE_SECURITY_SAE:
		return "sae";
	case CONNMAN_SERVICE_SECURITY_OWE:
		return "owe";
	case CONNMAN_SERVICE_SECURITY_DPP:
		return "dpp";
#else
	case CONNMAN_SERVICE_SECURITY_RSN:
		return "psk";
#endif
	case CONNMAN_SERVICE_SECURITY_8021X:
		return "ieee8021x";
	}

	return NULL;
}

static const char *state2string(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_STATE_IDLE:
		return "idle";
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
		return "association";
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		return "configuration";
	case CONNMAN_SERVICE_STATE_READY:
		return "ready";
	case CONNMAN_SERVICE_STATE_ONLINE:
		return "online";
	case CONNMAN_SERVICE_STATE_DISCONNECT:
		return "disconnect";
	case CONNMAN_SERVICE_STATE_FAILURE:
		return "failure";
	}

	return NULL;
}

static const char *error2string(enum connman_service_error error)
{
	switch (error) {
	case CONNMAN_SERVICE_ERROR_UNKNOWN:
		break;
	case CONNMAN_SERVICE_ERROR_OUT_OF_RANGE:
		return "out-of-range";
	case CONNMAN_SERVICE_ERROR_PIN_MISSING:
		return "pin-missing";
	case CONNMAN_SERVICE_ERROR_DHCP_FAILED:
		return "dhcp-failed";
	case CONNMAN_SERVICE_ERROR_CONNECT_FAILED:
		return "connect-failed";
	case CONNMAN_SERVICE_ERROR_LOGIN_FAILED:
		return "login-failed";
	case CONNMAN_SERVICE_ERROR_AUTH_FAILED:
		return "auth-failed";
	case CONNMAN_SERVICE_ERROR_INVALID_KEY:
		return "invalid-key";
	case CONNMAN_SERVICE_ERROR_BLOCKED:
		return "blocked";
	}

	return NULL;
}

static const char *proxymethod2string(enum connman_service_proxy_method method)
{
	switch (method) {
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		return "direct";
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		return "manual";
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		return "auto";
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		break;
	}

	return NULL;
}

static enum connman_service_proxy_method string2proxymethod(const char *method)
{
	if (g_strcmp0(method, "direct") == 0)
		return CONNMAN_SERVICE_PROXY_METHOD_DIRECT;
	else if (g_strcmp0(method, "auto") == 0)
		return CONNMAN_SERVICE_PROXY_METHOD_AUTO;
	else if (g_strcmp0(method, "manual") == 0)
		return CONNMAN_SERVICE_PROXY_METHOD_MANUAL;
	else
		return CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;
}

#ifdef TIZEN_EXT
static const char *__connman_dnsconfig_method2string(enum connman_dnsconfig_method method)
{
	switch (method) {
	case CONNMAN_DNSCONFIG_METHOD_UNKNOWN:
		return "unknown";
	case CONNMAN_DNSCONFIG_METHOD_MANUAL:
		return "manual";
	case CONNMAN_DNSCONFIG_METHOD_DHCP:
		return "dhcp";
	}

	return NULL;
}

static enum connman_dnsconfig_method __connman_dnsconfig_string2method(
		const char *method)
{
	if (g_strcmp0(method, "manual") == 0)
		return CONNMAN_DNSCONFIG_METHOD_MANUAL;
	else if (g_strcmp0(method, "dhcp") == 0)
		return CONNMAN_DNSCONFIG_METHOD_DHCP;
	else
		return CONNMAN_DNSCONFIG_METHOD_UNKNOWN;
}
#endif

static void set_split_routing(struct connman_service *service, bool value)
{
	if (service->type != CONNMAN_SERVICE_TYPE_VPN)
		return;

	service->do_split_routing = value;

	if (service->do_split_routing)
		service->order = 0;
	else
		service->order = 10;
}

int __connman_service_load_modifiable(struct connman_service *service)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	gchar *str;
	bool autoconnect;

	DBG("service %p", service);

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile)
		return -EIO;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
#if defined TIZEN_EXT_WIFI_MESH
	case CONNMAN_SERVICE_TYPE_MESH:
#endif
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
		set_split_routing(service, g_key_file_get_boolean(keyfile,
							service->identifier,
							"SplitRouting", NULL));

		/* fall through */
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		autoconnect = g_key_file_get_boolean(keyfile,
				service->identifier, "AutoConnect", &error);
		if (!error)
			service->autoconnect = autoconnect;
		g_clear_error(&error);
		break;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Modified", NULL);
	if (str) {
		g_time_val_from_iso8601(str, &service->modified);
		g_free(str);
	}

	g_key_file_free(keyfile);

	return 0;
}

#if defined TIZEN_EXT
static void save_assoc_reject(gpointer key, gpointer value, gpointer user_data)
{
	struct assoc_reject_data *assoc_rd = value;
	GString *assoc_reject_str = user_data;
	GSList *list;
	char *val_str;

	if (g_slist_length(assoc_rd->reject_time_list) < 1)
		return;

	for (list = assoc_rd->reject_time_list; list; list = list->next) {
		time_t assoc_reject_time = GPOINTER_TO_INT(list->data);

		val_str = g_strdup_printf("%s_%ld", assoc_rd->bssid, assoc_reject_time);

		if (assoc_reject_str->len > 0)
			g_string_append_printf(assoc_reject_str, " %s", val_str);
		else
			g_string_append(assoc_reject_str, val_str);

		g_free(val_str);
	}
}

static void count_assoc_reject(gpointer key, gpointer value, gpointer user_data)
{
	struct assoc_reject_data *assoc_data = value;
	int *assoc_reject_count = user_data;

	*assoc_reject_count += g_slist_length(assoc_data->reject_time_list);
}

static bool update_assoc_reject(struct connman_service *service)
{
	GHashTable *assoc_reject_table;
	int assoc_reject_count;

	if (!service->network)
		return false;

	assoc_reject_table = connman_network_get_assoc_reject_table(service->network);
	if (assoc_reject_table) {
		assoc_reject_count = 0;
		g_hash_table_foreach(assoc_reject_table, count_assoc_reject, &assoc_reject_count);
#if defined TIZEN_EXT_INS
		DBG("assoc reject count [%d -> %d]",
			service->assoc_reject_count, assoc_reject_count);
#endif
		if (service->assoc_reject_count != assoc_reject_count) {
			service->assoc_reject_count = assoc_reject_count;
			return true;
		}
	}

	return false;
}

static int service_ext_load(struct connman_service *service)
{
	GKeyFile *keyfile;
	GHashTable *reject_table;
	char **reject_list;
	gsize reject_len;
	struct assoc_reject_data *reject_data;
	char **bssid_time;
	char *bssid;
	time_t reject_time;
	time_t curr_time;
	time_t ref_time;
	struct tm* ref_timeinfo;
	int i;
	int err = 0;

	DBG("service %p", service);

	if (!service->network)
		return -EINVAL;

	if (service->type != CONNMAN_SERVICE_TYPE_WIFI)
		return -EINVAL;

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile)
		return -EIO;

	reject_table = connman_network_get_assoc_reject_table(service->network);

	reject_list = g_key_file_get_string_list(keyfile,
		service->identifier, "AssocReject", &reject_len, NULL);

	if (!reject_list || reject_len == 0) {
		g_strfreev(reject_list);
		goto done;
	}

	/* Only events that occur within one hour are appened. */
	curr_time = time(NULL);
	ref_timeinfo = localtime(&curr_time);
	ref_timeinfo->tm_hour -= 1;
	ref_time = mktime(ref_timeinfo);

	for (i = 0; reject_list[i]; i++) {
		bssid_time = g_strsplit(reject_list[i], "_", 0);
		if (!bssid_time) {
			err = -ERANGE;
			continue;
		}

		bssid = bssid_time[0];
		reject_time = strtol(bssid_time[1], NULL, 10);

		if (reject_time < ref_time) {
			g_strfreev(bssid_time);
			err = -ERANGE;
			continue;
		}

		reject_data = g_hash_table_lookup(reject_table, bssid);
		if (!reject_data) {
			reject_data = g_try_new0(struct assoc_reject_data, 1);
			if (!reject_data) {
				g_strfreev(bssid_time);
				err = -ERANGE;
				continue;
			}

			memset(reject_data, 0, sizeof(struct assoc_reject_data));
			reject_data->bssid = g_strdup(bssid);
			g_hash_table_insert(reject_table, reject_data->bssid, reject_data);
		}

		reject_data->reject_time_list = g_slist_append(reject_data->reject_time_list,
				GINT_TO_POINTER(reject_time));

#if defined TIZEN_EXT_INS
		DBG("assoc reject [%s_%ld]", bssid, reject_time);
#endif

		g_strfreev(bssid_time);
	}

	g_strfreev(reject_list);

done:
	g_key_file_free(keyfile);
	return err;
}

static int service_ext_save(struct connman_service *service)
{
	GKeyFile *keyfile;
	GHashTable *reject_table;
	GString *reject_str;
	char **reject_list;
	guint reject_len;
	int err = 0;

	DBG("service %p", service);

	if (!service->network)
		return -EINVAL;

	if (service->type != CONNMAN_SERVICE_TYPE_WIFI)
		return -EINVAL;

	keyfile = __connman_storage_open_service(service->identifier);
	if (!keyfile)
		return -EIO;

	/* Last connected BSSID */
	if (memcmp(service->last_connected_bssid, invalid_bssid, WIFI_BSSID_LEN_MAX)) {
		char *identifier = service->identifier;
		GString *bssid_str;
		unsigned int i;

		bssid_str = g_string_sized_new(MAC_ADDRESS_LENGTH);
		if (!bssid_str) {
			err = -ENOMEM;
			goto next;
		}

		for (i = 0; i < WIFI_BSSID_LEN_MAX; i++) {
			g_string_append_printf(bssid_str,
					"%02x", service->last_connected_bssid[i]);
			if (i < WIFI_BSSID_LEN_MAX - 1)
				g_string_append(bssid_str, ":");
		}

		g_key_file_set_string(keyfile, identifier,
					"LastConnectedBSSID", bssid_str->str);

#if defined TIZEN_EXT_INS
		DBG("last connected bssid[%s]", bssid_str->str);
#endif

		g_string_free(bssid_str, TRUE);
	}

next:

	/* Assoc reject */
	reject_table = connman_network_get_assoc_reject_table(service->network);
	if (reject_table && g_hash_table_size(reject_table) > 0) {
		reject_str = g_string_new(NULL);
		if (!reject_str) {
			err = -ENOMEM;
			goto done;
		}

		g_hash_table_foreach(reject_table, save_assoc_reject, reject_str);

		reject_list = g_strsplit_set(reject_str->str, " ", 0);
		reject_len = g_strv_length(reject_list);

		g_key_file_set_string_list(keyfile, service->identifier,
			"AssocReject", (const gchar **)reject_list, reject_len);

#if defined TIZEN_EXT_INS
		DBG("assoc reject table [%d]", reject_len);
#endif

		g_strfreev(reject_list);
		g_string_free(reject_str, TRUE);
	} else {
		g_key_file_remove_key(keyfile, service->identifier, "AssocReject", NULL);
	}

done:
	__connman_storage_save_service(keyfile, service->identifier);

	g_key_file_free(keyfile);
	return err;
}
#endif

static int service_load(struct connman_service *service)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	gsize length;
	gchar *str;
	bool autoconnect;
	unsigned int ssid_len;
	int err = 0;
#if defined TIZEN_EXT
	bool internet_connection;
#endif

	DBG("service %p", service);

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile) {
		service->new_service = true;
		return -EIO;
	} else
		service->new_service = false;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
#if defined TIZEN_EXT_WIFI_MESH
	case CONNMAN_SERVICE_TYPE_MESH:
#endif
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
		set_split_routing(service, g_key_file_get_boolean(keyfile,
							service->identifier,
							"SplitRouting", NULL));

		autoconnect = g_key_file_get_boolean(keyfile,
				service->identifier, "AutoConnect", &error);
		if (!error)
			service->autoconnect = autoconnect;
		g_clear_error(&error);
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		if (!service->name) {
			gchar *name;

			name = g_key_file_get_string(keyfile,
					service->identifier, "Name", NULL);
			if (name) {
				g_free(service->name);
				service->name = name;
			}

			if (service->network)
				connman_network_set_name(service->network,
									name);
		}

		if (service->network &&
				!connman_network_get_blob(service->network,
						"WiFi.SSID", &ssid_len)) {
			gchar *hex_ssid;

			hex_ssid = g_key_file_get_string(keyfile,
							service->identifier,
								"SSID", NULL);

			if (hex_ssid) {
				gchar *ssid;
				unsigned int i, j = 0, hex;
				size_t hex_ssid_len = strlen(hex_ssid);

				ssid = g_try_malloc0(hex_ssid_len / 2);
				if (!ssid) {
					g_free(hex_ssid);
					err = -ENOMEM;
					goto done;
				}

				for (i = 0; i < hex_ssid_len; i += 2) {
					sscanf(hex_ssid + i, "%02x", &hex);
					ssid[j++] = hex;
				}

				connman_network_set_blob(service->network,
					"WiFi.SSID", ssid, hex_ssid_len / 2);

				g_free(ssid);
			}

			g_free(hex_ssid);
		}

#if defined TIZEN_EXT
		/* Last connected BSSID */
		if (service->network) {
			gchar *bssid_str;
			unsigned char last_connected_bssid[WIFI_BSSID_LEN_MAX];
			char **str_list;
			unsigned int i;

			bssid_str = g_key_file_get_string(keyfile,
				service->identifier, "LastConnectedBSSID", NULL);

			if (bssid_str) {
				str_list = g_strsplit(bssid_str, ":", 0);

				if (str_list) {
					for (i = 0; i < WIFI_BSSID_LEN_MAX; i++)
						last_connected_bssid[i] = strtol(str_list[i], NULL, 16);

					memcpy(service->last_connected_bssid,
						last_connected_bssid, WIFI_BSSID_LEN_MAX);

					connman_network_set_last_connected_bssid(service->network,
						last_connected_bssid);

					g_strfreev(str_list);
				}

				g_free(bssid_str);
			}
		}

		/* Internet connection */
		internet_connection = g_key_file_get_boolean(keyfile,
				service->identifier, "InternetConnection", &error);
		if (!error)
			service->is_internet_connection = internet_connection;

		g_clear_error(&error);
#endif
		/* fall through */

	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		service->favorite = g_key_file_get_boolean(keyfile,
				service->identifier, "Favorite", NULL);

		/* fall through */

	case CONNMAN_SERVICE_TYPE_ETHERNET:
		autoconnect = g_key_file_get_boolean(keyfile,
				service->identifier, "AutoConnect", &error);
		if (!error)
			service->autoconnect = autoconnect;
		g_clear_error(&error);
		break;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Modified", NULL);
	if (str) {
		g_time_val_from_iso8601(str, &service->modified);
		g_free(str);
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Passphrase", NULL);
	if (str) {
		g_free(service->passphrase);
		service->passphrase = str;
	}

	if (service->ipconfig_ipv4)
		__connman_ipconfig_load(service->ipconfig_ipv4, keyfile,
					service->identifier, "IPv4.");

	if (service->ipconfig_ipv6)
		__connman_ipconfig_load(service->ipconfig_ipv6, keyfile,
					service->identifier, "IPv6.");

	service->nameservers_config = g_key_file_get_string_list(keyfile,
			service->identifier, "Nameservers", &length, NULL);
	if (service->nameservers_config && length == 0) {
		g_strfreev(service->nameservers_config);
		service->nameservers_config = NULL;
	}

#ifdef TIZEN_EXT
	char *dns_method;

	dns_method = g_key_file_get_string(keyfile, service->identifier,
			"Nameservers.IPv4method", NULL);
	if (dns_method) {
		service->dns_config_method_ipv4 = __connman_dnsconfig_string2method(dns_method);
		g_free(dns_method);
	}

	dns_method = g_key_file_get_string(keyfile, service->identifier,
			"Nameservers.IPv6method", NULL);
	if (dns_method) {
		service->dns_config_method_ipv6 = __connman_dnsconfig_string2method(dns_method);
		g_free(dns_method);
	}
#endif

	service->timeservers_config = g_key_file_get_string_list(keyfile,
			service->identifier, "Timeservers", &length, NULL);
	if (service->timeservers_config && length == 0) {
		g_strfreev(service->timeservers_config);
		service->timeservers_config = NULL;
	}

	service->domains = g_key_file_get_string_list(keyfile,
			service->identifier, "Domains", &length, NULL);
	if (service->domains && length == 0) {
		g_strfreev(service->domains);
		service->domains = NULL;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Proxy.Method", NULL);
	if (str)
		service->proxy_config = string2proxymethod(str);

	g_free(str);

	service->proxies = g_key_file_get_string_list(keyfile,
			service->identifier, "Proxy.Servers", &length, NULL);
	if (service->proxies && length == 0) {
		g_strfreev(service->proxies);
		service->proxies = NULL;
	}

	service->excludes = g_key_file_get_string_list(keyfile,
			service->identifier, "Proxy.Excludes", &length, NULL);
	if (service->excludes && length == 0) {
		g_strfreev(service->excludes);
		service->excludes = NULL;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Proxy.URL", NULL);
	if (str) {
		g_free(service->pac);
		service->pac = str;
	}

	service->mdns_config = g_key_file_get_boolean(keyfile,
				service->identifier, "mDNS", NULL);

	service->hidden_service = g_key_file_get_boolean(keyfile,
					service->identifier, "Hidden", NULL);

#if defined TIZEN_EXT
	if (service->type == CONNMAN_SERVICE_TYPE_WIFI &&
			service->security == CONNMAN_SERVICE_SECURITY_8021X) {
		str = g_key_file_get_string(keyfile,
				service->identifier, "EAP", NULL);
		if (str != NULL) {
			g_free(service->eap);
			service->eap = str;
		}

		str = g_key_file_get_string(keyfile,
				service->identifier, "Phase2", NULL);
		if (str != NULL) {
			g_free(service->phase2);
			service->phase2 = str;
		}

		str = g_key_file_get_string(keyfile,
				service->identifier, "Identity", NULL);
		if (str != NULL) {
			g_free(service->identity);
			service->identity = str;
		}

		str = g_key_file_get_string(keyfile,
				service->identifier, "CACertFile", NULL);
		if (str != NULL) {
			g_free(service->ca_cert_file);
			service->ca_cert_file = str;
		}

		str = g_key_file_get_string(keyfile,
				service->identifier, "ClientCertFile", NULL);
		if (str != NULL) {
			g_free(service->client_cert_file);
			service->client_cert_file = str;
		}

		str = g_key_file_get_string(keyfile,
				service->identifier, "PrivateKeyFile", NULL);
		if (str != NULL) {
			g_free(service->private_key_file);
			service->private_key_file = str;
		}

		str = g_key_file_get_string(keyfile,
				service->identifier, "PrivateKeyPassphrase", NULL);
		if (str != NULL) {
			g_free(service->private_key_passphrase);
			service->private_key_passphrase = str;
		}
	}
#endif
#if defined TIZEN_EXT
	if (service->type == CONNMAN_SERVICE_TYPE_WIFI &&
			service->security == CONNMAN_SERVICE_SECURITY_DPP) {
		str = g_key_file_get_string(keyfile,
				service->identifier, "Connector", NULL);
		if (str != NULL) {
			g_free(service->connector);
			service->connector = str;
		}
		str = g_key_file_get_string(keyfile,
				service->identifier, "CSignKey", NULL);
		if (str != NULL) {
			g_free(service->c_sign_key);
			service->c_sign_key = str;
		}
		str = g_key_file_get_string(keyfile,
				service->identifier, "NetAccessKey", NULL);
		if (str != NULL) {
			g_free(service->net_access_key);
			service->net_access_key = str;
		}
	}
#endif

done:
	g_key_file_free(keyfile);

	return err;
}

static int service_save(struct connman_service *service)
{
	GKeyFile *keyfile;
	gchar *str;
	guint freq;
	const char *cst_str = NULL;
	int err = 0;

	DBG("service %p new %d", service, service->new_service);

	if (service->new_service)
		return -ESRCH;

	keyfile = __connman_storage_open_service(service->identifier);
	if (!keyfile)
		return -EIO;

	if (service->name)
		g_key_file_set_string(keyfile, service->identifier,
						"Name", service->name);

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
#if defined TIZEN_EXT_WIFI_MESH
	case CONNMAN_SERVICE_TYPE_MESH:
#endif
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
		g_key_file_set_boolean(keyfile, service->identifier,
				"SplitRouting", service->do_split_routing);
		if (service->favorite)
			g_key_file_set_boolean(keyfile, service->identifier,
					"AutoConnect", service->autoconnect);
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		if (service->network) {
			const unsigned char *ssid;
			unsigned int ssid_len = 0;
#if defined TIZEN_EXT
			GHashTable *assoc_reject_table;
#endif

			ssid = connman_network_get_blob(service->network,
							"WiFi.SSID", &ssid_len);

			if (ssid && ssid_len > 0 && ssid[0] != '\0') {
				char *identifier = service->identifier;
				GString *ssid_str;
				unsigned int i;

				ssid_str = g_string_sized_new(ssid_len * 2);
				if (!ssid_str) {
					err = -ENOMEM;
					goto done;
				}

				for (i = 0; i < ssid_len; i++)
					g_string_append_printf(ssid_str,
							"%02x", ssid[i]);

				g_key_file_set_string(keyfile, identifier,
							"SSID", ssid_str->str);

				g_string_free(ssid_str, TRUE);
			}

			freq = connman_network_get_frequency(service->network);
			g_key_file_set_integer(keyfile, service->identifier,
						"Frequency", freq);

#if defined TIZEN_EXT
			/* Last connected BSSID */
			if (memcmp(service->last_connected_bssid, invalid_bssid, WIFI_BSSID_LEN_MAX)) {
				char *identifier = service->identifier;
				GString *bssid_str;
				unsigned int i;

				bssid_str = g_string_sized_new(18);
				if (!bssid_str) {
					err = -ENOMEM;
					goto done;
				}

				for (i = 0; i < WIFI_BSSID_LEN_MAX; i++) {
					g_string_append_printf(bssid_str,
							"%02x", service->last_connected_bssid[i]);
					if (i < WIFI_BSSID_LEN_MAX - 1)
						g_string_append(bssid_str, ":");
				}

				g_key_file_set_string(keyfile, identifier,
							"LastConnectedBSSID", bssid_str->str);

#if defined TIZEN_EXT_INS
				DBG("last connected bssid[%s]", bssid_str->str);
#endif

				g_string_free(bssid_str, TRUE);
			}

			/* Assoc reject */
			assoc_reject_table = connman_network_get_assoc_reject_table(service->network);
			if (assoc_reject_table && g_hash_table_size(assoc_reject_table) > 0) {
				GString *assoc_reject_str;
				char **assoc_reject_list;
				guint assoc_reject_len;

				assoc_reject_str = g_string_new(NULL);
				if (!assoc_reject_str) {
					err = -ENOMEM;
					goto done;
				}

				g_hash_table_foreach(assoc_reject_table, save_assoc_reject, assoc_reject_str);

				assoc_reject_list = g_strsplit_set(assoc_reject_str->str, " ", 0);
				assoc_reject_len = g_strv_length(assoc_reject_list);

				g_key_file_set_string_list(keyfile, service->identifier,
					"AssocReject", (const gchar **)assoc_reject_list, assoc_reject_len);

#if defined TIZEN_EXT_INS
				DBG("assoc reject table [%d]", assoc_reject_len);
#endif

				g_strfreev(assoc_reject_list);
				g_string_free(assoc_reject_str, TRUE);
			} else
				g_key_file_remove_key(keyfile, service->identifier, "AssocReject", NULL);

			/* Internet connection */
			g_key_file_set_boolean(keyfile, service->identifier,
					"InternetConnection", service->is_internet_connection);
#if defined TIZEN_EXT_INS
			DBG("internet connection [%s]", service->is_internet_connection ? "true" : "false");
#endif
#endif
		}
		/* fall through */

	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		g_key_file_set_boolean(keyfile, service->identifier,
					"Favorite", service->favorite);

		g_key_file_remove_key(keyfile, service->identifier,
				"Failure", NULL);

		/* fall through */

	case CONNMAN_SERVICE_TYPE_ETHERNET:
		if (service->favorite)
			g_key_file_set_boolean(keyfile, service->identifier,
					"AutoConnect", service->autoconnect);
		break;
	}

	str = g_time_val_to_iso8601(&service->modified);
	if (str) {
		g_key_file_set_string(keyfile, service->identifier,
							"Modified", str);
		g_free(str);
	}

	if (service->passphrase && strlen(service->passphrase) > 0)
		g_key_file_set_string(keyfile, service->identifier,
					"Passphrase", service->passphrase);
	else
		g_key_file_remove_key(keyfile, service->identifier,
							"Passphrase", NULL);

	if (service->ipconfig_ipv4)
		__connman_ipconfig_save(service->ipconfig_ipv4, keyfile,
					service->identifier, "IPv4.");

	if (service->ipconfig_ipv6)
		__connman_ipconfig_save(service->ipconfig_ipv6, keyfile,
						service->identifier, "IPv6.");

	if (service->nameservers_config) {
		guint len = g_strv_length(service->nameservers_config);

		g_key_file_set_string_list(keyfile, service->identifier,
								"Nameservers",
				(const gchar **) service->nameservers_config, len);
	} else
	g_key_file_remove_key(keyfile, service->identifier,
							"Nameservers", NULL);

#if defined TIZEN_EXT
	if(service->dns_config_method_ipv4 != 0) {
		const char *method;
		method = __connman_dnsconfig_method2string(
				service->dns_config_method_ipv4);
		g_key_file_set_string(keyfile, service->identifier,
				"Nameservers.IPv4method", method);
	} else
	g_key_file_remove_key(keyfile, service->identifier,
						"Nameservers.IPv4method", NULL);

	if(service->dns_config_method_ipv6 != 0) {
		const char *method;
		method = __connman_dnsconfig_method2string(
				service->dns_config_method_ipv6);
		g_key_file_set_string(keyfile, service->identifier,
				"Nameservers.IPv6method", method);
	} else
	g_key_file_remove_key(keyfile, service->identifier,
							"Nameservers.IPv6method", NULL);
#endif

	if (service->timeservers_config) {
		guint len = g_strv_length(service->timeservers_config);

		g_key_file_set_string_list(keyfile, service->identifier,
								"Timeservers",
				(const gchar **) service->timeservers_config, len);
	} else
		g_key_file_remove_key(keyfile, service->identifier,
							"Timeservers", NULL);

	if (service->domains) {
		guint len = g_strv_length(service->domains);

		g_key_file_set_string_list(keyfile, service->identifier,
								"Domains",
				(const gchar **) service->domains, len);
	} else
		g_key_file_remove_key(keyfile, service->identifier,
							"Domains", NULL);

	cst_str = proxymethod2string(service->proxy_config);
	if (cst_str)
		g_key_file_set_string(keyfile, service->identifier,
				"Proxy.Method", cst_str);

	if (service->proxies) {
		guint len = g_strv_length(service->proxies);

		g_key_file_set_string_list(keyfile, service->identifier,
				"Proxy.Servers",
				(const gchar **) service->proxies, len);
	} else
		g_key_file_remove_key(keyfile, service->identifier,
						"Proxy.Servers", NULL);

	if (service->excludes) {
		guint len = g_strv_length(service->excludes);

		g_key_file_set_string_list(keyfile, service->identifier,
				"Proxy.Excludes",
				(const gchar **) service->excludes, len);
	} else
		g_key_file_remove_key(keyfile, service->identifier,
						"Proxy.Excludes", NULL);

	if (service->pac && strlen(service->pac) > 0)
		g_key_file_set_string(keyfile, service->identifier,
					"Proxy.URL", service->pac);
	else
		g_key_file_remove_key(keyfile, service->identifier,
							"Proxy.URL", NULL);

	if (service->mdns_config)
		g_key_file_set_boolean(keyfile, service->identifier,
								"mDNS", TRUE);
	else
		g_key_file_remove_key(keyfile, service->identifier,
								"mDNS", NULL);

	if (service->hidden_service)
		g_key_file_set_boolean(keyfile, service->identifier, "Hidden",
									TRUE);

	if (service->config_file && strlen(service->config_file) > 0)
		g_key_file_set_string(keyfile, service->identifier,
				"Config.file", service->config_file);

	if (service->config_entry &&
					strlen(service->config_entry) > 0)
		g_key_file_set_string(keyfile, service->identifier,
				"Config.ident", service->config_entry);

#if defined TIZEN_EXT
	if (service->type == CONNMAN_SERVICE_TYPE_WIFI &&
			service->security == CONNMAN_SERVICE_SECURITY_8021X) {
		if (service->eap != NULL && strlen(service->eap) > 0)
			g_key_file_set_string(keyfile, service->identifier,
					"EAP", service->eap);
		else
			g_key_file_remove_key(keyfile, service->identifier,
					"EAP", NULL);

		if (service->phase2 != NULL && strlen(service->phase2) > 0)
			g_key_file_set_string(keyfile, service->identifier,
					"Phase2", service->phase2);
		else
			g_key_file_remove_key(keyfile, service->identifier,
					"Phase2", NULL);

		if (service->identity != NULL && strlen(service->identity) > 0)
			g_key_file_set_string(keyfile, service->identifier,
					"Identity", service->identity);
		else
			g_key_file_remove_key(keyfile, service->identifier,
					"Identity", NULL);

		if (service->ca_cert_file != NULL && strlen(service->ca_cert_file) > 0)
			g_key_file_set_string(keyfile, service->identifier,
					"CACertFile", service->ca_cert_file);
		else
			g_key_file_remove_key(keyfile, service->identifier,
					"CACertFile", NULL);

		if (service->client_cert_file != NULL && strlen(service->client_cert_file) > 0)
			g_key_file_set_string(keyfile, service->identifier,
					"ClientCertFile", service->client_cert_file);
		else
			g_key_file_remove_key(keyfile, service->identifier,
					"ClientCertFile", NULL);

		if (service->private_key_file != NULL && strlen(service->private_key_file) > 0)
			g_key_file_set_string(keyfile, service->identifier,
					"PrivateKeyFile", service->private_key_file);
		else
			g_key_file_remove_key(keyfile, service->identifier,
					"PrivateKeyFile", NULL);

		if (service->private_key_passphrase != NULL && strlen(service->private_key_passphrase) > 0)
			g_key_file_set_string(keyfile, service->identifier,
					"PrivateKeyPassphrase", service->private_key_passphrase);
		else
			g_key_file_remove_key(keyfile, service->identifier,
					"PrivateKeyPassphrase", NULL);
	}
	if (service->type == CONNMAN_SERVICE_TYPE_WIFI &&
			service->security == CONNMAN_SERVICE_SECURITY_DPP) {
		if (service->connector != NULL && strlen(service->connector) > 0)
			g_key_file_set_string(keyfile, service->identifier,
					"Connector", service->connector);
		else
			g_key_file_remove_key(keyfile, service->identifier,
					"Connector", NULL);

		if (service->c_sign_key != NULL && strlen(service->c_sign_key) > 0)
			g_key_file_set_string(keyfile, service->identifier,
					"CSignKey", service->c_sign_key);
		else
			g_key_file_remove_key(keyfile, service->identifier,
					"CSignKey", NULL);

		if (service->net_access_key != NULL && strlen(service->net_access_key) > 0)
			g_key_file_set_string(keyfile, service->identifier,
					"NetAccessKey", service->net_access_key);
		else
			g_key_file_remove_key(keyfile, service->identifier,
					"NetAccessKey", NULL);
	}
#endif

done:
	__connman_storage_save_service(keyfile, service->identifier);

	g_key_file_free(keyfile);

	return err;
}

#if defined TIZEN_EXT
static gint sort_entry(gconstpointer a, gconstpointer b, gpointer user_data)
{
	GTimeVal *aval = (GTimeVal *)a;
	GTimeVal *bval = (GTimeVal *)b;

	/* Note that the sort order is ascending */
	if (aval->tv_sec > bval->tv_sec)
		return 1;

	if (aval->tv_sec < bval->tv_sec)
		return -1;

	return 0;
}

static void free_entry(gpointer data)
{
	struct saved_profiles *entry = data;
	g_free(entry->profile_name);
	g_free(entry);
}

static void __connman_manage_saved_profiles()
{
	GKeyFile *keyfile;
	gchar **services = NULL;
	GTimeVal modified;
	int i, num_profiles = 0;
	GSequenceIter *iter;
	GSequence *profile_list;
	struct saved_profiles *entry;

	profile_list = g_sequence_new(free_entry);
	if (!profile_list)
		return;

	services = connman_storage_get_services();

	/* Check the count of saved profiles */
	for (i = 0; services && services[i]; i++) {
		if (strncmp(services[i], "wifi_", 5) != 0)
			continue;

		keyfile = connman_storage_load_service(services[i]);
		if (!keyfile)
			continue;

		gchar *str = g_key_file_get_string(keyfile,
				services[i], "Modified", NULL);
		if (!str) {
			g_key_file_free(keyfile);
			continue;
		}

		g_time_val_from_iso8601(str, &modified);
		g_free(str);

		entry = g_try_new(struct saved_profiles, 1);
		if (!entry) {
			g_sequence_free(profile_list);
			g_key_file_free(keyfile);
			return;
		}

		entry->modified = modified;
		entry->profile_name = g_strdup(services[i]);

		g_sequence_insert_sorted(profile_list, entry,
				sort_entry, NULL);

		num_profiles++;
	}
	DBG("number of profiles: %d", num_profiles);

	if (num_profiles > MAX_WIFI_PROFILES) {
		iter = g_sequence_get_begin_iter(profile_list);

		entry = g_sequence_get(iter);

		if (__connman_storage_remove_service(entry->profile_name) == false)
			DBG("Failed to remove service profile: %s", entry->profile_name);
	}

	g_sequence_free(profile_list);
}
#endif

void __connman_service_save(struct connman_service *service)
{
	if (!service)
		return;

	service_save(service);
#if defined TIZEN_EXT
	/*
	 * Description: Manage the wireless profiles saved in connman.
	 * If the number of saved profiles is more than 200, remove the
	 * profile that is not updated for longer duration.
	 */
	__connman_manage_saved_profiles();
#endif
}

static enum connman_service_state combine_state(
					enum connman_service_state state_a,
					enum connman_service_state state_b)
{
	enum connman_service_state result;

	if (state_a == state_b) {
		result = state_a;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_UNKNOWN) {
		result = state_b;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_UNKNOWN) {
		result = state_a;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_IDLE) {
		result = state_b;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_IDLE) {
		result = state_a;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_ONLINE) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_ONLINE) {
		result = state_b;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_READY) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_READY) {
		result = state_b;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_CONFIGURATION) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_CONFIGURATION) {
		result = state_b;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_ASSOCIATION) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_ASSOCIATION) {
		result = state_b;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_DISCONNECT) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_DISCONNECT) {
		result = state_b;
		goto done;
	}

	result = CONNMAN_SERVICE_STATE_FAILURE;

done:
	return result;
}

static bool is_connecting(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_FAILURE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		break;
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		return true;
	}

	return false;
}

static bool is_connected(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		break;
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		return true;
	}

	return false;
}

static bool is_idle(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		return true;
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		break;
	}

	return false;
}

static int nameservers_changed_cb(void *user_data)
{
	struct connman_service *service = user_data;

	DBG("service %p", service);

	service->nameservers_timeout = 0;
	if ((is_idle(service->state) && !service->nameservers) ||
			is_connected(service->state))
		dns_changed(service);

	return FALSE;
}

static void nameservers_changed(struct connman_service *service)
{
	if (!service->nameservers_timeout)
		service->nameservers_timeout = g_idle_add(nameservers_changed_cb,
							service);
}

static bool nameserver_available(struct connman_service *service,
				enum connman_ipconfig_type type,
				const char *ns)
{
	int family;

	family = connman_inet_check_ipaddress(ns);

	if (family == AF_INET) {
		if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
			return false;

		return is_connected(service->state_ipv4);
	}

	if (family == AF_INET6) {
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			return false;

		return is_connected(service->state_ipv6);
	}

	return false;
}

static int searchdomain_add_all(struct connman_service *service)
{
	int index, i = 0;

	if (!is_connected(service->state))
		return -ENOTCONN;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	if (service->domains) {
		while (service->domains[i]) {
			connman_resolver_append(index, service->domains[i],
						NULL);
			i++;
		}

		return 0;
	}

	if (service->domainname)
		connman_resolver_append(index, service->domainname, NULL);

	return 0;

}

static int searchdomain_remove_all(struct connman_service *service)
{
	int index, i = 0;

	if (!is_connected(service->state))
		return -ENOTCONN;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	while (service->domains && service->domains[i]) {
		connman_resolver_remove(index, service->domains[i], NULL);
		i++;
	}

	if (service->domainname)
		connman_resolver_remove(index, service->domainname, NULL);

	return 0;
}

static int nameserver_add(struct connman_service *service,
			enum connman_ipconfig_type type,
			const char *nameserver)
{
	int index, ret;

	if (!nameserver_available(service, type, nameserver))
		return 0;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

#if defined TIZEN_EXT
	DBG("Resolver append nameserver: %s", nameserver);
#endif
	ret = connman_resolver_append(index, NULL, nameserver);
	if (ret >= 0)
		nameservers_changed(service);

	return ret;
}

static int nameserver_add_all(struct connman_service *service,
			enum connman_ipconfig_type type)
{
	int i = 0;

	if (service->nameservers_config) {
		while (service->nameservers_config[i]) {
#if defined TIZEN_EXT
			DBG("type %d add service->nameservers_config[%d]:%s",type,
			    i, service->nameservers_config[i]);
			if(strncmp(service->nameservers_config[i], "::", 2) == 0) {
				DBG("Invalid nameserver");
				i++;
				continue;
			}

			switch(type) {
			case CONNMAN_IPCONFIG_TYPE_IPV4:
				if (connman_inet_check_ipaddress(
					service->nameservers_config[i]) == AF_INET &&
				    service->dns_config_method_ipv4 ==
				    CONNMAN_DNSCONFIG_METHOD_MANUAL) {
					nameserver_add(service, type,
						       service->nameservers_config[i]);
				}
				break;
			case CONNMAN_IPCONFIG_TYPE_IPV6:
				if (connman_inet_check_ipaddress(
					service->nameservers_config[i]) == AF_INET6 &&
				    service->dns_config_method_ipv6 ==
					CONNMAN_DNSCONFIG_METHOD_MANUAL) {
					nameserver_add(service, type,
						       service->nameservers_config[i]);
				}
				break;
			case CONNMAN_IPCONFIG_TYPE_ALL:
				if (connman_inet_check_ipaddress(
					service->nameservers_config[i]) == AF_INET &&
				    service->dns_config_method_ipv4 ==
					CONNMAN_DNSCONFIG_METHOD_MANUAL) {
					nameserver_add(service, type,
						       service->nameservers_config[i]);
				}
				if (connman_inet_check_ipaddress(
					service->nameservers_config[i]) == AF_INET6 &&
				    service->dns_config_method_ipv6 ==
					CONNMAN_DNSCONFIG_METHOD_MANUAL) {
					nameserver_add(service, type,
						       service->nameservers_config[i]);
				}
				break;
			case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
				DBG("CONNMAN_IPCONFIG_TYPE_UNKNOWN do nothing");
				break;
			default:
				DBG("default case do nothing");
				break;
			}
#else
			nameserver_add(service, type,
				service->nameservers_config[i]);
#endif
			i++;
		}
	} else if (service->nameservers) {
		while (service->nameservers[i]) {
#if defined TIZEN_EXT
			DBG("type %d service->nameservers[%d]: %s",type,
			    i, service->nameservers[i]);

			switch(type) {
			case CONNMAN_IPCONFIG_TYPE_IPV4:
				if (connman_inet_check_ipaddress(
					service->nameservers[i]) == AF_INET &&
					service->dns_config_method_ipv4 ==
						CONNMAN_DNSCONFIG_METHOD_DHCP) {
					nameserver_add(service, type,
						       service->nameservers[i]);
				}
				break;
			case CONNMAN_IPCONFIG_TYPE_IPV6:
				if (connman_inet_check_ipaddress(
					service->nameservers[i]) == AF_INET6 &&
					service->dns_config_method_ipv6 ==
						CONNMAN_DNSCONFIG_METHOD_DHCP) {
					nameserver_add(service, type,
						       service->nameservers[i]);
				}
				break;
			case CONNMAN_IPCONFIG_TYPE_ALL:
				if (connman_inet_check_ipaddress(
					service->nameservers[i]) == AF_INET &&
					service->dns_config_method_ipv4 ==
						CONNMAN_DNSCONFIG_METHOD_DHCP) {
					nameserver_add(service, type,
						       service->nameservers[i]);
				}
				if (connman_inet_check_ipaddress(
					service->nameservers[i]) == AF_INET6 &&
					service->dns_config_method_ipv6 ==
						CONNMAN_DNSCONFIG_METHOD_DHCP) {
					nameserver_add(service, type,
						       service->nameservers[i]);
				}
				break;
			case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
				DBG("CONNMAN_IPCONFIG_TYPE_UNKNOWN do nothing");
				break;
			default:
				DBG("default case do nothing");
				break;
			}
#else
			nameserver_add(service, type,
				service->nameservers[i]);
#endif
			i++;
		}
	}

	if (!i)
		__connman_resolver_append_fallback_nameservers();

#if defined TIZEN_EXT
	const char *global_dns = connman_option_get_string("GlobalNameserver");
	if (global_dns)
		nameserver_add(service, type, global_dns);
#endif

	searchdomain_add_all(service);

	return 0;
}

static int nameserver_remove(struct connman_service *service,
			enum connman_ipconfig_type type,
			const char *nameserver)
{
	int index, ret;

	if (!nameserver_available(service, type, nameserver))
		return 0;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

#if defined TIZEN_EXT
	DBG("Resolver remove nameserver: %s", nameserver);
#endif
	ret = connman_resolver_remove(index, NULL, nameserver);
	if (ret >= 0)
		nameservers_changed(service);

	return ret;
}

static int nameserver_remove_all(struct connman_service *service,
				enum connman_ipconfig_type type)
{
#if defined TIZEN_EXT
	/**
	  * Skip this function if there is any connected profiles
	  * that use same interface
	  */
	if (service->type == CONNMAN_SERVICE_TYPE_CELLULAR &&
			__connman_service_get_connected_count_of_iface(service) > 0)
		return 0;
#endif
	int index, i = 0;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	while (service->nameservers_config && service->nameservers_config[i]) {

#if defined TIZEN_EXT
		DBG("type %d Remove service->nameservers_config[%d]: %s",
		      type, i, service->nameservers_config[i]);
		switch(type) {
		case CONNMAN_IPCONFIG_TYPE_IPV4:
			if (connman_inet_check_ipaddress(
				service->nameservers_config[i]) == AF_INET &&
				(service->dns_config_method_ipv4 ==
					CONNMAN_DNSCONFIG_METHOD_DHCP ||
				service->dns_config_method_ipv4 ==
					CONNMAN_DNSCONFIG_METHOD_MANUAL)) {
				nameserver_remove(service, type,
						  service->nameservers_config[i]);
			}
			break;
		case CONNMAN_IPCONFIG_TYPE_IPV6:
			if (connman_inet_check_ipaddress(
				service->nameservers_config[i]) == AF_INET6 &&
				(service->dns_config_method_ipv6 ==
					CONNMAN_DNSCONFIG_METHOD_DHCP ||
				service->dns_config_method_ipv6 ==
					CONNMAN_DNSCONFIG_METHOD_MANUAL)) {
				nameserver_remove(service, type,
						  service->nameservers_config[i]);
			}
			break;
		case CONNMAN_IPCONFIG_TYPE_ALL:
			if (connman_inet_check_ipaddress(
				service->nameservers_config[i]) == AF_INET &&
				(service->dns_config_method_ipv4 ==
					CONNMAN_DNSCONFIG_METHOD_DHCP ||
				service->dns_config_method_ipv4 ==
					CONNMAN_DNSCONFIG_METHOD_MANUAL)) {
				nameserver_remove(service, type,
						  service->nameservers_config[i]);
			}
			if (connman_inet_check_ipaddress(
				service->nameservers_config[i]) == AF_INET6 &&
				(service->dns_config_method_ipv6 ==
					CONNMAN_DNSCONFIG_METHOD_DHCP ||
				service->dns_config_method_ipv6 ==
					CONNMAN_DNSCONFIG_METHOD_MANUAL)) {
				nameserver_remove(service, type,
						  service->nameservers_config[i]);
			}
			break;
		case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
			DBG("CONNMAN_IPCONFIG_TYPE_UNKNOWN do nothing");
			break;
		default:
			DBG("default case do nothing");
			break;
		}
#else
		nameserver_remove(service, type,
				service->nameservers_config[i]);
#endif
		i++;
	}

	i = 0;
	while (service->nameservers && service->nameservers[i]) {
#if defined TIZEN_EXT
		DBG("type %d Remove service->nameservers[%d]: %s",type, i,
		      service->nameservers[i]);
		switch(type) {
			case CONNMAN_IPCONFIG_TYPE_IPV4:
				if (connman_inet_check_ipaddress(
					service->nameservers[i]) == AF_INET &&
					(service->dns_config_method_ipv4 ==
						CONNMAN_DNSCONFIG_METHOD_MANUAL ||
					service->dns_config_method_ipv4 ==
						CONNMAN_DNSCONFIG_METHOD_DHCP)) {
					nameserver_remove(service, type,
							  service->nameservers[i]);
				}
				break;
			case CONNMAN_IPCONFIG_TYPE_IPV6:
				if (connman_inet_check_ipaddress(
					service->nameservers[i]) == AF_INET6 &&
					(service->dns_config_method_ipv6 ==
						CONNMAN_DNSCONFIG_METHOD_MANUAL ||
					service->dns_config_method_ipv6 ==
						CONNMAN_DNSCONFIG_METHOD_DHCP)) {
					nameserver_remove(service, type,
							  service->nameservers[i]);
				}
				break;
			case CONNMAN_IPCONFIG_TYPE_ALL:
				if (connman_inet_check_ipaddress(
					service->nameservers[i]) == AF_INET &&
					(service->dns_config_method_ipv4 ==
						CONNMAN_DNSCONFIG_METHOD_MANUAL ||
					service->dns_config_method_ipv4 ==
						CONNMAN_DNSCONFIG_METHOD_DHCP)) {
					nameserver_remove(service, type,
							  service->nameservers[i]);
				}
				if (connman_inet_check_ipaddress(
					service->nameservers[i]) == AF_INET6 &&
					(service->dns_config_method_ipv6 ==
						CONNMAN_DNSCONFIG_METHOD_MANUAL ||
					service->dns_config_method_ipv6 ==
						CONNMAN_DNSCONFIG_METHOD_DHCP)) {
					nameserver_remove(service, type,
							  service->nameservers[i]);
				}
				break;
			case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
				DBG("CONNMAN_IPCONFIG_TYPE_UNKNOWN do nothing");
				break;
			default:
				DBG("default case do nothing");
				break;
		}
#else
		nameserver_remove(service, type, service->nameservers[i]);
#endif
		i++;
	}

#if defined TIZEN_EXT
	const char *global_dns = connman_option_get_string("GlobalNameserver");
	if (global_dns)
		nameserver_remove(service, type, global_dns);
#endif
	searchdomain_remove_all(service);

	return 0;
}

/*
 * The is_auto variable is set to true when IPv6 autoconf nameservers are
 * inserted to resolver via netlink message (see rtnl.c:rtnl_newnduseropt()
 * for details) and not through service.c
 */
#if defined TIZEN_EXT
int __connman_service_nameserver_append(struct connman_service *service,
				const char *nameserver, bool is_auto,
				enum connman_ipconfig_type type)
#else
int __connman_service_nameserver_append(struct connman_service *service,
				const char *nameserver, bool is_auto)
#endif
{
	char **nameservers;
	int len, i;

	DBG("service %p nameserver %s auto %d",	service, nameserver, is_auto);

	if (!nameserver)
		return -EINVAL;

	if (is_auto)
		nameservers = service->nameservers_auto;
	else
		nameservers = service->nameservers;

	for (i = 0; nameservers && nameservers[i]; i++)
#if defined TIZEN_EXT
	{
		DBG("nameservers[%d] %s, nameserver %s", i, nameservers[i], nameserver);
#endif
		if (g_strcmp0(nameservers[i], nameserver) == 0)
			return -EEXIST;
#if defined TIZEN_EXT
	}
#endif

	if (nameservers) {
		len = g_strv_length(nameservers);
		nameservers = g_try_renew(char *, nameservers, len + 2);
	} else {
		len = 0;
		nameservers = g_try_new0(char *, len + 2);
	}

	if (!nameservers)
		return -ENOMEM;

	nameservers[len] = g_strdup(nameserver);
	nameservers[len + 1] = NULL;

#ifdef TIZEN_EXT
	if(type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
	   service->dns_config_method_ipv4 == CONNMAN_DNSCONFIG_METHOD_UNKNOWN)
		service->dns_config_method_ipv4 = CONNMAN_DNSCONFIG_METHOD_DHCP;

	if(type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
	   service->dns_config_method_ipv6 == CONNMAN_DNSCONFIG_METHOD_UNKNOWN)
		service->dns_config_method_ipv6 = CONNMAN_DNSCONFIG_METHOD_DHCP;
#endif

	if (is_auto) {
		service->nameservers_auto = nameservers;
	} else {
		service->nameservers = nameservers;
		nameserver_add(service, CONNMAN_IPCONFIG_TYPE_ALL, nameserver);
	}

	nameservers_changed(service);

	searchdomain_add_all(service);

	return 0;
}

#if defined TIZEN_EXT
int __connman_service_nameserver_remove(struct connman_service *service,
				const char *nameserver, bool is_auto,
				enum connman_ipconfig_type type)
#else
int __connman_service_nameserver_remove(struct connman_service *service,
				const char *nameserver, bool is_auto)
#endif
{
	char **servers, **nameservers;
	bool found = false;
	int len, i, j;

	DBG("service %p nameserver %s auto %d", service, nameserver, is_auto);

	if (!nameserver)
		return -EINVAL;

	if (is_auto)
		nameservers = service->nameservers_auto;
	else
		nameservers = service->nameservers;

	if (!nameservers)
		return 0;

	for (i = 0; nameservers[i]; i++)
		if (g_strcmp0(nameservers[i], nameserver) == 0) {
			found = true;
			break;
		}

	if (!found)
		return 0;

	len = g_strv_length(nameservers);

	if (len == 1) {
		servers = NULL;
		goto set_servers;
	}

	servers = g_try_new0(char *, len);
	if (!servers)
		return -ENOMEM;

	for (i = 0, j = 0; i < len; i++) {
		if (g_strcmp0(nameservers[i], nameserver)) {
			servers[j] = nameservers[i];
			j++;
		} else
			g_free(nameservers[i]);

		nameservers[i] = NULL;
	}
	servers[len - 1] = NULL;

set_servers:
	g_strfreev(nameservers);
	nameservers = servers;

	if (is_auto) {
		service->nameservers_auto = nameservers;
	} else {
		service->nameservers = nameservers;
#if defined TIZEN_EXT
		DBG("nameserver remove ip_type: %d", type);
		nameserver_remove(service, type,
				nameserver);
#else
		nameserver_remove(service, CONNMAN_IPCONFIG_TYPE_ALL,
				nameserver);
#endif
	}

	return 0;
}

void __connman_service_nameserver_clear(struct connman_service *service)
{
	nameserver_remove_all(service, CONNMAN_IPCONFIG_TYPE_ALL);

	g_strfreev(service->nameservers);
	service->nameservers = NULL;

	nameserver_add_all(service, CONNMAN_IPCONFIG_TYPE_ALL);
}

static void add_nameserver_route(int family, int index, char *nameserver,
				const char *gw)
{
	switch (family) {
	case AF_INET:
		if (connman_inet_compare_subnet(index, nameserver))
			break;

		if (connman_inet_add_host_route(index, nameserver, gw) < 0)
			/* For P-t-P link the above route add will fail */
			connman_inet_add_host_route(index, nameserver, NULL);
		break;

	case AF_INET6:
		if (connman_inet_add_ipv6_host_route(index, nameserver,
								gw) < 0)
			connman_inet_add_ipv6_host_route(index, nameserver,
							NULL);
		break;
	}
}

static void nameserver_add_routes(int index, char **nameservers,
					const char *gw)
{
	int i, ns_family, gw_family;

	gw_family = connman_inet_check_ipaddress(gw);
	if (gw_family < 0)
		return;

	for (i = 0; nameservers[i]; i++) {
		ns_family = connman_inet_check_ipaddress(nameservers[i]);
		if (ns_family < 0 || ns_family != gw_family)
			continue;

		add_nameserver_route(ns_family, index, nameservers[i], gw);
	}
}

static void nameserver_del_routes(int index, char **nameservers,
				enum connman_ipconfig_type type)
{
	int i, family;

	for (i = 0; nameservers[i]; i++) {
		family = connman_inet_check_ipaddress(nameservers[i]);
		if (family < 0)
			continue;

		switch (family) {
		case AF_INET:
			if (type != CONNMAN_IPCONFIG_TYPE_IPV6)
				connman_inet_del_host_route(index,
							nameservers[i]);
			break;
		case AF_INET6:
			if (type != CONNMAN_IPCONFIG_TYPE_IPV4)
				connman_inet_del_ipv6_host_route(index,
							nameservers[i]);
			break;
		}
	}
}

void __connman_service_nameserver_add_routes(struct connman_service *service,
						const char *gw)
{
	int index;

	if (!service)
		return;

	index = __connman_service_get_index(service);

	if (service->nameservers_config) {
		/*
		 * Configured nameserver takes preference over the
		 * discoverd nameserver gathered from DHCP, VPN, etc.
		 */
		nameserver_add_routes(index, service->nameservers_config, gw);
	} else if (service->nameservers) {
		/*
		 * We add nameservers host routes for nameservers that
		 * are not on our subnet. For those who are, the subnet
		 * route will be installed by the time the dns proxy code
		 * tries to reach them. The subnet route is installed
		 * when setting the interface IP address.
		 */
		nameserver_add_routes(index, service->nameservers, gw);
	}
}

void __connman_service_nameserver_del_routes(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	int index;

	if (!service)
		return;

	index = __connman_service_get_index(service);

	if (service->nameservers_config)
		nameserver_del_routes(index, service->nameservers_config,
					type);
	else if (service->nameservers)
		nameserver_del_routes(index, service->nameservers, type);
}

static void address_updated(struct connman_service *service,
			enum connman_ipconfig_type type)
{
	if (is_connected(service->state) &&
			service == connman_service_get_default()) {
		nameserver_remove_all(service, type);
		nameserver_add_all(service, type);

		__connman_timeserver_sync(service);
	}
}

static struct connman_stats *stats_get(struct connman_service *service)
{
	if (service->roaming)
		return &service->stats_roaming;
	else
		return &service->stats;
}

static bool stats_enabled(struct connman_service *service)
{
	struct connman_stats *stats = stats_get(service);

	return stats->enabled;
}

static void stats_start(struct connman_service *service)
{
	struct connman_stats *stats = stats_get(service);

	DBG("service %p", service);

	if (!stats->timer)
		return;

	stats->enabled = true;
	stats->data_last.time = stats->data.time;

	g_timer_start(stats->timer);
}

static void stats_stop(struct connman_service *service)
{
	struct connman_stats *stats = stats_get(service);
	unsigned int seconds;

	DBG("service %p", service);

	if (!stats->timer)
		return;

	if (!stats->enabled)
		return;

	g_timer_stop(stats->timer);

	seconds = g_timer_elapsed(stats->timer, NULL);
	stats->data.time = stats->data_last.time + seconds;

	stats->enabled = false;
}

static void reset_stats(struct connman_service *service)
{
	DBG("service %p", service);

	/* home */
	service->stats.valid = false;

	service->stats.data.rx_packets = 0;
	service->stats.data.tx_packets = 0;
	service->stats.data.rx_bytes = 0;
	service->stats.data.tx_bytes = 0;
	service->stats.data.rx_errors = 0;
	service->stats.data.tx_errors = 0;
	service->stats.data.rx_dropped = 0;
	service->stats.data.tx_dropped = 0;
	service->stats.data.time = 0;
	service->stats.data_last.time = 0;

	g_timer_reset(service->stats.timer);

	/* roaming */
	service->stats_roaming.valid = false;

	service->stats_roaming.data.rx_packets = 0;
	service->stats_roaming.data.tx_packets = 0;
	service->stats_roaming.data.rx_bytes = 0;
	service->stats_roaming.data.tx_bytes = 0;
	service->stats_roaming.data.rx_errors = 0;
	service->stats_roaming.data.tx_errors = 0;
	service->stats_roaming.data.rx_dropped = 0;
	service->stats_roaming.data.tx_dropped = 0;
	service->stats_roaming.data.time = 0;
	service->stats_roaming.data_last.time = 0;

	g_timer_reset(service->stats_roaming.timer);
}

#if defined TIZEN_EXT
static gboolean __connman_service_is_internet_profile(
		struct connman_service *cellular)
{
	const char internet_suffix[] = "_1";

	DBG("Service path: %s", cellular->path);

	if (g_str_has_suffix(cellular->path, internet_suffix) == TRUE)
		return TRUE;

	return FALSE;
}

struct connman_service *connman_service_get_default_connection(void)
{
	GList *list;
	struct connman_service *service;
	struct connman_service *default_service = NULL;

	for (list = service_list; list; list = list->next) {
		service = list->data;

		DBG("service: %p %s %s %s", service, service->name,
				state2string(service->state),
				__connman_service_type2string(service->type));

#if defined TIZEN_MAINTAIN_ONLINE
		if (service->type == CONNMAN_SERVICE_TYPE_WIFI &&
				service->state == CONNMAN_SERVICE_STATE_ONLINE) {
#else
		if (service->type == CONNMAN_SERVICE_TYPE_WIFI &&
				is_connected(service->state) == TRUE) {
#endif
			return service;
		} else if (service->type == CONNMAN_SERVICE_TYPE_CELLULAR &&
				__connman_service_is_internet_profile(service) == TRUE) {
			if (default_service == NULL)
				default_service = service;
			else if (is_connected(service->state) == TRUE &&
					is_connected(default_service->state) == FALSE)
				default_service = service;
		} else if (service->type == CONNMAN_SERVICE_TYPE_ETHERNET &&
				is_connected(service->state) == TRUE) {
			if (default_service == NULL)
				default_service = service;
		} else if (service->type == CONNMAN_SERVICE_TYPE_BLUETOOTH &&
				is_connected(service->state) == TRUE) {
			if (default_service == NULL)
				default_service = service;
		}
	}

	return default_service;
}
#endif

struct connman_service *connman_service_get_default(void)
{
#if defined TIZEN_MAINTAIN_ONLINE
	return connman_service_get_default_connection();
#else
	struct connman_service *service;

	if (!service_list)
		return NULL;

	service = service_list->data;

	if (!is_connected(service->state))
		return NULL;

	return service;
#endif
}

bool __connman_service_index_is_default(int index)
{
	struct connman_service *service;

	if (index < 0)
		return false;

	service = connman_service_get_default();

	return __connman_service_get_index(service) == index;
}

static void default_changed(void)
{
	struct connman_service *service = connman_service_get_default();

	if (service == current_default)
		return;

	DBG("current default %p %s", current_default,
		current_default ? current_default->identifier : "");
	DBG("new default %p %s", service, service ? service->identifier : "");

#if defined TIZEN_EXT
	current_default = service;

	__connman_service_timeserver_changed(service, NULL);
#else
	__connman_service_timeserver_changed(current_default, NULL);

	current_default = service;
#endif

	if (service) {
		if (service->hostname &&
				connman_setting_get_bool("AllowHostnameUpdates"))
			__connman_utsname_set_hostname(service->hostname);

		if (service->domainname &&
				connman_setting_get_bool("AllowDomainnameUpdates"))
			__connman_utsname_set_domainname(service->domainname);
	}

	__connman_notifier_default_changed(service);
}

static void state_changed(struct connman_service *service)
{
	const char *str;

	__connman_notifier_service_state_changed(service, service->state);

	str = state2string(service->state);
	if (!str)
		return;

#if !defined TIZEN_EXT
	if (!allow_property_changed(service))
		return;

#endif
#if defined TIZEN_EXT
	DBG(" %s, %s", str, service->path);
#endif
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "State",
						DBUS_TYPE_STRING, &str);
}

#if defined TIZEN_EXT
static void connect_reason_changed(struct connman_service *service)
{
	struct connman_device *device;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	if (service->connect_reason == CONNMAN_SERVICE_CONNECT_REASON_USER) {
		device = connman_network_get_device(service->network);
		if (device) {
			bool need_save = false;

			need_save |= connman_device_set_last_user_selection_ident(device, service->identifier);
			need_save |= connman_device_set_last_user_selection_time(device, time(NULL));

			DBG("last user selection ident[%s] time[%ld]",
				connman_device_get_last_user_selection_ident(device),
				connman_device_get_last_user_selection_time(device));

			if (need_save)
				connman_device_save_last_user_selection(device);
		}
	}

	connman_dbus_property_changed_basic(service->path,
					    CONNMAN_SERVICE_INTERFACE,
					    "ConnectReason",
					    DBUS_TYPE_INT32,
					    &service->connect_reason);
}

static void disconnection_requested_changed(struct connman_service *service)
{
	dbus_bool_t disconnection_requested;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	disconnection_requested = service->disconnection_requested;
	connman_dbus_property_changed_basic(service->path,
					    CONNMAN_SERVICE_INTERFACE,
					    "DisconnectionRequested",
					    DBUS_TYPE_BOOLEAN,
					    &disconnection_requested);
}

void connman_service_set_disconnection_requested(struct connman_service *service,
						 bool disconnection_requested)
{
	if (service == NULL)
		return;

	service->disconnection_requested = disconnection_requested;
	disconnection_requested_changed(service);
}
#endif

static void strength_changed(struct connman_service *service)
{
	if (service->strength == 0)
		return;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Strength",
					DBUS_TYPE_BYTE, &service->strength);
}

#if defined TIZEN_EXT
static bool update_last_connected_bssid(struct connman_service *service)
{
	const unsigned char *last_connected_bssid;

	if (!service->network)
		return false;

	last_connected_bssid = connman_network_get_last_connected_bssid(service->network);
	if (memcmp(last_connected_bssid, invalid_bssid, WIFI_BSSID_LEN_MAX) == 0)
		return false;

	if (memcmp(last_connected_bssid, service->last_connected_bssid, WIFI_BSSID_LEN_MAX) != 0) {
		memcpy(service->last_connected_bssid, last_connected_bssid, WIFI_BSSID_LEN_MAX);
		return true;
	}

	return false;
}
#endif

static void favorite_changed(struct connman_service *service)
{
	dbus_bool_t favorite;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	favorite = service->favorite;
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Favorite",
					DBUS_TYPE_BOOLEAN, &favorite);
}

static void immutable_changed(struct connman_service *service)
{
	dbus_bool_t immutable;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	immutable = service->immutable;
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Immutable",
					DBUS_TYPE_BOOLEAN, &immutable);
}

static void roaming_changed(struct connman_service *service)
{
	dbus_bool_t roaming;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	roaming = service->roaming;
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Roaming",
					DBUS_TYPE_BOOLEAN, &roaming);
}

static void autoconnect_changed(struct connman_service *service)
{
	dbus_bool_t autoconnect;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	autoconnect = service->autoconnect;
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "AutoConnect",
				DBUS_TYPE_BOOLEAN, &autoconnect);
}

static void append_security(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	const char *str;

	str = security2string(service->security);
	if (str)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);

	/*
	 * Some access points incorrectly advertise WPS even when they
	 * are configured as open or no security, so filter
	 * appropriately.
	 */
	if (service->wps) {
		switch (service->security) {
		case CONNMAN_SERVICE_SECURITY_PSK:
		case CONNMAN_SERVICE_SECURITY_WPA:
		case CONNMAN_SERVICE_SECURITY_RSN:
#if defined TIZEN_EXT
		case CONNMAN_SERVICE_SECURITY_SAE:
#endif
			str = "wps";
			dbus_message_iter_append_basic(iter,
						DBUS_TYPE_STRING, &str);
			break;
#if defined TIZEN_EXT
		case CONNMAN_SERVICE_SECURITY_OWE:
#endif
		case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		case CONNMAN_SERVICE_SECURITY_NONE:
		case CONNMAN_SERVICE_SECURITY_WEP:
		case CONNMAN_SERVICE_SECURITY_8021X:
			break;
		}

		if (service->wps_advertizing) {
			str = "wps_advertising";
			dbus_message_iter_append_basic(iter,
						DBUS_TYPE_STRING, &str);
		}
	}
}

static void security_changed(struct connman_service *service)
{
	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE, "Security",
				DBUS_TYPE_STRING, append_security, service);
}

static void append_ethernet(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (service->ipconfig_ipv4)
		__connman_ipconfig_append_ethernet(service->ipconfig_ipv4,
									iter);
	else if (service->ipconfig_ipv6)
		__connman_ipconfig_append_ethernet(service->ipconfig_ipv6,
									iter);
}

static void append_ipv4(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state_ipv4))
		return;

	if (service->ipconfig_ipv4)
		__connman_ipconfig_append_ipv4(service->ipconfig_ipv4, iter);
}

static void append_ipv6(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state_ipv6))
		return;

	if (service->ipconfig_ipv6)
		__connman_ipconfig_append_ipv6(service->ipconfig_ipv6, iter,
						service->ipconfig_ipv4);
}

static void append_ipv4config(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (service->ipconfig_ipv4)
		__connman_ipconfig_append_ipv4config(service->ipconfig_ipv4,
							iter);
}

static void append_ipv6config(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (service->ipconfig_ipv6)
		__connman_ipconfig_append_ipv6config(service->ipconfig_ipv6,
							iter);
}

static void append_nameservers(DBusMessageIter *iter,
		struct connman_service *service, char **servers)
{
	int i;
	bool available = true;

	for (i = 0; servers[i]; i++) {
		if (service)
			available = nameserver_available(service,
						CONNMAN_IPCONFIG_TYPE_ALL,
						servers[i]);

		if (available)
			dbus_message_iter_append_basic(iter,
					DBUS_TYPE_STRING, &servers[i]);
	}
}

#if defined TIZEN_EXT
static void append_nameserver_manual(DBusMessageIter *iter,
		struct connman_service *service, const char *server)
{
	bool available = true;

	if (service)
		available = nameserver_available(service,
				CONNMAN_IPCONFIG_TYPE_ALL, server);

	if (available)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &server);
}

static void append_nameserver_dhcp(DBusMessageIter *iter,
		struct connman_service *service, const char *server)
{
	bool available = true;

	if (service)
		available = nameserver_available(service,
				CONNMAN_IPCONFIG_TYPE_ALL, server);

	if (available)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &server);
}
#endif

static void append_dns(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
#if defined TIZEN_EXT
	int i;
#endif

	if (!is_connected(service->state))
		return;

#ifdef TIZEN_EXT
	const char *str;

	str = __connman_dnsconfig_method2string(service->dns_config_method_ipv4);
	if(str != NULL) {
		char *str1 = g_strdup_printf("ipv4.%s", str);
		dbus_message_iter_append_basic(iter,
			DBUS_TYPE_STRING, &str1);
		g_free(str1);
	}

	str = __connman_dnsconfig_method2string(service->dns_config_method_ipv6);
	if(str != NULL) {
		char *str1 = g_strdup_printf("ipv6.%s", str);
		dbus_message_iter_append_basic(iter,
			DBUS_TYPE_STRING, &str1);
		g_free(str1);
	}
#endif

	if (service->nameservers_config) {
#if defined TIZEN_EXT
		i = 0;
		while (service->nameservers_config[i]) {
			if (connman_inet_check_ipaddress(
				service->nameservers_config[i]) == AF_INET &&
				service->dns_config_method_ipv4 ==
					CONNMAN_DNSCONFIG_METHOD_MANUAL) {
				append_nameserver_manual(iter, service,
						service->nameservers_config[i]);
			}

			if (connman_inet_check_ipaddress(
				service->nameservers_config[i]) == AF_INET6 &&
				service->dns_config_method_ipv6 ==
					CONNMAN_DNSCONFIG_METHOD_MANUAL) {
				append_nameserver_manual(iter, service,
						service->nameservers_config[i]);
			}
			i++;
		}
		/* In case of mixed DNS Config Type one of IPv4/IPv6 can be
		 * dynamic while other is static so try to append the DNS
		 * Address which is dynamic also */
		if (service->nameservers != NULL) {
			i = 0;
			while (service->nameservers[i]) {
				if (connman_inet_check_ipaddress(
					service->nameservers[i]) == AF_INET &&
					service->dns_config_method_ipv4 ==
						CONNMAN_DNSCONFIG_METHOD_DHCP) {
					append_nameserver_dhcp(iter, service,
							service->nameservers[i]);
				}

				if (connman_inet_check_ipaddress(
					service->nameservers[i]) == AF_INET6 &&
					service->dns_config_method_ipv6 ==
						CONNMAN_DNSCONFIG_METHOD_DHCP) {
					append_nameserver_dhcp(iter, service,
							service->nameservers[i]);
				}
				i++;
			}
		}
#else
		append_nameservers(iter, service, service->nameservers_config);
#endif
		return;
	} else {
		if (service->nameservers)
#if defined TIZEN_EXT
		{
			i = 0;
			while (service->nameservers[i]) {
				if (connman_inet_check_ipaddress(
					service->nameservers[i]) == AF_INET &&
					service->dns_config_method_ipv4 ==
						CONNMAN_DNSCONFIG_METHOD_DHCP) {
					append_nameserver_dhcp(iter, service,
							service->nameservers[i]);
				}

				if (connman_inet_check_ipaddress(
					service->nameservers[i]) == AF_INET6 &&
					service->dns_config_method_ipv6 ==
						CONNMAN_DNSCONFIG_METHOD_DHCP) {
					append_nameserver_dhcp(iter, service,
							service->nameservers[i]);
				}
				i++;
			}
		}
#else
			append_nameservers(iter, service,
					service->nameservers);
#endif

		if (service->nameservers_auto)
			append_nameservers(iter, service,
					service->nameservers_auto);

		if (!service->nameservers && !service->nameservers_auto) {
			char **ns;

			DBG("append fallback nameservers");

			ns = connman_setting_get_string_list("FallbackNameservers");
			if (ns)
				append_nameservers(iter, service, ns);
		}
	}
}

static void append_dnsconfig(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

#ifdef TIZEN_EXT
	/* Append DNS Config Type */
	const char *str;
	str = __connman_dnsconfig_method2string(service->dns_config_method_ipv4);
	if(str != NULL) {
		char *str1 = g_strdup_printf("ipv4.%s", str);
		dbus_message_iter_append_basic(iter,
			DBUS_TYPE_STRING, &str1);
		g_free(str1);
	}

	str = __connman_dnsconfig_method2string(service->dns_config_method_ipv6);
	if(str != NULL) {
		char *str1 = g_strdup_printf("ipv6.%s", str);
		dbus_message_iter_append_basic(iter,
			DBUS_TYPE_STRING, &str1);
		g_free(str1);
	}
#endif

	if (!service->nameservers_config)
		return;

#if defined TIZEN_EXT
	int i = 0;
	while (service->nameservers_config[i]) {
		if (connman_inet_check_ipaddress(service->nameservers_config[i]) == AF_INET &&
				service->dns_config_method_ipv4 == CONNMAN_DNSCONFIG_METHOD_MANUAL) {
			append_nameserver_manual(iter, NULL, service->nameservers_config[i]);
		}

		if (connman_inet_check_ipaddress(service->nameservers_config[i]) == AF_INET6 &&
				service->dns_config_method_ipv6 == CONNMAN_DNSCONFIG_METHOD_MANUAL) {
			append_nameserver_manual(iter, NULL, service->nameservers_config[i]);
		}
		i++;
	}
#else
	append_nameservers(iter, NULL, service->nameservers_config);
#endif
}

static void append_ts(DBusMessageIter *iter, void *user_data)
{
	GSList *list = user_data;

	while (list) {
		char *timeserver = list->data;

		if (timeserver)
			dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
					&timeserver);

		list = g_slist_next(list);
	}
}

static void append_tsconfig(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	int i;

	if (!service->timeservers_config)
		return;

	for (i = 0; service->timeservers_config[i]; i++) {
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING,
				&service->timeservers_config[i]);
	}
}

static void append_domainconfig(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	int i;

	if (!service->domains)
		return;

	for (i = 0; service->domains[i]; i++)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &service->domains[i]);
}

static void append_domain(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state) &&
				!is_connecting(service->state))
		return;

	if (service->domains)
		append_domainconfig(iter, user_data);
	else if (service->domainname)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &service->domainname);
}

static void append_proxies(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	int i;

	if (!service->proxies)
		return;

	for (i = 0; service->proxies[i]; i++)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &service->proxies[i]);
}

static void append_excludes(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	int i;

	if (!service->excludes)
		return;

	for (i = 0; service->excludes[i]; i++)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &service->excludes[i]);
}

static void append_proxy(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	enum connman_service_proxy_method proxy;
	const char *pac = NULL;
	const char *method = proxymethod2string(
		CONNMAN_SERVICE_PROXY_METHOD_DIRECT);

	if (!is_connected(service->state))
		return;

	proxy = connman_service_get_proxy_method(service);

	switch (proxy) {
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		return;
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		goto done;
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		connman_dbus_dict_append_array(iter, "Servers",
					DBUS_TYPE_STRING, append_proxies,
					service);

		connman_dbus_dict_append_array(iter, "Excludes",
					DBUS_TYPE_STRING, append_excludes,
					service);
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		/* Maybe DHCP, or WPAD,  has provided an url for a pac file */
		if (service->ipconfig_ipv4)
			pac = __connman_ipconfig_get_proxy_autoconfig(
				service->ipconfig_ipv4);
		else if (service->ipconfig_ipv6)
			pac = __connman_ipconfig_get_proxy_autoconfig(
				service->ipconfig_ipv6);

		if (!service->pac && !pac)
			goto done;

		if (service->pac)
			pac = service->pac;

		connman_dbus_dict_append_basic(iter, "URL",
					DBUS_TYPE_STRING, &pac);
		break;
	}

	method = proxymethod2string(proxy);

done:
	connman_dbus_dict_append_basic(iter, "Method",
					DBUS_TYPE_STRING, &method);
}

static void append_proxyconfig(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	const char *method;

	if (service->proxy_config == CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN)
		return;

	switch (service->proxy_config) {
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		return;
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		if (service->proxies)
			connman_dbus_dict_append_array(iter, "Servers",
						DBUS_TYPE_STRING,
						append_proxies, service);

		if (service->excludes)
			connman_dbus_dict_append_array(iter, "Excludes",
						DBUS_TYPE_STRING,
						append_excludes, service);
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		if (service->pac)
			connman_dbus_dict_append_basic(iter, "URL",
					DBUS_TYPE_STRING, &service->pac);
		break;
	}

	method = proxymethod2string(service->proxy_config);

	connman_dbus_dict_append_basic(iter, "Method",
				DBUS_TYPE_STRING, &method);
}

static void append_provider(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state))
		return;

	if (service->provider)
		__connman_provider_append_properties(service->provider, iter);
}


static void settings_changed(struct connman_service *service,
				struct connman_ipconfig *ipconfig)
{
	enum connman_ipconfig_type type;

	type = __connman_ipconfig_get_config_type(ipconfig);

	__connman_notifier_ipconfig_changed(service, ipconfig);

	if (!allow_property_changed(service))
		return;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE, "IPv4",
					append_ipv4, service);
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE, "IPv6",
					append_ipv6, service);
}

static void ipv4_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE,
							"IPv4.Configuration",
							append_ipv4config,
							service);
}

void __connman_service_notify_ipv4_configuration(
					struct connman_service *service)
{
	if (!service)
		return;

	ipv4_configuration_changed(service);
}

static void ipv6_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE,
							"IPv6.Configuration",
							append_ipv6config,
							service);
}

static void dns_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE, "Nameservers",
					DBUS_TYPE_STRING, append_dns, service);
}

static void dns_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE,
				"Nameservers.Configuration",
				DBUS_TYPE_STRING, append_dnsconfig, service);

	dns_changed(service);
}

static void domain_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE, "Domains",
				DBUS_TYPE_STRING, append_domain, service);
}

static void domain_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE,
				"Domains.Configuration",
				DBUS_TYPE_STRING, append_domainconfig, service);
}

static void proxy_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE, "Proxy",
							append_proxy, service);
}

static void proxy_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
			CONNMAN_SERVICE_INTERFACE, "Proxy.Configuration",
						append_proxyconfig, service);

	proxy_changed(service);
}

static void mdns_changed(struct connman_service *service)
{
	dbus_bool_t mdns = service->mdns;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_basic(service->path,
			CONNMAN_SERVICE_INTERFACE, "mDNS", DBUS_TYPE_BOOLEAN,
			&mdns);
}

static void mdns_configuration_changed(struct connman_service *service)
{
	dbus_bool_t mdns_config = service->mdns_config;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_basic(service->path,
			CONNMAN_SERVICE_INTERFACE, "mDNS.Configuration",
			DBUS_TYPE_BOOLEAN, &mdns_config);
}

static int set_mdns(struct connman_service *service,
			bool enabled)
{
	int result;

	result = __connman_resolver_set_mdns(
			__connman_service_get_index(service), enabled);

	if (result == 0) {
		if (service->mdns != enabled) {
			service->mdns = enabled;
			mdns_changed(service);
		}
	}

	return result;
}

static void timeservers_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
			CONNMAN_SERVICE_INTERFACE,
			"Timeservers.Configuration",
			DBUS_TYPE_STRING,
			append_tsconfig, service);
}

static void link_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE, "Ethernet",
						append_ethernet, service);
}

static void stats_append_counters(DBusMessageIter *dict,
			struct connman_stats_data *stats,
			struct connman_stats_data *counters,
			bool append_all)
{
	if (counters->rx_packets != stats->rx_packets || append_all) {
		counters->rx_packets = stats->rx_packets;
		connman_dbus_dict_append_basic(dict, "RX.Packets",
					DBUS_TYPE_UINT32, &stats->rx_packets);
	}

	if (counters->tx_packets != stats->tx_packets || append_all) {
		counters->tx_packets = stats->tx_packets;
		connman_dbus_dict_append_basic(dict, "TX.Packets",
					DBUS_TYPE_UINT32, &stats->tx_packets);
	}

	if (counters->rx_bytes != stats->rx_bytes || append_all) {
		counters->rx_bytes = stats->rx_bytes;
		connman_dbus_dict_append_basic(dict, "RX.Bytes",
					DBUS_TYPE_UINT32, &stats->rx_bytes);
	}

	if (counters->tx_bytes != stats->tx_bytes || append_all) {
		counters->tx_bytes = stats->tx_bytes;
		connman_dbus_dict_append_basic(dict, "TX.Bytes",
					DBUS_TYPE_UINT32, &stats->tx_bytes);
	}

	if (counters->rx_errors != stats->rx_errors || append_all) {
		counters->rx_errors = stats->rx_errors;
		connman_dbus_dict_append_basic(dict, "RX.Errors",
					DBUS_TYPE_UINT32, &stats->rx_errors);
	}

	if (counters->tx_errors != stats->tx_errors || append_all) {
		counters->tx_errors = stats->tx_errors;
		connman_dbus_dict_append_basic(dict, "TX.Errors",
					DBUS_TYPE_UINT32, &stats->tx_errors);
	}

	if (counters->rx_dropped != stats->rx_dropped || append_all) {
		counters->rx_dropped = stats->rx_dropped;
		connman_dbus_dict_append_basic(dict, "RX.Dropped",
					DBUS_TYPE_UINT32, &stats->rx_dropped);
	}

	if (counters->tx_dropped != stats->tx_dropped || append_all) {
		counters->tx_dropped = stats->tx_dropped;
		connman_dbus_dict_append_basic(dict, "TX.Dropped",
					DBUS_TYPE_UINT32, &stats->tx_dropped);
	}

	if (counters->time != stats->time || append_all) {
		counters->time = stats->time;
		connman_dbus_dict_append_basic(dict, "Time",
					DBUS_TYPE_UINT32, &stats->time);
	}
}

static void stats_append(struct connman_service *service,
				const char *counter,
				struct connman_stats_counter *counters,
				bool append_all)
{
	DBusMessageIter array, dict;
	DBusMessage *msg;

	DBG("service %p counter %s", service, counter);

	msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_CALL);
	if (!msg)
		return;

	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH,
				&service->path, DBUS_TYPE_INVALID);

	dbus_message_iter_init_append(msg, &array);

	/* home counter */
	connman_dbus_dict_open(&array, &dict);

	stats_append_counters(&dict, &service->stats.data,
				&counters->stats.data, append_all);

	connman_dbus_dict_close(&array, &dict);

	/* roaming counter */
	connman_dbus_dict_open(&array, &dict);

	stats_append_counters(&dict, &service->stats_roaming.data,
				&counters->stats_roaming.data, append_all);

	connman_dbus_dict_close(&array, &dict);

	__connman_counter_send_usage(counter, msg);
}

static void stats_update(struct connman_service *service,
				unsigned int rx_packets, unsigned int tx_packets,
				unsigned int rx_bytes, unsigned int tx_bytes,
				unsigned int rx_errors, unsigned int tx_errors,
				unsigned int rx_dropped, unsigned int tx_dropped)
{
	struct connman_stats *stats = stats_get(service);
	struct connman_stats_data *data_last = &stats->data_last;
	struct connman_stats_data *data = &stats->data;
	unsigned int seconds;

	DBG("service %p", service);

	if (stats->valid) {
		data->rx_packets +=
			rx_packets - data_last->rx_packets;
		data->tx_packets +=
			tx_packets - data_last->tx_packets;
		data->rx_bytes +=
			rx_bytes - data_last->rx_bytes;
		data->tx_bytes +=
			tx_bytes - data_last->tx_bytes;
		data->rx_errors +=
			rx_errors - data_last->rx_errors;
		data->tx_errors +=
			tx_errors - data_last->tx_errors;
		data->rx_dropped +=
			rx_dropped - data_last->rx_dropped;
		data->tx_dropped +=
			tx_dropped - data_last->tx_dropped;
	} else {
		stats->valid = true;
	}

	data_last->rx_packets = rx_packets;
	data_last->tx_packets = tx_packets;
	data_last->rx_bytes = rx_bytes;
	data_last->tx_bytes = tx_bytes;
	data_last->rx_errors = rx_errors;
	data_last->tx_errors = tx_errors;
	data_last->rx_dropped = rx_dropped;
	data_last->tx_dropped = tx_dropped;

	seconds = g_timer_elapsed(stats->timer, NULL);
	stats->data.time = stats->data_last.time + seconds;
}

void __connman_service_notify(struct connman_service *service,
			unsigned int rx_packets, unsigned int tx_packets,
			unsigned int rx_bytes, unsigned int tx_bytes,
			unsigned int rx_errors, unsigned int tx_errors,
			unsigned int rx_dropped, unsigned int tx_dropped)
{
	GHashTableIter iter;
	gpointer key, value;
	const char *counter;
	struct connman_stats_counter *counters;
	struct connman_stats_data *data;
	int err;

	if (!service)
		return;

	if (!is_connected(service->state))
		return;

	stats_update(service,
		rx_packets, tx_packets,
		rx_bytes, tx_bytes,
		rx_errors, tx_errors,
		rx_dropped, tx_dropped);

	data = &stats_get(service)->data;
	err = __connman_stats_update(service, service->roaming, data);
	if (err < 0)
		connman_error("Failed to store statistics for %s",
				service->identifier);

	g_hash_table_iter_init(&iter, service->counter_table);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		counter = key;
		counters = value;

		stats_append(service, counter, counters, counters->append_all);
		counters->append_all = false;
	}
}

int __connman_service_counter_register(const char *counter)
{
	struct connman_service *service;
	GList *list;
	struct connman_stats_counter *counters;

	DBG("counter %s", counter);

	counter_list = g_slist_prepend(counter_list, (gpointer)counter);

	for (list = service_list; list; list = list->next) {
		service = list->data;

		counters = g_try_new0(struct connman_stats_counter, 1);
		if (!counters)
			return -ENOMEM;

		counters->append_all = true;

		g_hash_table_replace(service->counter_table, (gpointer)counter,
					counters);
	}

	return 0;
}

void __connman_service_counter_unregister(const char *counter)
{
	struct connman_service *service;
	GList *list;

	DBG("counter %s", counter);

	for (list = service_list; list; list = list->next) {
		service = list->data;

		g_hash_table_remove(service->counter_table, counter);
	}

	counter_list = g_slist_remove(counter_list, counter);
}

int connman_service_iterate_services(connman_service_iterate_cb cb,
							void *user_data)
{
	GList *list;
	int ret = 0;

	for (list = service_list; list && ret == 0; list = list->next)
		ret = cb((struct connman_service *)list->data, user_data);

	return ret;
}

#if defined TIZEN_EXT
static void append_wifi_ext_info(DBusMessageIter *dict,
					struct connman_network *network)
{
	char bssid_buff[WIFI_BSSID_STR_LEN] = {0,};
	char *bssid_str = bssid_buff;
	const void *ssid;
	unsigned int ssid_len;
	unsigned char *bssid;
	unsigned int maxrate;
	int maxspeed;
	unsigned int keymgmt;
	uint16_t frequency;
	const char *enc_mode;
	const char *str;
	gboolean passpoint;
	char country_code_buff[WIFI_COUNTRY_CODE_LEN + 1] = {0,};
	char *country_code_str = country_code_buff;
	unsigned char *country_code;
	uint16_t connection_mode;

	ssid = connman_network_get_blob(network, "WiFi.SSID", &ssid_len);
	bssid = connman_network_get_bssid(network);
	maxrate = connman_network_get_maxrate(network);
	maxspeed = connman_network_get_maxspeed(network);
	frequency = connman_network_get_frequency(network);
	enc_mode = connman_network_get_enc_mode(network);
	passpoint = connman_network_get_bool(network, "WiFi.HS20AP");
	keymgmt = connman_network_get_keymgmt(network);
	country_code = connman_network_get_countrycode(network);
	connection_mode = connman_network_get_connection_mode(network);

	snprintf(bssid_str, WIFI_BSSID_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
				bssid[0], bssid[1], bssid[2],
				bssid[3], bssid[4], bssid[5]);

	snprintf(country_code_str, (WIFI_COUNTRY_CODE_LEN + 1), "%c%c",
		 country_code[0], country_code[1]);


	connman_dbus_dict_append_fixed_array(dict, "SSID",
					DBUS_TYPE_BYTE, &ssid, ssid_len);
	connman_dbus_dict_append_basic(dict, "BSSID",
					DBUS_TYPE_STRING, &bssid_str);
	connman_dbus_dict_append_basic(dict, "MaxRate",
					DBUS_TYPE_UINT32, &maxrate);
	connman_dbus_dict_append_basic(dict, "MaxSpeed",
					DBUS_TYPE_INT32, &maxspeed);
	connman_dbus_dict_append_basic(dict, "Frequency",
					DBUS_TYPE_UINT16, &frequency);
	connman_dbus_dict_append_basic(dict, "EncryptionMode",
					DBUS_TYPE_STRING, &enc_mode);
	connman_dbus_dict_append_basic(dict, "Passpoint",
					DBUS_TYPE_BOOLEAN, &passpoint);
	connman_dbus_dict_append_basic(dict, "Keymgmt",
					DBUS_TYPE_UINT32, &keymgmt);
	connman_dbus_dict_append_basic(dict, "Country", DBUS_TYPE_STRING,
				       &country_code_str);
	connman_dbus_dict_append_basic(dict, "ConnMode",
					DBUS_TYPE_UINT16, &connection_mode);

	str = connman_network_get_string(network, "WiFi.Security");
	if (str != NULL && g_str_equal(str, "ieee8021x") == TRUE) {
		str = connman_network_get_string(network, "WiFi.EAP");
		if (str != NULL)
			connman_dbus_dict_append_basic(dict, "EAP",
					DBUS_TYPE_STRING, &str);

		str = connman_network_get_string(network, "WiFi.Phase2");
		if (str != NULL)
			connman_dbus_dict_append_basic(dict, "Phase2",
					DBUS_TYPE_STRING, &str);

		str = connman_network_get_string(network, "WiFi.Identity");
		if (str != NULL)
			connman_dbus_dict_append_basic(dict, "Identity",
					DBUS_TYPE_STRING, &str);

		str = connman_network_get_string(network, "WiFi.CACertFile");
		if (str != NULL)
			connman_dbus_dict_append_basic(dict, "CACertFile",
					DBUS_TYPE_STRING, &str);

		str = connman_network_get_string(network,
				"WiFi.ClientCertFile");
		if (str != NULL)
			connman_dbus_dict_append_basic(dict, "ClientCertFile",
					DBUS_TYPE_STRING, &str);

		str = connman_network_get_string(network,
				"WiFi.PrivateKeyFile");
		if (str != NULL)
			connman_dbus_dict_append_basic(dict, "PrivateKeyFile",
					DBUS_TYPE_STRING, &str);
	}
}

static void append_bssid_info(DBusMessageIter *iter, void *user_data)
{
	GSList *bssid_list = NULL;
	struct connman_network *network = user_data;
	struct connman_bssids *bssids;
	char bssid_buf[MAC_ADDRESS_LENGTH] = {0,};
	char *bssid_str = bssid_buf;

	bssid_list = (GSList *)connman_network_get_bssid_list(network);
	if(bssid_list) {
		GSList *list;
		for (list = bssid_list; list; list = list->next) {
			bssids = (struct connman_bssids *)list->data;
			g_snprintf(bssid_buf, MAC_ADDRESS_LENGTH, "%02x:%02x:%02x:%02x:%02x:%02x",
					bssids->bssid[0], bssids->bssid[1], bssids->bssid[2],
					bssids->bssid[3], bssids->bssid[4], bssids->bssid[5]);

			connman_dbus_dict_append_basic(iter, "BSSID",
					DBUS_TYPE_STRING, &bssid_str);

			connman_dbus_dict_append_basic(iter, "Strength",
					DBUS_TYPE_UINT16, &bssids->strength);

			connman_dbus_dict_append_basic(iter, "Frequency",
					DBUS_TYPE_UINT16, &bssids->frequency);
		}
	}
}
#endif

static void append_properties(DBusMessageIter *dict, dbus_bool_t limited,
					struct connman_service *service)
{
	dbus_bool_t val;
	const char *str;
	GSList *list;

#if defined TIZEN_EXT
	unsigned int frequency = 0U;
	unsigned char *wifi_vsie;
	unsigned int wifi_vsie_len;
	GSList *vsie_list = NULL;

	if (service->network) {
		frequency = connman_network_get_frequency(service->network);
		connman_dbus_dict_append_basic(dict, "Frequency",
				DBUS_TYPE_UINT16, &frequency);
		vsie_list = (GSList *)connman_network_get_vsie_list(service->network);
	}

	if (vsie_list) {
		GSList *list;
		for (list = vsie_list; list; list = list->next) {
			wifi_vsie = (unsigned char *)list->data;
			wifi_vsie_len = wifi_vsie[1] + 2;

			connman_dbus_dict_append_fixed_array(dict, "Vsie", DBUS_TYPE_BYTE,
					&wifi_vsie, wifi_vsie_len);
		}
	}
#endif

	str = __connman_service_type2string(service->type);
	if (str)
		connman_dbus_dict_append_basic(dict, "Type",
						DBUS_TYPE_STRING, &str);

	connman_dbus_dict_append_array(dict, "Security",
				DBUS_TYPE_STRING, append_security, service);

	str = state2string(service->state);
	if (str)
		connman_dbus_dict_append_basic(dict, "State",
						DBUS_TYPE_STRING, &str);

#ifdef TIZEN_EXT
	str = state2string(service->state_ipv6);
	if (str != NULL)
		connman_dbus_dict_append_basic(dict, "StateIPv6",
				DBUS_TYPE_STRING, &str);
#endif

	str = error2string(service->error);
	if (str)
		connman_dbus_dict_append_basic(dict, "Error",
						DBUS_TYPE_STRING, &str);

	if (service->strength > 0)
		connman_dbus_dict_append_basic(dict, "Strength",
					DBUS_TYPE_BYTE, &service->strength);

	val = service->favorite;
	connman_dbus_dict_append_basic(dict, "Favorite",
					DBUS_TYPE_BOOLEAN, &val);

	val = service->immutable;
	connman_dbus_dict_append_basic(dict, "Immutable",
					DBUS_TYPE_BOOLEAN, &val);

	if (service->favorite)
		val = service->autoconnect;
	else
		val = service->favorite;

	connman_dbus_dict_append_basic(dict, "AutoConnect",
				DBUS_TYPE_BOOLEAN, &val);

	if (service->name)
		connman_dbus_dict_append_basic(dict, "Name",
					DBUS_TYPE_STRING, &service->name);

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_P2P:
#if defined TIZEN_EXT_WIFI_MESH
	case CONNMAN_SERVICE_TYPE_MESH:
#endif
		break;
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		val = service->roaming;
		connman_dbus_dict_append_basic(dict, "Roaming",
					DBUS_TYPE_BOOLEAN, &val);

		connman_dbus_dict_append_dict(dict, "Ethernet",
						append_ethernet, service);
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
#if defined TIZEN_EXT
		if (service->network != NULL) {
			append_wifi_ext_info(dict, service->network);
			connman_dbus_dict_append_dict(dict, "BSSID.List",
					append_bssid_info, service->network);
		}

		connman_dbus_dict_append_dict(dict, "Ethernet",
						append_ethernet, service);

		service->disconnect_reason = connman_network_get_disconnect_reason(service->network);
		connman_dbus_dict_append_basic(dict, "DisconnectReason",
				DBUS_TYPE_INT32, &service->disconnect_reason);

		connman_dbus_dict_append_basic(dict, "AssocStatusCode",
				DBUS_TYPE_INT32, &service->assoc_status_code);

		connman_dbus_dict_append_basic(dict, "Hidden",
				DBUS_TYPE_BOOLEAN, &service->hidden_service);

		break;
#endif
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_GADGET:
		connman_dbus_dict_append_dict(dict, "Ethernet",
						append_ethernet, service);
		break;
	}

	connman_dbus_dict_append_dict(dict, "IPv4", append_ipv4, service);

	connman_dbus_dict_append_dict(dict, "IPv4.Configuration",
						append_ipv4config, service);

	connman_dbus_dict_append_dict(dict, "IPv6", append_ipv6, service);

	connman_dbus_dict_append_dict(dict, "IPv6.Configuration",
						append_ipv6config, service);

	connman_dbus_dict_append_array(dict, "Nameservers",
				DBUS_TYPE_STRING, append_dns, service);

	connman_dbus_dict_append_array(dict, "Nameservers.Configuration",
				DBUS_TYPE_STRING, append_dnsconfig, service);

	if (service->state == CONNMAN_SERVICE_STATE_READY ||
			service->state == CONNMAN_SERVICE_STATE_ONLINE)
		list = __connman_timeserver_get_all(service);
	else
		list = NULL;

	connman_dbus_dict_append_array(dict, "Timeservers",
				DBUS_TYPE_STRING, append_ts, list);

	g_slist_free_full(list, g_free);

	connman_dbus_dict_append_array(dict, "Timeservers.Configuration",
				DBUS_TYPE_STRING, append_tsconfig, service);

	connman_dbus_dict_append_array(dict, "Domains",
				DBUS_TYPE_STRING, append_domain, service);

	connman_dbus_dict_append_array(dict, "Domains.Configuration",
				DBUS_TYPE_STRING, append_domainconfig, service);

	connman_dbus_dict_append_dict(dict, "Proxy", append_proxy, service);

	connman_dbus_dict_append_dict(dict, "Proxy.Configuration",
						append_proxyconfig, service);

	val = service->mdns;
	connman_dbus_dict_append_basic(dict, "mDNS", DBUS_TYPE_BOOLEAN,
				&val);

	val = service->mdns_config;
	connman_dbus_dict_append_basic(dict, "mDNS.Configuration",
				DBUS_TYPE_BOOLEAN, &val);

	connman_dbus_dict_append_dict(dict, "Provider",
						append_provider, service);

	if (service->network)
		connman_network_append_acddbus(dict, service->network);
}

static void append_struct_service(DBusMessageIter *iter,
		connman_dbus_append_cb_t function,
		struct connman_service *service)
{
	DBusMessageIter entry, dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
							&service->path);

	connman_dbus_dict_open(&entry, &dict);
	if (function)
		function(&dict, service);
	connman_dbus_dict_close(&entry, &dict);

	dbus_message_iter_close_container(iter, &entry);
}

static void append_dict_properties(DBusMessageIter *dict, void *user_data)
{
	struct connman_service *service = user_data;

	append_properties(dict, TRUE, service);
}

static void append_struct(gpointer value, gpointer user_data)
{
	struct connman_service *service = value;
	DBusMessageIter *iter = user_data;

	if (!service->path)
		return;

	append_struct_service(iter, append_dict_properties, service);
}

void __connman_service_list_struct(DBusMessageIter *iter)
{
	g_list_foreach(service_list, append_struct, iter);
}

bool __connman_service_is_hidden(struct connman_service *service)
{
	return service->hidden;
}

bool
__connman_service_is_split_routing(struct connman_service *service)
{
	return service->do_split_routing;
}

bool __connman_service_index_is_split_routing(int index)
{
	struct connman_service *service;

	if (index < 0)
		return false;

	service = __connman_service_lookup_from_index(index);
	if (!service)
		return false;

	return __connman_service_is_split_routing(service);
}

int __connman_service_get_index(struct connman_service *service)
{
	if (!service)
		return -1;

	if (service->network)
		return connman_network_get_index(service->network);
	else if (service->provider)
		return connman_provider_get_index(service->provider);

	return -1;
}

void __connman_service_set_hidden(struct connman_service *service)
{
	if (!service || service->hidden)
		return;

	service->hidden_service = true;
}

void __connman_service_set_hostname(struct connman_service *service,
						const char *hostname)
{
	if (!service || service->hidden)
		return;

	g_free(service->hostname);
	service->hostname = NULL;

	if (hostname && g_str_is_ascii(hostname))
		service->hostname = g_strdup(hostname);
}

const char *__connman_service_get_hostname(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->hostname;
}

void __connman_service_set_domainname(struct connman_service *service,
						const char *domainname)
{
	if (!service || service->hidden)
		return;

	g_free(service->domainname);
	service->domainname = NULL;

	if (domainname && g_str_is_ascii(domainname))
		service->domainname = g_strdup(domainname);

	domain_changed(service);
}

const char *connman_service_get_domainname(struct connman_service *service)
{
	if (!service)
		return NULL;

	if (service->domains)
		return service->domains[0];
	else
		return service->domainname;
}

const char *connman_service_get_dbuspath(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->path;
}

char **connman_service_get_nameservers(struct connman_service *service)
{
	if (!service)
		return NULL;

	if (service->nameservers_config)
		return g_strdupv(service->nameservers_config);
	else if (service->nameservers ||
					service->nameservers_auto) {
		int len = 0, len_auto = 0, i;
		char **nameservers;

		if (service->nameservers)
			len = g_strv_length(service->nameservers);
		if (service->nameservers_auto)
			len_auto = g_strv_length(service->nameservers_auto);

		nameservers = g_try_new0(char *, len + len_auto + 1);
		if (!nameservers)
			return NULL;

		for (i = 0; i < len; i++)
			nameservers[i] = g_strdup(service->nameservers[i]);

		for (i = 0; i < len_auto; i++)
			nameservers[i + len] =
				g_strdup(service->nameservers_auto[i]);

		return nameservers;
	}

	return g_strdupv(connman_setting_get_string_list("FallbackNameservers"));
}

char **connman_service_get_timeservers_config(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->timeservers_config;
}

char **connman_service_get_timeservers(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->timeservers;
}

#if defined TIZEN_EXT
/*
 * Description: Telephony plug-in requires manual PROXY setting function
 */
int connman_service_set_proxy(struct connman_service *service,
					const char *proxy, gboolean active)
{
	char **proxies_array = NULL;

	if (service == NULL)
		return -EINVAL;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
		break;

	default:
		return -EINVAL;
	}

	g_strfreev(service->proxies);
	service->proxies = NULL;

	if (proxy != NULL)
		proxies_array = g_strsplit(proxy, " ", 0);

	service->proxies = proxies_array;

	if (proxy == NULL) {
		service->proxy_config = CONNMAN_SERVICE_PROXY_METHOD_DIRECT;
		DBG("proxy changed (%d)", active);
	} else {
		service->proxy_config = CONNMAN_SERVICE_PROXY_METHOD_MANUAL;
		DBG("proxy chagned %s (%d)", proxy, active);
	}

	if (active == TRUE) {
		proxy_changed(service);

		__connman_notifier_proxy_changed(service);
	}

	return 0;
}
#endif

void connman_service_set_proxy_method(struct connman_service *service,
					enum connman_service_proxy_method method)
{
	if (!service || service->hidden)
		return;

	service->proxy = method;

	proxy_changed(service);

	if (method != CONNMAN_SERVICE_PROXY_METHOD_AUTO)
		__connman_notifier_proxy_changed(service);
}

enum connman_service_proxy_method connman_service_get_proxy_method(
					struct connman_service *service)
{
	if (!service)
		return CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;

	if (service->proxy_config != CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN) {
		if (service->proxy_config == CONNMAN_SERVICE_PROXY_METHOD_AUTO &&
				!service->pac)
			return service->proxy;

		return service->proxy_config;
	}

	return service->proxy;
}

char **connman_service_get_proxy_servers(struct connman_service *service)
{
	return g_strdupv(service->proxies);
}

char **connman_service_get_proxy_excludes(struct connman_service *service)
{
	return g_strdupv(service->excludes);
}

const char *connman_service_get_proxy_url(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->pac;
}

#if defined TIZEN_EXT
void connman_service_set_internet_connection(struct connman_service *service,
							bool internet_connection)
{
	if (!service)
		return;

	if (service->is_internet_connection != internet_connection) {
		service->is_internet_connection = internet_connection;

		g_get_current_time(&service->modified);
		service_save(service);
	}
}

bool connman_service_get_internet_connection(struct connman_service *service)
{
	if (!service)
		return false;

	return service->is_internet_connection;
}
#endif

void __connman_service_set_proxy_autoconfig(struct connman_service *service,
							const char *url)
{
	if (!service || service->hidden)
		return;

	service->proxy = CONNMAN_SERVICE_PROXY_METHOD_AUTO;

	if (service->ipconfig_ipv4) {
		if (__connman_ipconfig_set_proxy_autoconfig(
			    service->ipconfig_ipv4, url) < 0)
			return;
	} else if (service->ipconfig_ipv6) {
		if (__connman_ipconfig_set_proxy_autoconfig(
			    service->ipconfig_ipv6, url) < 0)
			return;
	} else
		return;

	proxy_changed(service);

	__connman_notifier_proxy_changed(service);
}

const char *connman_service_get_proxy_autoconfig(struct connman_service *service)
{
	if (!service)
		return NULL;

	if (service->ipconfig_ipv4)
		return __connman_ipconfig_get_proxy_autoconfig(
						service->ipconfig_ipv4);
	else if (service->ipconfig_ipv6)
		return __connman_ipconfig_get_proxy_autoconfig(
						service->ipconfig_ipv6);
	return NULL;
}

#if defined TIZEN_EXT
int connman_service_get_ipv6_dns_method(struct connman_service *service)
{
	if (!service) {
		DBG("Service is NULL");
		return -1;
	}

	return service->dns_config_method_ipv6;
}
#endif

void __connman_service_set_timeservers(struct connman_service *service,
				char **timeservers)
{
	int i;

	if (!service)
		return;

	g_strfreev(service->timeservers);
	service->timeservers = NULL;

	for (i = 0; timeservers && timeservers[i]; i++)
		__connman_service_timeserver_append(service, timeservers[i]);
}

int __connman_service_timeserver_append(struct connman_service *service,
						const char *timeserver)
{
	int len;

	DBG("service %p timeserver %s", service, timeserver);

	if (!timeserver)
		return -EINVAL;

	if (service->timeservers) {
		int i;

		for (i = 0; service->timeservers[i]; i++)
			if (g_strcmp0(service->timeservers[i], timeserver) == 0)
				return -EEXIST;

		len = g_strv_length(service->timeservers);
		service->timeservers = g_try_renew(char *, service->timeservers,
							len + 2);
	} else {
		len = 0;
		service->timeservers = g_try_new0(char *, len + 2);
	}

	if (!service->timeservers)
		return -ENOMEM;

	service->timeservers[len] = g_strdup(timeserver);
	service->timeservers[len + 1] = NULL;

	return 0;
}

int __connman_service_timeserver_remove(struct connman_service *service,
						const char *timeserver)
{
	char **servers;
	int len, i, j, found = 0;

	DBG("service %p timeserver %s", service, timeserver);

	if (!timeserver)
		return -EINVAL;

	if (!service->timeservers)
		return 0;

	for (i = 0; service->timeservers &&
					service->timeservers[i]; i++)
		if (g_strcmp0(service->timeservers[i], timeserver) == 0) {
			found = 1;
			break;
		}

	if (found == 0)
		return 0;

	len = g_strv_length(service->timeservers);

	if (len == 1) {
		g_strfreev(service->timeservers);
		service->timeservers = NULL;

		return 0;
	}

	servers = g_try_new0(char *, len);
	if (!servers)
		return -ENOMEM;

	for (i = 0, j = 0; i < len; i++) {
		if (g_strcmp0(service->timeservers[i], timeserver) != 0) {
			servers[j] = g_strdup(service->timeservers[i]);
			if (!servers[j])
				return -ENOMEM;
			j++;
		}
	}
	servers[len - 1] = NULL;

	g_strfreev(service->timeservers);
	service->timeservers = servers;

	return 0;
}

void __connman_service_timeserver_changed(struct connman_service *service,
		GSList *ts_list)
{
	if (!service)
		return;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
			CONNMAN_SERVICE_INTERFACE, "Timeservers",
			DBUS_TYPE_STRING, append_ts, ts_list);
}

void __connman_service_set_pac(struct connman_service *service,
					const char *pac)
{
	if (service->hidden)
		return;
	g_free(service->pac);
	service->pac = g_strdup(pac);

	proxy_changed(service);
}

#if defined TIZEN_EXT
void __connman_service_set_proxy(struct connman_service *service,
                                       const char *proxies)
{
       char **proxies_array = NULL;

       g_strfreev(service->proxies);
       service->proxies = NULL;

       if (proxies != NULL)
               proxies_array = g_strsplit(proxies, " ", 0);

       service->proxies = proxies_array;
}
#endif

void __connman_service_set_identity(struct connman_service *service,
					const char *identity)
{
	if (service->immutable || service->hidden)
		return;

	g_free(service->identity);
	service->identity = g_strdup(identity);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.Identity",
					service->identity);
}

void __connman_service_set_anonymous_identity(struct connman_service *service,
						const char *anonymous_identity)
{
	if (service->immutable || service->hidden)
		return;

	g_free(service->anonymous_identity);
	service->anonymous_identity = g_strdup(anonymous_identity);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.AnonymousIdentity",
					service->anonymous_identity);
}

void __connman_service_set_subject_match(struct connman_service *service,
						const char *subject_match)
{
	if (service->immutable || service->hidden)
		return;

	g_free(service->subject_match);
	service->subject_match = g_strdup(subject_match);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.SubjectMatch",
					service->subject_match);
}

void __connman_service_set_altsubject_match(struct connman_service *service,
						const char *altsubject_match)
{
	if (service->immutable || service->hidden)
		return;

	g_free(service->altsubject_match);
	service->altsubject_match = g_strdup(altsubject_match);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.AltSubjectMatch",
					service->altsubject_match);
}

void __connman_service_set_domain_suffix_match(struct connman_service *service,
						const char *domain_suffix_match)
{
	if (service->immutable || service->hidden)
		return;

	g_free(service->domain_suffix_match);
	service->domain_suffix_match = g_strdup(domain_suffix_match);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.DomainSuffixMatch",
					service->domain_suffix_match);
}

void __connman_service_set_domain_match(struct connman_service *service,
						const char *domain_match)
{
	if (service->immutable || service->hidden)
		return;

	g_free(service->domain_match);
	service->domain_match = g_strdup(domain_match);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.DomainMatch",
					service->domain_match);
}

void __connman_service_set_agent_identity(struct connman_service *service,
						const char *agent_identity)
{
	if (service->hidden)
		return;
	g_free(service->agent_identity);
	service->agent_identity = g_strdup(agent_identity);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.AgentIdentity",
					service->agent_identity);
}

int __connman_service_check_passphrase(enum connman_service_security security,
		const char *passphrase)
{
	guint i;
	gsize length;

	if (!passphrase)
		return 0;

	length = strlen(passphrase);

	switch (security) {
	case CONNMAN_SERVICE_SECURITY_UNKNOWN:
	case CONNMAN_SERVICE_SECURITY_NONE:
	case CONNMAN_SERVICE_SECURITY_WPA:
#if !defined TIZEN_EXT
	case CONNMAN_SERVICE_SECURITY_RSN:
#endif

		DBG("service security '%s' (%d) not handled",
				security2string(security), security);

		return -EOPNOTSUPP;

	case CONNMAN_SERVICE_SECURITY_PSK:
#if defined TIZEN_EXT
	case CONNMAN_SERVICE_SECURITY_RSN:
	/* TO CHECK: We need to check the key length supported by SAE */
	case CONNMAN_SERVICE_SECURITY_SAE:
#endif
		/* A raw key is always 64 bytes length,
		 * its content is in hex representation.
		 * A PSK key must be between [8..63].
		 */
		if (length == 64) {
			for (i = 0; i < 64; i++)
				if (!isxdigit((unsigned char)
					      passphrase[i]))
					return -ENOKEY;
		} else if (length < 8 || length > 63)
			return -ENOKEY;
		break;
	case CONNMAN_SERVICE_SECURITY_WEP:
		/* length of WEP key is 10 or 26
		 * length of WEP passphrase is 5 or 13
		 */
		if (length == 10 || length == 26) {
			for (i = 0; i < length; i++)
				if (!isxdigit((unsigned char)
					      passphrase[i]))
					return -ENOKEY;
		} else if (length != 5 && length != 13)
			return -ENOKEY;
		break;

	case CONNMAN_SERVICE_SECURITY_8021X:
#if defined TIZEN_EXT
	case CONNMAN_SERVICE_SECURITY_OWE:
	case CONNMAN_SERVICE_SECURITY_DPP:
#endif
		break;
	}

	return 0;
}

int __connman_service_set_passphrase(struct connman_service *service,
					const char *passphrase)
{
	int err;

	if (service->hidden)
		return -EINVAL;

	if (service->immutable &&
			service->security != CONNMAN_SERVICE_SECURITY_8021X)
		return -EINVAL;

#if defined TIZEN_EXT
	if (service->immutable &&
			service->security != CONNMAN_SERVICE_SECURITY_DPP)
		return -EINVAL;
	/* The encrypted passphrase is used here
	 * and validation is done by net-config before being encrypted.
	 */
	err = 0;
	if (service->security != CONNMAN_SERVICE_SECURITY_PSK &&
			service->security != CONNMAN_SERVICE_SECURITY_RSN &&
			service->security != CONNMAN_SERVICE_SECURITY_SAE &&
			service->security != CONNMAN_SERVICE_SECURITY_WEP)
#endif
	err = __connman_service_check_passphrase(service->security, passphrase);

	if (err < 0)
		return err;

	g_free(service->passphrase);
	service->passphrase = g_strdup(passphrase);

	if (service->network)
		connman_network_set_string(service->network, "WiFi.Passphrase",
				service->passphrase);

	return 0;
}

const char *__connman_service_get_passphrase(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->passphrase;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	connman_dbus_dict_open(&array, &dict);
	append_properties(&dict, FALSE, service);
	connman_dbus_dict_close(&array, &dict);

	return reply;
}

static char **remove_empty_strings(char **strv)
{
	int index = 0;
	char **iter = strv;

	while (*iter) {
		if (**iter)
			strv[index++] = *iter;
		else
			g_free(*iter);
		iter++;
	}

	strv[index] = NULL;
	return strv;
}

static int update_proxy_configuration(struct connman_service *service,
				DBusMessageIter *array)
{
	DBusMessageIter dict;
	enum connman_service_proxy_method method;
	GString *servers_str = NULL;
	GString *excludes_str = NULL;
	const char *url = NULL;

	method = CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant;
		const char *key;
		int type;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			goto error;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			goto error;

		dbus_message_iter_recurse(&entry, &variant);

		type = dbus_message_iter_get_arg_type(&variant);

		if (g_str_equal(key, "Method")) {
			const char *val;

			if (type != DBUS_TYPE_STRING)
				goto error;

			dbus_message_iter_get_basic(&variant, &val);
			method = string2proxymethod(val);
		} else if (g_str_equal(key, "URL")) {
			if (type != DBUS_TYPE_STRING)
				goto error;

			dbus_message_iter_get_basic(&variant, &url);
		} else if (g_str_equal(key, "Servers")) {
			DBusMessageIter str_array;

			if (type != DBUS_TYPE_ARRAY)
				goto error;

			servers_str = g_string_new(NULL);
			if (!servers_str)
				goto error;

			dbus_message_iter_recurse(&variant, &str_array);

			while (dbus_message_iter_get_arg_type(&str_array) ==
							DBUS_TYPE_STRING) {
				char *val = NULL;

				dbus_message_iter_get_basic(&str_array, &val);

				if (servers_str->len > 0)
					g_string_append_printf(servers_str,
							" %s", val);
				else
					g_string_append(servers_str, val);

				dbus_message_iter_next(&str_array);
			}
		} else if (g_str_equal(key, "Excludes")) {
			DBusMessageIter str_array;

			if (type != DBUS_TYPE_ARRAY)
				goto error;

			excludes_str = g_string_new(NULL);
			if (!excludes_str)
				goto error;

			dbus_message_iter_recurse(&variant, &str_array);

			while (dbus_message_iter_get_arg_type(&str_array) ==
							DBUS_TYPE_STRING) {
				char *val = NULL;

				dbus_message_iter_get_basic(&str_array, &val);

				if (excludes_str->len > 0)
					g_string_append_printf(excludes_str,
							" %s", val);
				else
					g_string_append(excludes_str, val);

				dbus_message_iter_next(&str_array);
			}
		}

		dbus_message_iter_next(&dict);
	}

	switch (method) {
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		if (!servers_str && !service->proxies)
			goto error;

		if (servers_str) {
			g_strfreev(service->proxies);

			if (servers_str->len > 0) {
				char **proxies = g_strsplit_set(
					servers_str->str, " ", 0);
				proxies = remove_empty_strings(proxies);
				service->proxies = proxies;
			} else
				service->proxies = NULL;
		}

		if (excludes_str) {
			g_strfreev(service->excludes);

			if (excludes_str->len > 0) {
				char **excludes = g_strsplit_set(
					excludes_str->str, " ", 0);
				excludes = remove_empty_strings(excludes);
				service->excludes = excludes;
			} else
				service->excludes = NULL;
		}

		if (!service->proxies)
			method = CONNMAN_SERVICE_PROXY_METHOD_DIRECT;

		break;
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		g_free(service->pac);

		if (url && strlen(url) > 0)
			service->pac = g_strstrip(g_strdup(url));
		else
			service->pac = NULL;

		/* if we are connected:
		   - if service->pac == NULL
		   - if __connman_ipconfig_get_proxy_autoconfig(
		   service->ipconfig) == NULL
		   --> We should start WPAD */

		break;
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		goto error;
	}

	if (servers_str)
		g_string_free(servers_str, TRUE);

	if (excludes_str)
		g_string_free(excludes_str, TRUE);

	service->proxy_config = method;

	return 0;

error:
	if (servers_str)
		g_string_free(servers_str, TRUE);

	if (excludes_str)
		g_string_free(excludes_str, TRUE);

	return -EINVAL;
}

int __connman_service_reset_ipconfig(struct connman_service *service,
		enum connman_ipconfig_type type, DBusMessageIter *array,
		enum connman_service_state *new_state)
{
	struct connman_ipconfig *ipconfig, *new_ipconfig;
	enum connman_ipconfig_method old_method, new_method;
	enum connman_service_state state;
	int err = 0, index;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		ipconfig = service->ipconfig_ipv4;
		state = service->state_ipv4;
		new_method = CONNMAN_IPCONFIG_METHOD_DHCP;
	} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		ipconfig = service->ipconfig_ipv6;
		state = service->state_ipv6;
		new_method = CONNMAN_IPCONFIG_METHOD_AUTO;
	} else
		return -EINVAL;

	if (!ipconfig)
		return -ENXIO;

	old_method = __connman_ipconfig_get_method(ipconfig);
	index = __connman_ipconfig_get_index(ipconfig);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		new_ipconfig = create_ip4config(service, index,
				CONNMAN_IPCONFIG_METHOD_UNKNOWN);
	else
		new_ipconfig = create_ip6config(service, index);

	if (array) {
		err = __connman_ipconfig_set_config(new_ipconfig, array);
		if (err < 0) {
			__connman_ipconfig_unref(new_ipconfig);
			return err;
		}

		new_method = __connman_ipconfig_get_method(new_ipconfig);
	}

	if (is_connecting(state) || is_connected(state))
		__connman_network_clear_ipconfig(service->network, ipconfig);

	__connman_ipconfig_unref(ipconfig);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		service->ipconfig_ipv4 = new_ipconfig;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		service->ipconfig_ipv6 = new_ipconfig;

	if (is_connecting(state) || is_connected(state))
		__connman_ipconfig_enable(new_ipconfig);

	if (new_state && new_method != old_method) {
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			*new_state = service->state_ipv4;
		else
			*new_state = service->state_ipv6;

		settings_changed(service, new_ipconfig);
		address_updated(service, type);

		__connman_service_auto_connect(CONNMAN_SERVICE_CONNECT_REASON_AUTO);
	}

	DBG("err %d ipconfig %p type %d method %d state %s", err,
		new_ipconfig, type, new_method,
		!new_state  ? "-" : state2string(*new_state));

	return err;
}

/*
 * We set the timeout to 1 sec so that we have a chance to get
 * necessary IPv6 router advertisement messages that might have
 * DNS data etc.
 */
#define ONLINE_CHECK_INITIAL_INTERVAL 1
#define ONLINE_CHECK_MAX_INTERVAL 12

void __connman_service_wispr_start(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	DBG("service %p type %s", service, __connman_ipconfig_type2string(type));

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		service->online_check_interval_ipv4 =
					ONLINE_CHECK_INITIAL_INTERVAL;
	else
		service->online_check_interval_ipv6 =
					ONLINE_CHECK_INITIAL_INTERVAL;

	__connman_wispr_start(service, type);
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("service %p", service);

	if (!dbus_message_iter_init(msg, &iter))
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, "AutoConnect")) {
		dbus_bool_t autoconnect;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		if (!service->favorite)
			return __connman_error_invalid_service(msg);

		dbus_message_iter_get_basic(&value, &autoconnect);

		if (service->autoconnect == autoconnect)
			return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

		service->autoconnect = autoconnect;

		autoconnect_changed(service);

		if (autoconnect)
			__connman_service_auto_connect(CONNMAN_SERVICE_CONNECT_REASON_AUTO);

		service_save(service);
	} else if (g_str_equal(name, "Nameservers.Configuration")) {
		DBusMessageIter entry;
		GString *str;
		int index;
		const char *gw;
#if defined TIZEN_EXT
		enum connman_ipconfig_type ip_type = CONNMAN_IPCONFIG_TYPE_ALL;
		DBG("%s", name);
#endif

		if (__connman_provider_is_immutable(service->provider) ||
				service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		str = g_string_new(NULL);
		if (!str)
			return __connman_error_invalid_arguments(msg);

		index = __connman_service_get_index(service);
		gw = __connman_ipconfig_get_gateway_from_index(index,
			CONNMAN_IPCONFIG_TYPE_ALL);

#if !defined TIZEN_EXT
		if (gw && strlen(gw))
			__connman_service_nameserver_del_routes(service,
						CONNMAN_IPCONFIG_TYPE_ALL);

#endif
		dbus_message_iter_recurse(&value, &entry);

#if defined TIZEN_EXT
		/* IPv4/IPv6 Last DNS config method */
		int last_dns_ipv4 = service->dns_config_method_ipv4;
		int last_dns_ipv6 = service->dns_config_method_ipv6;
		DBG("Last DNS Config Method IPv4: %d IPv6: %d", last_dns_ipv4, last_dns_ipv6);
#endif

		while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
			const char *val;
			dbus_message_iter_get_basic(&entry, &val);
			dbus_message_iter_next(&entry);
#ifdef TIZEN_EXT
			/* First unpack the DNS Config Method */
			DBG("DNS Config Method: %s", val);
			if((g_strcmp0(val, "ipv4.manual") == 0)) {
				service->dns_config_method_ipv4 =
					CONNMAN_DNSCONFIG_METHOD_MANUAL;

				if(last_dns_ipv4 != CONNMAN_DNSCONFIG_METHOD_MANUAL) {
					if(ip_type == CONNMAN_IPCONFIG_TYPE_UNKNOWN)
						ip_type = CONNMAN_IPCONFIG_TYPE_IPV4;
					else
						ip_type = CONNMAN_IPCONFIG_TYPE_ALL;
				}
				continue;
			} else if(g_strcmp0(val, "ipv4.dhcp") == 0) {
				service->dns_config_method_ipv4 =
					CONNMAN_DNSCONFIG_METHOD_DHCP;
				if(last_dns_ipv4 == CONNMAN_DNSCONFIG_METHOD_MANUAL)
					ip_type = CONNMAN_IPCONFIG_TYPE_IPV4;

				continue;
			} else if(g_strcmp0(val, "ipv6.manual") == 0) {
				service->dns_config_method_ipv6 =
					CONNMAN_DNSCONFIG_METHOD_MANUAL;
				if(last_dns_ipv6 != CONNMAN_DNSCONFIG_METHOD_MANUAL) {
					if(ip_type == CONNMAN_IPCONFIG_TYPE_UNKNOWN)
						ip_type = CONNMAN_IPCONFIG_TYPE_IPV6;
					else
						ip_type = CONNMAN_IPCONFIG_TYPE_ALL;
				}
				continue;
			} else if(g_strcmp0(val, "ipv6.dhcp") == 0) {
				service->dns_config_method_ipv6 =
					CONNMAN_DNSCONFIG_METHOD_DHCP;
				if(last_dns_ipv6 == CONNMAN_DNSCONFIG_METHOD_MANUAL)
					ip_type = CONNMAN_IPCONFIG_TYPE_IPV6;

				continue;
			}
#endif
			if (!val[0])
				continue;

			if (str->len > 0)
				g_string_append_printf(str, " %s", val);
			else
				g_string_append(str, val);
		}

#if defined TIZEN_EXT
		if (service->dns_config_method_ipv4 == CONNMAN_DNSCONFIG_METHOD_DHCP &&
			service->dns_config_method_ipv6 == CONNMAN_DNSCONFIG_METHOD_DHCP) {
					DBG("Both IPv4 and IPv6 DNS Method DHCP");
					ip_type = CONNMAN_IPCONFIG_TYPE_ALL;
		}
		if (gw && strlen(gw))
			__connman_service_nameserver_del_routes(service,
						ip_type);

		DBG("%s ip_type: %d nameserver remove all", name, ip_type);
		nameserver_remove_all(service, ip_type);
#else
		nameserver_remove_all(service, CONNMAN_IPCONFIG_TYPE_ALL);
#endif
		g_strfreev(service->nameservers_config);

		if (str->len > 0) {
			char **nameservers, **iter;

			nameservers = g_strsplit_set(str->str, " ", 0);

			for (iter = nameservers; *iter; iter++)
				if (connman_inet_check_ipaddress(*iter) <= 0)
					*iter[0] = '\0';

			nameservers = remove_empty_strings(nameservers);
			service->nameservers_config = nameservers;
		} else {
			service->nameservers_config = NULL;
		}

		g_string_free(str, TRUE);

		if (gw && strlen(gw))
			__connman_service_nameserver_add_routes(service, gw);

#if defined TIZEN_EXT
		DBG("%s ip_type: %d nameserver add all", name, ip_type);
		nameserver_add_all(service, ip_type);
#else
		nameserver_add_all(service, CONNMAN_IPCONFIG_TYPE_ALL);
#endif
		dns_configuration_changed(service);

		if (__connman_service_is_connected_state(service,
						CONNMAN_IPCONFIG_TYPE_IPV4))
			__connman_service_wispr_start(service, CONNMAN_IPCONFIG_TYPE_IPV4);

		if (__connman_service_is_connected_state(service,
						CONNMAN_IPCONFIG_TYPE_IPV6))
			__connman_service_wispr_start(service, CONNMAN_IPCONFIG_TYPE_IPV6);

		service_save(service);
	} else if (g_str_equal(name, "Timeservers.Configuration")) {
		DBusMessageIter entry;
		GString *str;

		if (service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		str = g_string_new(NULL);
		if (!str)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_recurse(&value, &entry);

		while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
			const char *val;
			dbus_message_iter_get_basic(&entry, &val);
			dbus_message_iter_next(&entry);

			if (!val[0])
				continue;

			if (str->len > 0)
				g_string_append_printf(str, " %s", val);
			else
				g_string_append(str, val);
		}

		g_strfreev(service->timeservers_config);
		service->timeservers_config = NULL;

		if (str->len > 0) {
			char **timeservers = g_strsplit_set(str->str, " ", 0);
			timeservers = remove_empty_strings(timeservers);
			service->timeservers_config = timeservers;
		}

		g_string_free(str, TRUE);

		service_save(service);
		timeservers_configuration_changed(service);

		if (service == connman_service_get_default())
			__connman_timeserver_sync(service);

	} else if (g_str_equal(name, "Domains.Configuration")) {
		DBusMessageIter entry;
		GString *str;

		if (service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		str = g_string_new(NULL);
		if (!str)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_recurse(&value, &entry);

		while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
			const char *val;
			dbus_message_iter_get_basic(&entry, &val);
			dbus_message_iter_next(&entry);

			if (!val[0])
				continue;

			if (str->len > 0)
				g_string_append_printf(str, " %s", val);
			else
				g_string_append(str, val);
		}

		searchdomain_remove_all(service);
		g_strfreev(service->domains);

		if (str->len > 0) {
			char **domains = g_strsplit_set(str->str, " ", 0);
			domains = remove_empty_strings(domains);
			service->domains = domains;
		} else
			service->domains = NULL;

		g_string_free(str, TRUE);

		searchdomain_add_all(service);
		domain_configuration_changed(service);
		domain_changed(service);

		service_save(service);
	} else if (g_str_equal(name, "Proxy.Configuration")) {
		int err;

		if (service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		err = update_proxy_configuration(service, &value);

		if (err < 0)
			return __connman_error_failed(msg, -err);

		proxy_configuration_changed(service);

		__connman_notifier_proxy_changed(service);

		service_save(service);
	} else if (g_str_equal(name, "mDNS.Configuration")) {
		dbus_bool_t val;

		if (service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &val);
		service->mdns_config = val;

		mdns_configuration_changed(service);

		set_mdns(service, service->mdns_config);

		service_save(service);
	} else if (g_str_equal(name, "IPv4.Configuration") ||
			g_str_equal(name, "IPv6.Configuration")) {

		enum connman_service_state state =
						CONNMAN_SERVICE_STATE_UNKNOWN;
		enum connman_ipconfig_type type =
			CONNMAN_IPCONFIG_TYPE_UNKNOWN;
		int err = 0;

		if (service->type == CONNMAN_SERVICE_TYPE_VPN ||
				service->immutable)
			return __connman_error_not_supported(msg);

		DBG("%s", name);

		if (!service->ipconfig_ipv4 &&
					!service->ipconfig_ipv6)
			return __connman_error_invalid_property(msg);

		if (g_str_equal(name, "IPv4.Configuration"))
			type = CONNMAN_IPCONFIG_TYPE_IPV4;
		else
			type = CONNMAN_IPCONFIG_TYPE_IPV6;

		err = __connman_service_reset_ipconfig(service, type, &value,
								&state);

		if (err < 0) {
			if (is_connected(state) || is_connecting(state)) {
				if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
					__connman_network_enable_ipconfig(service->network,
							service->ipconfig_ipv4);
				else
					__connman_network_enable_ipconfig(service->network,
							service->ipconfig_ipv6);
			}

			return __connman_error_failed(msg, -err);
		}

		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			ipv4_configuration_changed(service);
		else
			ipv6_configuration_changed(service);

		if (is_connecting(service->state) ||
				is_connected(service->state)) {
			if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
				__connman_network_enable_ipconfig(service->network,
								service->ipconfig_ipv4);
			else
				__connman_network_enable_ipconfig(service->network,
								service->ipconfig_ipv6);
		}

		service_save(service);
#if defined TIZEN_EXT
		/* When AP is connected using WPS without SSID then its password needs
		 * to be saved for autoconnection */
	} else if (g_str_equal(name, "Passphrase")) {
		char *passphrase;

		if (type != DBUS_TYPE_STRING)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &passphrase);

		__connman_service_set_passphrase(service, passphrase);
#endif
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void set_error(struct connman_service *service,
					enum connman_service_error error)
{
	const char *str;

	if (service->error == error)
		return;

	service->error = error;

	if (!service->path)
		return;

#if !defined TIZEN_EXT
	if (!allow_property_changed(service))
		return;
#endif

	str = error2string(service->error);

	if (!str)
		str = "";

	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Error",
				DBUS_TYPE_STRING, &str);
}

static void remove_timeout(struct connman_service *service)
{
	if (service->timeout > 0) {
		g_source_remove(service->timeout);
		service->timeout = 0;
	}
}

static void reply_pending(struct connman_service *service, int error)
{
	remove_timeout(service);

	if (service->pending) {
		connman_dbus_reply_pending(service->pending, error, NULL);
		service->pending = NULL;
	}

	if (service->provider_pending) {
		connman_dbus_reply_pending(service->provider_pending,
				error, service->path);
		service->provider_pending = NULL;
	}
}

static void service_complete(struct connman_service *service)
{
	reply_pending(service, EIO);

	if (service->connect_reason != CONNMAN_SERVICE_CONNECT_REASON_USER)
		__connman_service_auto_connect(service->connect_reason);

	g_get_current_time(&service->modified);
	service_save(service);
}

static DBusMessage *clear_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	const char *name;

	DBG("service %p", service);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &name,
							DBUS_TYPE_INVALID);

	if (g_str_equal(name, "Error")) {
		set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);

		__connman_service_clear_error(service);
		service_complete(service);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static bool is_ipconfig_usable(struct connman_service *service)
{
	if (!__connman_ipconfig_is_usable(service->ipconfig_ipv4) &&
			!__connman_ipconfig_is_usable(service->ipconfig_ipv6))
		return false;

	return true;
}

static bool is_ignore(struct connman_service *service)
{
	if (!service->autoconnect)
		return true;

	if (service->roaming &&
		!connman_setting_get_bool("AutoConnectRoamingServices"))
		return true;

	if (service->ignore)
		return true;

	if (service->state == CONNMAN_SERVICE_STATE_FAILURE)
		return true;

	if (!is_ipconfig_usable(service))
		return true;

	return false;
}

static void disconnect_on_last_session(enum connman_service_type type)
{
	GList *list;

	for (list = service_list; list; list = list->next) {
		struct connman_service *service = list->data;

		if (service->type != type)
			continue;

		if (service->connect_reason != CONNMAN_SERVICE_CONNECT_REASON_SESSION)
			 continue;

		__connman_service_disconnect(service);
		return;
	}
}

static int active_sessions[MAX_CONNMAN_SERVICE_TYPES] = {};
static int always_connect[MAX_CONNMAN_SERVICE_TYPES] = {};
static int active_count = 0;

void __connman_service_set_active_session(bool enable, GSList *list)
{
	if (!list)
		return;

	if (enable)
		active_count++;
	else
		active_count--;

	while (list) {
		enum connman_service_type type = GPOINTER_TO_INT(list->data);

		switch (type) {
		case CONNMAN_SERVICE_TYPE_ETHERNET:
		case CONNMAN_SERVICE_TYPE_WIFI:
		case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		case CONNMAN_SERVICE_TYPE_CELLULAR:
		case CONNMAN_SERVICE_TYPE_GADGET:
			if (enable)
				active_sessions[type]++;
			else
				active_sessions[type]--;
			break;

		case CONNMAN_SERVICE_TYPE_UNKNOWN:
		case CONNMAN_SERVICE_TYPE_SYSTEM:
		case CONNMAN_SERVICE_TYPE_GPS:
		case CONNMAN_SERVICE_TYPE_VPN:
		case CONNMAN_SERVICE_TYPE_P2P:
#if defined TIZEN_EXT_WIFI_MESH
		case CONNMAN_SERVICE_TYPE_MESH:
#endif
			break;
		}

		if (active_sessions[type] == 0)
			disconnect_on_last_session(type);

		list = g_slist_next(list);
	}

	DBG("eth %d wifi %d bt %d cellular %d gadget %d sessions %d",
			active_sessions[CONNMAN_SERVICE_TYPE_ETHERNET],
			active_sessions[CONNMAN_SERVICE_TYPE_WIFI],
			active_sessions[CONNMAN_SERVICE_TYPE_BLUETOOTH],
			active_sessions[CONNMAN_SERVICE_TYPE_CELLULAR],
			active_sessions[CONNMAN_SERVICE_TYPE_GADGET],
			active_count);
}

struct preferred_tech_data {
	GList *preferred_list;
	enum connman_service_type type;
};

static void preferred_tech_add_by_type(gpointer data, gpointer user_data)
{
	struct connman_service *service = data;
	struct preferred_tech_data *tech_data = user_data;

	if (service->type == tech_data->type) {
		tech_data->preferred_list =
			g_list_append(tech_data->preferred_list, service);

		DBG("type %d service %p %s", tech_data->type, service,
				service->name);
	}
}

static GList *preferred_tech_list_get(void)
{
	unsigned int *tech_array;
	struct preferred_tech_data tech_data = { 0, };
	int i;

	tech_array = connman_setting_get_uint_list("PreferredTechnologies");
	if (!tech_array)
		return NULL;

	if (connman_setting_get_bool("SingleConnectedTechnology")) {
		GList *list;
		for (list = service_list; list; list = list->next) {
			struct connman_service *service = list->data;

			if (!is_connected(service->state))
				break;

			if (service->connect_reason ==
					CONNMAN_SERVICE_CONNECT_REASON_USER) {
				DBG("service %p name %s is user connected",
						service, service->name);
#if defined TIZEN_EXT
				/* We can connect to a favorite service like
				 * wifi even we have a userconnect for cellular
				 * because we have refount for cellular service
				 */
				if (service->type == CONNMAN_SERVICE_TYPE_CELLULAR)
					break;

				if (service->type == CONNMAN_SERVICE_TYPE_BLUETOOTH)
					break;
#endif
				return NULL;
			}
		}
	}

	for (i = 0; tech_array[i] != 0; i += 1) {
		tech_data.type = tech_array[i];
		g_list_foreach(service_list, preferred_tech_add_by_type,
				&tech_data);
	}

	return tech_data.preferred_list;
}

static void set_always_connecting_technologies()
{
	unsigned int *always_connected_techs =
		connman_setting_get_uint_list("AlwaysConnectedTechnologies");
	int i;
	for (i = 0; always_connected_techs && always_connected_techs[i]; i++)
		always_connect[always_connected_techs[i]] = 1;
}

static bool autoconnect_no_session_active(struct connman_service *service)
{
	/*
	 * Test active_count to see if there are no sessions set up and
	 * stop autoconnecting, but continue connecting if the service
	 * belongs to a technology which should always autoconnect.
	 */
	if (!active_count && !always_connect[service->type])
		return true;

	return false;
}

static bool autoconnect_already_connecting(struct connman_service *service,
					   bool autoconnecting)
{
	/*
	 * If another service is already connecting and this service type has
	 * not been marked as always connecting, stop the connecting procedure.
	 */
	if (autoconnecting &&
			!active_sessions[service->type] &&
			!always_connect[service->type])
		return true;

	return false;
}

static bool auto_connect_service(GList *services,
				enum connman_service_connect_reason reason,
				bool preferred)
{
	struct connman_service *service = NULL;
	bool ignore[MAX_CONNMAN_SERVICE_TYPES] = { };
	bool autoconnecting = false;
	GList *list;

	DBG("preferred %d sessions %d reason %s", preferred, active_count,
		reason2string(reason));

	ignore[CONNMAN_SERVICE_TYPE_VPN] = true;

#if defined TIZEN_EXT_WIFI_MESH
	/* Don't auto connect wifi if mesh interface is created */
	if (connman_mesh_is_interface_created())
		ignore[CONNMAN_SERVICE_TYPE_WIFI] = true;
#endif

	for (list = services; list; list = list->next) {
		service = list->data;

		if (ignore[service->type]) {
			DBG("service %p type %s ignore", service,
				__connman_service_type2string(service->type));
			continue;
		}

#if defined TIZEN_EXT
		DBG("service %p %s %s %s, favorite(%d), ignore(%d), hidden(%d, %d)",
				service, service->name,
				state2string(service->state),
				__connman_service_type2string(service->type),
				service->favorite, is_ignore(service),
				service->hidden, service->hidden_service);

		/* Tizen takes Wi-Fi as the highest priority into consideration. */
		if (service->type != CONNMAN_SERVICE_TYPE_WIFI)
			if (is_connecting(service->state) == TRUE || is_connected(service->state) == TRUE)
				continue;
#endif

		if (service->pending ||
				is_connecting(service->state) ||
				is_connected(service->state)) {
			if (autoconnect_no_session_active(service))
					return true;

			ignore[service->type] = true;
			autoconnecting = true;

			DBG("service %p type %s busy", service,
				__connman_service_type2string(service->type));

			continue;
		}

		if (!service->favorite) {
			if (preferred)
			       continue;

#if defined TIZEN_EXT
			DBG("Service is not favorite, autoconnecting %d",
					autoconnecting);
#endif
			return autoconnecting;
		}

#if defined TIZEN_EXT
		DBG("service %p identifier %s roaming %d ignore %d "
				"ipconfig_usable %d autoconnect %d state %d",
				service,
				service->identifier, service->roaming,
				service->ignore, is_ipconfig_usable(service),
				service->autoconnect, service->state);
#endif
		if (is_ignore(service) || service->state !=
				CONNMAN_SERVICE_STATE_IDLE)
			continue;

		if (autoconnect_already_connecting(service, autoconnecting)) {
			DBG("service %p type %s has no users", service,
				__connman_service_type2string(service->type));
			continue;
		}

		DBG("service %p %s %s", service, service->name,
			(preferred) ? "preferred" : reason2string(reason));

		__connman_service_connect(service, reason);

		if (autoconnect_no_session_active(service))
			return true;

		ignore[service->type] = true;
	}

	return autoconnecting;
}

static gboolean run_auto_connect(gpointer data)
{
	enum connman_service_connect_reason reason = GPOINTER_TO_UINT(data);
	bool autoconnecting = false;
	GList *preferred_tech;

	autoconnect_id = 0;

	DBG("");

	preferred_tech = preferred_tech_list_get();
	if (preferred_tech) {
		autoconnecting = auto_connect_service(preferred_tech, reason,
							true);
		g_list_free(preferred_tech);
	}

	if (!autoconnecting || active_count)
		auto_connect_service(service_list, reason, false);

	return FALSE;
}

#if defined TIZEN_EXT
bool __connman_service_get_auto_connect_mode(void)
{
	return auto_connect_mode;
}

void __connman_service_set_auto_connect_mode(bool enable)
{
	DBG("set auto_connect_mode = %d", enable);

	if (auto_connect_mode != enable)
		auto_connect_mode = enable;
}
#endif

void __connman_service_auto_connect(enum connman_service_connect_reason reason)
{
	DBG("");

	if (autoconnect_id != 0)
		return;

#if defined TIZEN_EXT
	if (auto_connect_mode == FALSE) {
		DBG("Currently, not auto connection mode");
		return;
	}
#endif

	if (!__connman_session_policy_autoconnect(reason))
		return;

#if defined TIZEN_EXT
	/* Adding Timeout of 500ms before trying to auto connect.
	 * This is done because of below scenario
	 * 1. Device is connected to AP1
	 * 2. WPS Connection request is initiated for AP2
	 * 3. Immediately WPS Connection is Cancelled
	 * When WPS Connection Connection is initiated for AP2 then
	 * sometimes there is a scenario where connman gets in ASSOCIATED
	 * state with AP1 due to autoconnect and subsequently the connection
	 * initiated by AP1 fails and connman service for AP1 comes in
	 * FAILURE state due to this when connection with AP2 is cancelled
	 * then autoconnect with AP1 doesn't works because its autoconnection
	 * is ignored as its last state was FAILURE rather than IDLE */
	autoconnect_id = g_timeout_add(500, run_auto_connect,
#else
	autoconnect_id = g_idle_add(run_auto_connect,
#endif
						GUINT_TO_POINTER(reason));
}

static gboolean run_vpn_auto_connect(gpointer data) {
	GList *list;
	bool need_split = false;

	vpn_autoconnect_id = 0;

	for (list = service_list; list; list = list->next) {
		struct connman_service *service = list->data;
		int res;

		if (service->type != CONNMAN_SERVICE_TYPE_VPN)
			continue;

		if (is_connected(service->state) ||
				is_connecting(service->state)) {
			if (!service->do_split_routing)
				need_split = true;
			continue;
		}

		if (is_ignore(service) || !service->favorite)
			continue;

		if (need_split && !service->do_split_routing) {
			DBG("service %p no split routing", service);
			continue;
		}

		DBG("service %p %s %s", service, service->name,
				service->do_split_routing ?
				"split routing" : "");

		res = __connman_service_connect(service,
				CONNMAN_SERVICE_CONNECT_REASON_AUTO);
		if (res < 0 && res != -EINPROGRESS)
			continue;

		if (!service->do_split_routing)
			need_split = true;
	}

	return FALSE;
}

static void vpn_auto_connect(void)
{
	if (vpn_autoconnect_id)
		return;

	vpn_autoconnect_id =
		g_idle_add(run_vpn_auto_connect, NULL);
}

bool
__connman_service_is_provider_pending(struct connman_service *service)
{
	if (!service)
		return false;

	if (service->provider_pending)
		return true;

	return false;
}

void __connman_service_set_provider_pending(struct connman_service *service,
							DBusMessage *msg)
{
	if (service->provider_pending) {
		DBG("service %p provider pending msg %p already exists",
			service, service->provider_pending);
		return;
	}

	service->provider_pending = msg;
}

static void check_pending_msg(struct connman_service *service)
{
	if (!service->pending)
		return;

	DBG("service %p pending msg %p already exists", service,
						service->pending);
	dbus_message_unref(service->pending);
}

void __connman_service_set_hidden_data(struct connman_service *service,
							gpointer user_data)
{
	DBusMessage *pending = user_data;

	DBG("service %p pending %p", service, pending);

	if (!pending)
		return;

	check_pending_msg(service);

	service->pending = pending;
}

void __connman_service_return_error(struct connman_service *service,
				int error, gpointer user_data)
{
	DBG("service %p error %d user_data %p", service, error, user_data);

	__connman_service_set_hidden_data(service, user_data);

	reply_pending(service, error);
}

static gboolean connect_timeout(gpointer user_data)
{
	struct connman_service *service = user_data;
	bool autoconnect = false;

	DBG("service %p", service);

	service->timeout = 0;

	if (service->network)
		__connman_network_disconnect(service->network);
	else if (service->provider)
		connman_provider_disconnect(service->provider);

	__connman_stats_service_unregister(service);

	if (service->pending) {
		DBusMessage *reply;

		reply = __connman_error_operation_timeout(service->pending);
		if (reply)
			g_dbus_send_message(connection, reply);

		dbus_message_unref(service->pending);
		service->pending = NULL;
	} else
		autoconnect = true;

	__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_FAILURE,
					CONNMAN_IPCONFIG_TYPE_IPV4);
	__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_FAILURE,
					CONNMAN_IPCONFIG_TYPE_IPV6);

	if (autoconnect &&
			service->connect_reason !=
				CONNMAN_SERVICE_CONNECT_REASON_USER)
		__connman_service_auto_connect(CONNMAN_SERVICE_CONNECT_REASON_AUTO);

	return FALSE;
}

static DBusMessage *connect_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
#if defined TIZEN_EXT
	int err = 0;
#else
	int index, err = 0;
	GList *list;
#endif

	DBG("service %p", service);

#if defined TIZEN_EXT
	/*
	 * Description: TIZEN implements system global connection management.
	 */
	if (service->type == CONNMAN_SERVICE_TYPE_CELLULAR)
		connman_service_user_pdn_connection_ref(service);

	/*Reset the Disconnect Reason while issue connect request*/
	service->disconnect_reason = 0;

	/*Reset the association status code while issue connect request*/
	service->assoc_status_code = 0;

	/* Reset the disconnection_requested while issue connect request*/
	connman_service_set_disconnection_requested(service, false);
#endif

	if (service->pending)
		return __connman_error_in_progress(msg);

#if !defined TIZEN_EXT
	index = __connman_service_get_index(service);

	for (list = service_list; list; list = list->next) {
		struct connman_service *temp = list->data;

#if defined TIZEN_EXT
		if (service->type == CONNMAN_SERVICE_TYPE_CELLULAR)
			break;
#endif
		if (!is_connecting(temp->state) && !is_connected(temp->state))
			break;

		if (service == temp)
			continue;

		if (service->type != temp->type)
			continue;

		if (__connman_service_get_index(temp) == index &&
				__connman_service_disconnect(temp) == -EINPROGRESS)
			err = -EINPROGRESS;

	}
	if (err == -EINPROGRESS)
		return __connman_error_operation_timeout(msg);
#endif

	service->ignore = false;

	service->pending = dbus_message_ref(msg);

	err = __connman_service_connect(service,
			CONNMAN_SERVICE_CONNECT_REASON_USER);

	if (err != -EINPROGRESS)
		reply_pending(service, -err);

	return NULL;
}

static DBusMessage *disconnect_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	int err;

	DBG("service %p", service);

#if defined TIZEN_EXT
	/*
	 * Description: TIZEN implements system global connection management.
	 */
	if (service->type == CONNMAN_SERVICE_TYPE_CELLULAR) {
		if (connman_service_user_pdn_connection_unref_and_test(service) != TRUE)
			return __connman_error_failed(msg, EISCONN);

		if (is_connected(service->state) == TRUE &&
				service == connman_service_get_default_connection())
			return __connman_error_failed(msg, EISCONN);
	}
#endif

	service->ignore = true;

	err = __connman_service_disconnect(service);
	if (err < 0 && err != -EINPROGRESS)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

#if defined TIZEN_EXT
static void __connman_service_cleanup_network_8021x(struct connman_service *service)
{
	if (service == NULL)
		return;

	DBG("service %p ", service);

	connman_network_set_string(service->network, "WiFi.EAP", NULL);
	connman_network_set_string(service->network, "WiFi.Identity", NULL);
	connman_network_set_string(service->network, "WiFi.CACertFile", NULL);
	connman_network_set_string(service->network, "WiFi.ClientCertFile", NULL);
	connman_network_set_string(service->network, "WiFi.PrivateKeyFile", NULL);
	connman_network_set_string(service->network, "WiFi.PrivateKeyPassphrase", NULL);
	connman_network_set_string(service->network, "WiFi.Phase2", NULL);
	connman_network_set_string(service->network, "WiFi.AnonymousIdentity", NULL);
}
static void __connman_service_cleanup_network_dpp(struct connman_service *service)
{
	if (service == NULL)
		return;

	DBG("service %p ", service);

	connman_network_set_string(service->network, "WiFi.Connector", NULL);
	connman_network_set_string(service->network, "WiFi.CSignKey", NULL);
	connman_network_set_string(service->network, "WiFi.NetAccessKey", NULL);
}
#endif

bool __connman_service_remove(struct connman_service *service)
{
	if (service->type == CONNMAN_SERVICE_TYPE_ETHERNET ||
			service->type == CONNMAN_SERVICE_TYPE_GADGET)
		return false;

	if (service->immutable || service->hidden ||
			__connman_provider_is_immutable(service->provider))
		return false;

#if !defined TIZEN_EXT
	if (!service->favorite && !is_idle(service->state))
		return false;
#endif

	__connman_service_disconnect(service);

	g_free(service->passphrase);
	service->passphrase = NULL;

	g_free(service->identity);
	service->identity = NULL;

	g_free(service->anonymous_identity);
	service->anonymous_identity = NULL;

	g_free(service->subject_match);
	service->subject_match = NULL;

	g_free(service->altsubject_match);
	service->altsubject_match = NULL;

	g_free(service->domain_suffix_match);
	service->domain_suffix_match = NULL;

	g_free(service->domain_match);
	service->domain_match = NULL;

	g_free(service->agent_identity);
	service->agent_identity = NULL;

	g_free(service->eap);
	service->eap = NULL;

#if defined TIZEN_EXT
	g_free(service->ca_cert_file);
	service->ca_cert_file = NULL;

	g_free(service->client_cert_file);
	service->client_cert_file = NULL;

	g_free(service->private_key_file);
	service->private_key_file = NULL;

	g_free(service->private_key_passphrase);
	service->private_key_passphrase = NULL;

	g_free(service->phase2);
	service->phase2 = NULL;

	__connman_service_cleanup_network_8021x(service);

	__connman_ipconfig_set_method(service->ipconfig_ipv4, CONNMAN_IPCONFIG_METHOD_DHCP);
	__connman_ipconfig_set_method(service->ipconfig_ipv6, CONNMAN_IPCONFIG_METHOD_AUTO);
	connman_service_set_proxy(service, NULL, false);

	__connman_service_nameserver_clear(service);

	g_strfreev(service->nameservers_config);
	service->nameservers_config = NULL;

	g_free(service->connector);
	service->connector = NULL;

	g_free(service->c_sign_key);
	service->c_sign_key = NULL;

	g_free(service->net_access_key);
	service->net_access_key = NULL;

	__connman_service_cleanup_network_dpp(service);
#endif

	service->error = CONNMAN_SERVICE_ERROR_UNKNOWN;

	__connman_service_set_favorite(service, false);

	__connman_ipconfig_ipv6_reset_privacy(service->ipconfig_ipv6);

#if defined TIZEN_EXT
	/* Reset IP Method and DNS Method to DHCP */
	__connman_ipconfig_set_method(service->ipconfig_ipv4,
			CONNMAN_IPCONFIG_METHOD_DHCP);
	service->dns_config_method_ipv4 = CONNMAN_DNSCONFIG_METHOD_DHCP;
	g_strfreev(service->nameservers_config);
	service->nameservers_config = NULL;
#endif

#if defined TIZEN_EXT
	__connman_storage_remove_service(service->identifier);
#else
	service_save(service);
#endif

	return true;
}

static DBusMessage *remove_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;

	DBG("service %p", service);

	if (!__connman_service_remove(service))
		return __connman_error_not_supported(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static bool check_suitable_state(enum connman_service_state a,
					enum connman_service_state b)
{
	/*
	 * Special check so that "ready" service can be moved before
	 * "online" one.
	 */
	if ((a == CONNMAN_SERVICE_STATE_ONLINE &&
			b == CONNMAN_SERVICE_STATE_READY) ||
		(b == CONNMAN_SERVICE_STATE_ONLINE &&
			a == CONNMAN_SERVICE_STATE_READY))
		return true;

	return a == b;
}

static void downgrade_state(struct connman_service *service)
{
	if (!service)
		return;

	DBG("service %p state4 %d state6 %d", service, service->state_ipv4,
						service->state_ipv6);

	if (service->state_ipv4 == CONNMAN_SERVICE_STATE_ONLINE)
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV4);

	if (service->state_ipv6 == CONNMAN_SERVICE_STATE_ONLINE)
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV6);
}

static void apply_relevant_default_downgrade(struct connman_service *service)
{
	struct connman_service *def_service;

	def_service = connman_service_get_default();
	if (!def_service)
		return;

	if (def_service == service &&
			def_service->state == CONNMAN_SERVICE_STATE_ONLINE) {
		def_service->state = CONNMAN_SERVICE_STATE_READY;
		__connman_notifier_leave_online(def_service->type);
		state_changed(def_service);
	}
}

static void switch_default_service(struct connman_service *default_service,
		struct connman_service *downgrade_service)
{
	struct connman_service *service;
	GList *src, *dst;

	apply_relevant_default_downgrade(default_service);
	src = g_list_find(service_list, downgrade_service);
	dst = g_list_find(service_list, default_service);

	/* Nothing to do */
	if (src == dst || src->next == dst)
		return;

	service = src->data;
	service_list = g_list_delete_link(service_list, src);
	service_list = g_list_insert_before(service_list, dst, service);

	downgrade_state(downgrade_service);
}

static struct _services_notify {
	int id;
	GHashTable *add;
	GHashTable *remove;
} *services_notify;


static void service_append_added_foreach(gpointer data, gpointer user_data)
{
	struct connman_service *service = data;
	DBusMessageIter *iter = user_data;

	if (!service || !service->path) {
		DBG("service %p or path is NULL", service);
		return;
	}

	if (g_hash_table_lookup(services_notify->add, service->path)) {
		DBG("new %s", service->path);

		append_struct(service, iter);
		g_hash_table_remove(services_notify->add, service->path);
	} else {
		DBG("changed %s", service->path);

		append_struct_service(iter, NULL, service);
	}
}

static void service_append_ordered(DBusMessageIter *iter, void *user_data)
{
	g_list_foreach(service_list, service_append_added_foreach, iter);
}

static void append_removed(gpointer key, gpointer value, gpointer user_data)
{
	char *objpath = key;
	DBusMessageIter *iter = user_data;

	DBG("removed %s", objpath);
	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &objpath);
}

static void service_append_removed(DBusMessageIter *iter, void *user_data)
{
	g_hash_table_foreach(services_notify->remove, append_removed, iter);
}

static gboolean service_send_changed(gpointer data)
{
	DBusMessage *signal;

	DBG("");

	services_notify->id = 0;

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "ServicesChanged");
	if (!signal)
		return FALSE;

	__connman_dbus_append_objpath_dict_array(signal,
					service_append_ordered, NULL);
	__connman_dbus_append_objpath_array(signal,
					service_append_removed, NULL);

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);

	g_hash_table_remove_all(services_notify->remove);
	g_hash_table_remove_all(services_notify->add);

	return FALSE;
}

static void service_schedule_changed(void)
{
	if (services_notify->id != 0)
		return;

	services_notify->id = g_timeout_add(100, service_send_changed, NULL);
}

static DBusMessage *move_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data,
								bool before)
{
	struct connman_service *service = user_data;
	struct connman_service *target;
	const char *path;
	enum connman_ipconfig_method target4, target6;
	enum connman_ipconfig_method service4, service6;

	DBG("service %p", service);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	if (!service->favorite)
		return __connman_error_not_supported(msg);

	target = find_service(path);
	if (!target || !target->favorite || target == service)
		return __connman_error_invalid_service(msg);

	if (target->type == CONNMAN_SERVICE_TYPE_VPN) {
		/*
		 * We only allow VPN route splitting if there are
		 * routes defined for a given VPN.
		 */
		if (!__connman_provider_check_routes(target->provider)) {
			connman_info("Cannot move service. "
				"No routes defined for provider %s",
				__connman_provider_get_ident(target->provider));
			return __connman_error_invalid_service(msg);
		}

		set_split_routing(target, true);
	} else
		set_split_routing(target, false);

	set_split_routing(service, false);

	target4 = __connman_ipconfig_get_method(target->ipconfig_ipv4);
	target6 = __connman_ipconfig_get_method(target->ipconfig_ipv6);
	service4 = __connman_ipconfig_get_method(service->ipconfig_ipv4);
	service6 = __connman_ipconfig_get_method(service->ipconfig_ipv6);

	DBG("target %s method %d/%d state %d/%d split %d", target->identifier,
		target4, target6, target->state_ipv4, target->state_ipv6,
		target->do_split_routing);

	DBG("service %s method %d/%d state %d/%d", service->identifier,
				service4, service6,
				service->state_ipv4, service->state_ipv6);

	/*
	 * If method is OFF, then we do not need to check the corresponding
	 * ipconfig state.
	 */
	if (target4 == CONNMAN_IPCONFIG_METHOD_OFF) {
		if (service6 != CONNMAN_IPCONFIG_METHOD_OFF) {
			if (!check_suitable_state(target->state_ipv6,
							service->state_ipv6))
				return __connman_error_invalid_service(msg);
		}
	}

	if (target6 == CONNMAN_IPCONFIG_METHOD_OFF) {
		if (service4 != CONNMAN_IPCONFIG_METHOD_OFF) {
			if (!check_suitable_state(target->state_ipv4,
							service->state_ipv4))
				return __connman_error_invalid_service(msg);
		}
	}

	if (service4 == CONNMAN_IPCONFIG_METHOD_OFF) {
		if (target6 != CONNMAN_IPCONFIG_METHOD_OFF) {
			if (!check_suitable_state(target->state_ipv6,
							service->state_ipv6))
				return __connman_error_invalid_service(msg);
		}
	}

	if (service6 == CONNMAN_IPCONFIG_METHOD_OFF) {
		if (target4 != CONNMAN_IPCONFIG_METHOD_OFF) {
			if (!check_suitable_state(target->state_ipv4,
							service->state_ipv4))
				return __connman_error_invalid_service(msg);
		}
	}

	g_get_current_time(&service->modified);
	service_save(service);
	service_save(target);

	/*
	 * If the service which goes down is the default service and is
	 * online, we downgrade directly its state to ready so:
	 * the service which goes up, needs to recompute its state which
	 * is triggered via downgrading it - if relevant - to state ready.
	 */
	if (before)
		switch_default_service(target, service);
	else
		switch_default_service(service, target);

	__connman_connection_update_gateway();

	service_schedule_changed();

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *move_before(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	return move_service(conn, msg, user_data, true);
}

static DBusMessage *move_after(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	return move_service(conn, msg, user_data, false);
}

static DBusMessage *reset_counters(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;

	reset_stats(service);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

#if defined TIZEN_MAINTAIN_ONLINE
static DBusMessage *downgrade_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;

	downgrade_state(service);
	__connman_connection_update_gateway();

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}
#endif

static void service_schedule_added(struct connman_service *service)
{
	DBG("service %p", service);

	g_hash_table_remove(services_notify->remove, service->path);
	g_hash_table_replace(services_notify->add, service->path, service);

	service_schedule_changed();
}

static void service_schedule_removed(struct connman_service *service)
{
	if (!service || !service->path) {
		DBG("service %p or path is NULL", service);
		return;
	}

	DBG("service %p %s", service, service->path);

	g_hash_table_remove(services_notify->add, service->path);
	g_hash_table_replace(services_notify->remove, g_strdup(service->path),
			NULL);

	service_schedule_changed();
}

static bool allow_property_changed(struct connman_service *service)
{
#if defined TIZEN_EXT
	if (service->path == NULL)
		return FALSE;
#endif
	if (g_hash_table_lookup_extended(services_notify->add, service->path,
					NULL, NULL))
		return false;

	return true;
}

static const GDBusMethodTable service_methods[] = {
	{ GDBUS_DEPRECATED_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_property) },
	{ GDBUS_METHOD("ClearProperty",
			GDBUS_ARGS({ "name", "s" }), NULL,
			clear_property) },
	{ GDBUS_ASYNC_METHOD("Connect", NULL, NULL,
			      connect_service) },
	{ GDBUS_METHOD("Disconnect", NULL, NULL,
			disconnect_service) },
	{ GDBUS_METHOD("Remove", NULL, NULL, remove_service) },
	{ GDBUS_METHOD("MoveBefore",
			GDBUS_ARGS({ "service", "o" }), NULL,
			move_before) },
	{ GDBUS_METHOD("MoveAfter",
			GDBUS_ARGS({ "service", "o" }), NULL,
			move_after) },
	{ GDBUS_METHOD("ResetCounters", NULL, NULL, reset_counters) },
#if defined TIZEN_MAINTAIN_ONLINE
	{ GDBUS_METHOD("Downgrade", NULL, NULL, downgrade_service) },
#endif
	{ },
};

static const GDBusSignalTable service_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ },
};

static void service_free(gpointer user_data)
{
	struct connman_service *service = user_data;
	char *path = service->path;

	DBG("service %p", service);

	reply_pending(service, ENOENT);

	if (service->nameservers_timeout) {
		g_source_remove(service->nameservers_timeout);
		dns_changed(service);
	}

	__connman_notifier_service_remove(service);
	service_schedule_removed(service);

	__connman_wispr_stop(service);
	stats_stop(service);

	service->path = NULL;

	if (path) {
		__connman_connection_update_gateway();

		g_dbus_unregister_interface(connection, path,
						CONNMAN_SERVICE_INTERFACE);
		g_free(path);
	}

	g_hash_table_destroy(service->counter_table);

	if (service->network) {
		__connman_network_disconnect(service->network);
		connman_network_unref(service->network);
		service->network = NULL;
	}

	if (service->provider)
		connman_provider_unref(service->provider);

	if (service->ipconfig_ipv4) {
		__connman_ipconfig_set_ops(service->ipconfig_ipv4, NULL);
		__connman_ipconfig_set_data(service->ipconfig_ipv4, NULL);
		__connman_ipconfig_unref(service->ipconfig_ipv4);
		service->ipconfig_ipv4 = NULL;
	}

	if (service->ipconfig_ipv6) {
		__connman_ipconfig_set_ops(service->ipconfig_ipv6, NULL);
		__connman_ipconfig_set_data(service->ipconfig_ipv6, NULL);
		__connman_ipconfig_unref(service->ipconfig_ipv6);
		service->ipconfig_ipv6 = NULL;
	}

	g_strfreev(service->timeservers);
	g_strfreev(service->timeservers_config);
	g_strfreev(service->nameservers);
	g_strfreev(service->nameservers_config);
	g_strfreev(service->nameservers_auto);
	g_strfreev(service->domains);
	g_strfreev(service->proxies);
	g_strfreev(service->excludes);

	g_free(service->hostname);
	g_free(service->domainname);
	g_free(service->pac);
	g_free(service->name);
	g_free(service->passphrase);
	g_free(service->identifier);
	g_free(service->eap);
	g_free(service->identity);
	g_free(service->anonymous_identity);
	g_free(service->agent_identity);
	g_free(service->ca_cert_file);
	g_free(service->subject_match);
	g_free(service->altsubject_match);
	g_free(service->domain_suffix_match);
	g_free(service->domain_match);
	g_free(service->client_cert_file);
	g_free(service->private_key_file);
	g_free(service->private_key_passphrase);
	g_free(service->phase2);
	g_free(service->config_file);
	g_free(service->config_entry);
#if defined TIZEN_EXT
	g_free(service->connector);
	g_free(service->c_sign_key);
	g_free(service->net_access_key);
#endif

	if (service->stats.timer)
		g_timer_destroy(service->stats.timer);
	if (service->stats_roaming.timer)
		g_timer_destroy(service->stats_roaming.timer);

	if (current_default == service)
		current_default = NULL;

	g_free(service);
}

static void stats_init(struct connman_service *service)
{
	/* home */
	service->stats.valid = false;
	service->stats.enabled = false;
	service->stats.timer = g_timer_new();

	/* roaming */
	service->stats_roaming.valid = false;
	service->stats_roaming.enabled = false;
	service->stats_roaming.timer = g_timer_new();
}

static void service_initialize(struct connman_service *service)
{
	DBG("service %p", service);

	service->refcount = 1;

	service->error = CONNMAN_SERVICE_ERROR_UNKNOWN;

	service->type     = CONNMAN_SERVICE_TYPE_UNKNOWN;
	service->security = CONNMAN_SERVICE_SECURITY_UNKNOWN;

	service->state = CONNMAN_SERVICE_STATE_UNKNOWN;
	service->state_ipv4 = CONNMAN_SERVICE_STATE_UNKNOWN;
	service->state_ipv6 = CONNMAN_SERVICE_STATE_UNKNOWN;

	service->favorite  = false;
	service->immutable = false;
	service->hidden = false;

	service->ignore = false;

	service->connect_reason = CONNMAN_SERVICE_CONNECT_REASON_NONE;

	service->order = 0;

	stats_init(service);

	service->provider = NULL;

	service->wps = false;
	service->wps_advertizing = false;
#if defined TIZEN_EXT
	memset(service->last_connected_bssid, 0, WIFI_BSSID_LEN_MAX);
	service->is_internet_connection = false;
	service->assoc_reject_count = 0;
#endif
#if defined TIZEN_EXT
	service->disconnection_requested = false;
	service->storage_reload = false;
	/*
	 * Description: TIZEN implements system global connection management.
	 */
	service->user_pdn_connection_refcount = 0;
	__sync_synchronize();
#endif
}

/**
 * connman_service_create:
 *
 * Allocate a new service.
 *
 * Returns: a newly-allocated #connman_service structure
 */
struct connman_service *connman_service_create(void)
{
	GSList *list;
	struct connman_stats_counter *counters;
	const char *counter;

	struct connman_service *service;

	service = g_try_new0(struct connman_service, 1);
	if (!service)
		return NULL;

	DBG("service %p", service);

	service->counter_table = g_hash_table_new_full(g_str_hash,
						g_str_equal, NULL, g_free);

	for (list = counter_list; list; list = list->next) {
		counter = list->data;

		counters = g_try_new0(struct connman_stats_counter, 1);
		if (!counters) {
			g_hash_table_destroy(service->counter_table);
			g_free(service);
			return NULL;
		}

		counters->append_all = true;

		g_hash_table_replace(service->counter_table, (gpointer)counter,
				counters);
	}

	service_initialize(service);

	return service;
}

/**
 * connman_service_ref:
 * @service: service structure
 *
 * Increase reference counter of service
 */
struct connman_service *
connman_service_ref_debug(struct connman_service *service,
			const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", service, service->refcount + 1,
		file, line, caller);

	__sync_fetch_and_add(&service->refcount, 1);

	return service;
}

/**
 * connman_service_unref:
 * @service: service structure
 *
 * Decrease reference counter of service and release service if no
 * longer needed.
 */
void connman_service_unref_debug(struct connman_service *service,
			const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", service, service->refcount - 1,
		file, line, caller);

	if (__sync_fetch_and_sub(&service->refcount, 1) != 1)
		return;

	service_list = g_list_remove(service_list, service);

	__connman_service_disconnect(service);

	g_hash_table_remove(service_hash, service->identifier);
}

#if defined TIZEN_EXT
static int calculate_score_last_user_selection(struct connman_service *service)
{
	int score = 0;
	struct connman_device *device;
	const char *last_user_selection_ident;
	time_t last_user_selection_time;
	unsigned int frequency;
	time_t curr_time;
	time_t ref_time;
	struct tm* ref_timeinfo;

	device = connman_network_get_device(service->network);
	last_user_selection_time = connman_device_get_last_user_selection_time(device);
	last_user_selection_ident = connman_device_get_last_user_selection_ident(device);
	frequency = connman_network_get_frequency(service->network);

	if (ins_settings.last_user_selection) {
		if (g_strcmp0(last_user_selection_ident, service->identifier) == 0 &&
			(((frequency >= FREQ_RANGE_24GHZ_CHANNEL_1 &&
			frequency <= FREQ_RANGE_24GHZ_CHANNEL_14) &&
			service->strength >= ins_settings.signal_level3_24ghz) ||
			((frequency >= FREQ_RANGE_5GHZ_CHANNEL_32 &&
			frequency <= FREQ_RANGE_5GHZ_CHANNEL_165) &&
			service->strength >= ins_settings.signal_level3_5ghz))) {

			/* Only events that occur within 8 hours are counted. */
			curr_time = time(NULL);
			ref_timeinfo = localtime(&curr_time);
			ref_timeinfo->tm_hour -= 8;
			ref_time = mktime(ref_timeinfo);

			if (last_user_selection_time > ref_time) {
				int time_diff = (curr_time - last_user_selection_time) / 60;
				int denominator = ins_settings.last_user_selection_time - time_diff;
				int numerator = ins_settings.last_user_selection_time /
									ins_settings.last_user_selection_score;
				int last_user_score = denominator / numerator;

				score += (last_user_score > ins_settings.last_user_selection_score ?
					ins_settings.last_user_selection_score : last_user_score);
			}
		}
	}

	return score;
}

static int calculate_score_last_connected(struct connman_service *service)
{
	int score = 0;
	struct connman_device *device;
	const char *last_connected_ident;
	unsigned int frequency;

	device = connman_network_get_device(service->network);
	last_connected_ident = connman_device_get_last_connected_ident(device);
	frequency = connman_network_get_frequency(service->network);

	if (g_strcmp0(last_connected_ident, service->identifier) == 0 &&
		(((frequency >= FREQ_RANGE_24GHZ_CHANNEL_1 &&
		frequency <= FREQ_RANGE_24GHZ_CHANNEL_14) &&
		service->strength >= ins_settings.signal_level3_24ghz) ||
		((frequency >= FREQ_RANGE_5GHZ_CHANNEL_32 &&
		frequency <= FREQ_RANGE_5GHZ_CHANNEL_165) &&
		service->strength >= ins_settings.signal_level3_5ghz))) {
		score += ins_settings.last_connected_score;
	}

	return score;
}

static int calculate_score_frequency(struct connman_service *service)
{
	int score = 0;
	unsigned int frequency;

	frequency = connman_network_get_frequency(service->network);

	switch (ins_settings.preferred_freq) {
	case CONNMAN_INS_PREFERRED_FREQ_24GHZ:
		if ((frequency >= FREQ_RANGE_24GHZ_CHANNEL_14 &&
			frequency <= FREQ_RANGE_24GHZ_CHANNEL_14) &&
			(service->strength >= ins_settings.signal_level3_24ghz))
			score += ins_settings.preferred_freq_score;

		break;
	case CONNMAN_INS_PREFERRED_FREQ_5GHZ:
		if ((frequency >= FREQ_RANGE_5GHZ_CHANNEL_32 &&
			frequency <= FREQ_RANGE_5GHZ_CHANNEL_165) &&
			(service->strength >= ins_settings.signal_level3_5ghz))
			score += ins_settings.preferred_freq_score;

		break;
	default:
		break;
	}

	return score;
}

static int calculate_score_security_priority(struct connman_service *service)
{
	int score = 0;

	if (ins_settings.security_priority_count)
		score += ins_settings.security_priority[service->security];

	return score;
}

static int calculate_score_internet_connection(struct connman_service *service)
{
	int score = 0;

	if (ins_settings.internet) {
		if (service->is_internet_connection)
			score += ins_settings.internet_score;
	}

	return score;
}

static int calculate_score_strength(struct connman_service *service)
{
	int score = 0;

	if (ins_settings.signal)
		score += (((service->strength > 60) ? 60 : service->strength) - 35);

	return score;
}

static int calculate_score(struct connman_service *service)
{
	int score = 0;

	if (service->type != CONNMAN_SERVICE_TYPE_WIFI) {
		score += calculate_score_internet_connection(service);
		service->ins_score = score;
		return score;
	}

	score += calculate_score_last_user_selection(service);
	score += calculate_score_last_connected(service);
	score += calculate_score_frequency(service);
	score += calculate_score_security_priority(service);
	score += calculate_score_internet_connection(service);
	score += calculate_score_strength(service);

	service->ins_score = score;
	return score;
}
#endif

static gint service_compare(gconstpointer a, gconstpointer b)
{
	struct connman_service *service_a = (void *) a;
	struct connman_service *service_b = (void *) b;
	enum connman_service_state state_a, state_b;
	bool a_connected, b_connected;
#if defined TIZEN_EXT
	int score_a;
	int score_b;
#else
	gint strength;
#endif

	state_a = service_a->state;
	state_b = service_b->state;
	a_connected = is_connected(state_a);
	b_connected = is_connected(state_b);

	if (a_connected && b_connected) {
		if (service_a->order > service_b->order)
			return -1;

		if (service_a->order < service_b->order)
			return 1;
	}

	if (state_a != state_b) {
		if (a_connected && b_connected) {
			/* We prefer online over ready state */
			if (state_a == CONNMAN_SERVICE_STATE_ONLINE)
				return -1;

			if (state_b == CONNMAN_SERVICE_STATE_ONLINE)
				return 1;
		}

		if (a_connected)
			return -1;
		if (b_connected)
			return 1;

		if (is_connecting(state_a))
			return -1;
		if (is_connecting(state_b))
			return 1;
	}

	if (service_a->favorite && !service_b->favorite)
		return -1;

	if (!service_a->favorite && service_b->favorite)
		return 1;

	if (service_a->type != service_b->type) {
		unsigned int *tech_array;
		int i;

		tech_array = connman_setting_get_uint_list(
						"PreferredTechnologies");
		if (tech_array) {
			for (i = 0; tech_array[i]; i++) {
				if (tech_array[i] == service_a->type)
					return -1;

				if (tech_array[i] == service_b->type)
					return 1;
			}
		}

		if (service_a->type == CONNMAN_SERVICE_TYPE_ETHERNET)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_ETHERNET)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_WIFI)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_WIFI)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_CELLULAR)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_CELLULAR)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_BLUETOOTH)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_BLUETOOTH)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_VPN)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_VPN)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_GADGET)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_GADGET)
			return 1;
	}

#if defined TIZEN_EXT
	score_a = calculate_score(service_a);
	score_b = calculate_score(service_b);
	if (score_b != score_a)
		return score_b - score_a;
#else
	strength = (gint) service_b->strength - (gint) service_a->strength;
	if (strength)
		return strength;
#endif

	return g_strcmp0(service_a->name, service_b->name);
}

#if defined TIZEN_EXT_INS
static void print_service_sort(gpointer data, gpointer user_data)
{
	struct connman_service *service = data;
	struct connman_device *device;
	const char *last_user_selection_ident;
	const char *last_connected_ident;
	unsigned int frequency;
	time_t ref_time;
	struct tm* timeinfo;
	time_t last_user_selection_time;

	device = connman_network_get_device(service->network);
	last_user_selection_ident = connman_device_get_last_user_selection_ident(device);
	last_user_selection_time = connman_device_get_last_user_selection_time(device);
	last_connected_ident = connman_device_get_last_connected_ident(device);
	frequency = connman_network_get_frequency(service->network);

	/* Only events that occur within 8 hours are checked. */
	ref_time = time(NULL);
	timeinfo = localtime(&ref_time);
	timeinfo->tm_hour -= 8;
	ref_time = mktime(timeinfo);

	DBG("name[%s] score[%d] strength[%d] freq[%d] last_usr[%d] last_conn[%d] internet[%d]",
		service->name, service->ins_score, service->strength, frequency,
		(g_strcmp0(last_user_selection_ident, service->identifier) == 0 &&
		last_user_selection_time > ref_time) ? 1 : 0,
		g_strcmp0(last_connected_ident, service->identifier) == 0 ? 1 : 0,
		service->is_internet_connection);
}
#endif

static void service_list_sort(void)
{
	if (service_list && service_list->next) {
		service_list = g_list_sort(service_list, service_compare);
#if defined TIZEN_EXT_INS
		g_list_foreach(service_list, print_service_sort, NULL);
#endif
		service_schedule_changed();
	}
}

int __connman_service_compare(const struct connman_service *a,
					const struct connman_service *b)
{
	return service_compare(a, b);
}

/**
 * connman_service_get_type:
 * @service: service structure
 *
 * Get the type of service
 */
enum connman_service_type connman_service_get_type(struct connman_service *service)
{
	if (!service)
		return CONNMAN_SERVICE_TYPE_UNKNOWN;

	return service->type;
}

/**
 * connman_service_get_interface:
 * @service: service structure
 *
 * Get network interface of service
 */
char *connman_service_get_interface(struct connman_service *service)
{
	int index;

	if (!service)
		return NULL;

	index = __connman_service_get_index(service);

	return connman_inet_ifname(index);
}

/**
 * connman_service_get_network:
 * @service: service structure
 *
 * Get the service network
 */
struct connman_network *
__connman_service_get_network(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->network;
}

struct connman_ipconfig *
__connman_service_get_ip4config(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->ipconfig_ipv4;
}

struct connman_ipconfig *
__connman_service_get_ip6config(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->ipconfig_ipv6;
}

struct connman_ipconfig *
__connman_service_get_ipconfig(struct connman_service *service, int family)
{
	if (family == AF_INET)
		return __connman_service_get_ip4config(service);
	else if (family == AF_INET6)
		return __connman_service_get_ip6config(service);
	else
		return NULL;

}

bool __connman_service_is_connected_state(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	if (!service)
		return false;

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		break;
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		return is_connected(service->state_ipv4);
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		return is_connected(service->state_ipv6);
	case CONNMAN_IPCONFIG_TYPE_ALL:
		return is_connected(service->state_ipv4) &&
			is_connected(service->state_ipv6);
	}

	return false;
}
enum connman_service_security __connman_service_get_security(
				struct connman_service *service)
{
	if (!service)
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;

	return service->security;
}

const char *__connman_service_get_phase2(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->phase2;
}

bool __connman_service_wps_enabled(struct connman_service *service)
{
	if (!service)
		return false;

	return service->wps;
}

void __connman_service_mark_dirty(void)
{
	services_dirty = true;
}

#if defined TIZEN_EXT
/**
  * Returns profile count if there is any connected profiles
  * that use same interface
  */
int __connman_service_get_connected_count_of_iface(
					struct connman_service *service)
{
	GList *list;
	int count = 0;
	int index1 = 0;
	int index2 = 0;

	DBG("");

	index1 = __connman_service_get_index(service);

	if (index1 <= 0)
		return 0;

	for (list = service_list; list; list = list->next) {
		struct connman_service *service2 = list->data;

		if (service == service2)
			continue;

		index2 = __connman_service_get_index(service2);

		if (is_connected(service2->state) && index2 > 0 && index1 == index2)
			count++;

		index2 = 0;
	}

	DBG("Interface index %d, count %d", index1, count);

	return count;
}

void __connman_service_set_storage_reload(struct connman_service *service,
					bool storage_reload)
{
	if (service != NULL)
		service->storage_reload = storage_reload;
}
#endif

/**
 * __connman_service_set_favorite_delayed:
 * @service: service structure
 * @favorite: favorite value
 * @delay_ordering: do not order service sequence
 *
 * Change the favorite setting of service
 */
int __connman_service_set_favorite_delayed(struct connman_service *service,
					bool favorite,
					bool delay_ordering)
{
#if defined TIZEN_EXT
	if (service->type == CONNMAN_SERVICE_TYPE_CELLULAR)
		return -EIO;
#endif
	if (service->hidden)
		return -EOPNOTSUPP;

	if (service->favorite == favorite)
		return -EALREADY;

	service->favorite = favorite;

	favorite_changed(service);

	if (!delay_ordering) {

		service_list_sort();

		__connman_connection_update_gateway();
	}

	return 0;
}

/**
 * __connman_service_set_favorite:
 * @service: service structure
 * @favorite: favorite value
 *
 * Change the favorite setting of service
 */
int __connman_service_set_favorite(struct connman_service *service,
						bool favorite)
{
	return __connman_service_set_favorite_delayed(service, favorite,
							false);
}

bool connman_service_get_favorite(struct connman_service *service)
{
	return service->favorite;
}

bool connman_service_get_autoconnect(struct connman_service *service)
{
	return service->autoconnect;
}

int __connman_service_set_immutable(struct connman_service *service,
						bool immutable)
{
	if (service->hidden)
		return -EOPNOTSUPP;

	if (service->immutable == immutable)
		return 0;

	service->immutable = immutable;

	immutable_changed(service);

	return 0;
}

int __connman_service_set_ignore(struct connman_service *service,
						bool ignore)
{
	if (!service)
		return -EINVAL;

	service->ignore = ignore;

	return 0;
}

void __connman_service_set_string(struct connman_service *service,
				  const char *key, const char *value)
{
	if (service->hidden)
		return;
	if (g_str_equal(key, "EAP")) {
		g_free(service->eap);
		service->eap = g_strdup(value);
	} else if (g_str_equal(key, "Identity")) {
		g_free(service->identity);
		service->identity = g_strdup(value);
	} else if (g_str_equal(key, "AnonymousIdentity")) {
		g_free(service->anonymous_identity);
		service->anonymous_identity = g_strdup(value);
	} else if (g_str_equal(key, "CACertFile")) {
		g_free(service->ca_cert_file);
		service->ca_cert_file = g_strdup(value);
	} else if (g_str_equal(key, "SubjectMatch")) {
		g_free(service->subject_match);
		service->subject_match = g_strdup(value);
	} else if (g_str_equal(key, "AltSubjectMatch")) {
		g_free(service->altsubject_match);
		service->altsubject_match = g_strdup(value);
	} else if (g_str_equal(key, "DomainSuffixMatch")) {
		g_free(service->domain_suffix_match);
		service->domain_suffix_match = g_strdup(value);
	} else if (g_str_equal(key, "DomainMatch")) {
		g_free(service->domain_match);
		service->domain_match = g_strdup(value);
	} else if (g_str_equal(key, "ClientCertFile")) {
		g_free(service->client_cert_file);
		service->client_cert_file = g_strdup(value);
	} else if (g_str_equal(key, "PrivateKeyFile")) {
		g_free(service->private_key_file);
		service->private_key_file = g_strdup(value);
	} else if (g_str_equal(key, "PrivateKeyPassphrase")) {
		g_free(service->private_key_passphrase);
		service->private_key_passphrase = g_strdup(value);
	} else if (g_str_equal(key, "Phase2")) {
		g_free(service->phase2);
		service->phase2 = g_strdup(value);
	} else if (g_str_equal(key, "Passphrase"))
		__connman_service_set_passphrase(service, value);
#if defined TIZEN_EXT
	 else if (g_str_equal(key, "Connector")) {
		g_free(service->connector);
		service->connector = g_strdup(value);
	 }	else if (g_str_equal(key, "CSignKey")) {
		g_free(service->c_sign_key);
		service->c_sign_key = g_strdup(value);
	 }	else if (g_str_equal(key, "NetAccessKey")) {
		g_free(service->net_access_key);
		service->net_access_key = g_strdup(value);
	} else
		DBG("Unknown key: %s", key);
#endif
}

void __connman_service_set_search_domains(struct connman_service *service,
					char **domains)
{
	searchdomain_remove_all(service);

	if (service->domains)
		g_strfreev(service->domains);

	service->domains = g_strdupv(domains);

	searchdomain_add_all(service);
}

int __connman_service_set_mdns(struct connman_service *service,
			bool enabled)
{
	service->mdns_config = enabled;

	return set_mdns(service, enabled);
}

static void report_error_cb(void *user_context, bool retry,
							void *user_data)
{
	struct connman_service *service = user_context;

	if (retry)
		__connman_service_connect(service,
					CONNMAN_SERVICE_CONNECT_REASON_USER);
	else {
		/* It is not relevant to stay on Failure state
		 * when failing is due to wrong user input */
		__connman_service_clear_error(service);
#if defined TIZEN_EXT
		/* Reseting the state back in case of failure state */
		service->state_ipv4 = service->state_ipv6 =
				CONNMAN_SERVICE_STATE_IDLE;

		if (service->error != CONNMAN_SERVICE_ERROR_AUTH_FAILED)
			set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);
#endif
		service_complete(service);
		__connman_connection_update_gateway();
	}
}

static int check_wpspin(struct connman_service *service, const char *wpspin)
{
	int length;
	guint i;

	if (!wpspin)
		return 0;

	length = strlen(wpspin);

	/* If 0, it will mean user wants to use PBC method */
	if (length == 0) {
		connman_network_set_string(service->network,
							"WiFi.PinWPS", NULL);
		return 0;
	}

	/* A WPS PIN is always 8 chars length,
	 * its content is in digit representation.
	 */
	if (length != 8)
		return -ENOKEY;

	for (i = 0; i < 8; i++)
		if (!isdigit((unsigned char) wpspin[i]))
			return -ENOKEY;

	connman_network_set_string(service->network, "WiFi.PinWPS", wpspin);

	return 0;
}

static void request_input_cb(struct connman_service *service,
			bool values_received,
			const char *name, int name_len,
			const char *identity, const char *passphrase,
			bool wps, const char *wpspin,
			const char *error, void *user_data)
{
	struct connman_device *device;
	const char *security;
	int err = 0;

	DBG("RequestInput return, %p", service);

	if (error) {
		DBG("error: %s", error);

		if (g_strcmp0(error,
				"net.connman.Agent.Error.Canceled") == 0) {
			err = -ECONNABORTED;

			if (service->hidden)
				__connman_service_return_error(service,
							ECONNABORTED,
							user_data);
			goto done;
		} else {
			if (service->hidden)
				__connman_service_return_error(service,
							ETIMEDOUT, user_data);
		}
	}

	if (service->hidden && name_len > 0 && name_len <= 32) {
		device = connman_network_get_device(service->network);
		security = connman_network_get_string(service->network,
							"WiFi.Security");
		err = __connman_device_request_hidden_scan(device,
						name, name_len,
						identity, passphrase,
						security, user_data);
		if (err < 0)
			__connman_service_return_error(service,	-err,
							user_data);
	}

	if (!values_received || service->hidden) {
		err = -EINVAL;
		goto done;
	}

	if (wps && service->network) {
		err = check_wpspin(service, wpspin);
		if (err < 0)
			goto done;

		connman_network_set_bool(service->network, "WiFi.UseWPS", wps);
	}

	if (identity)
		__connman_service_set_agent_identity(service, identity);

	if (passphrase)
		err = __connman_service_set_passphrase(service, passphrase);

 done:
	if (err >= 0) {
		/* We forget any previous error. */
		set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);

		__connman_service_connect(service,
					CONNMAN_SERVICE_CONNECT_REASON_USER);

	} else if (err == -ENOKEY) {
		__connman_service_indicate_error(service,
					CONNMAN_SERVICE_ERROR_INVALID_KEY);
	} else {
		/* It is not relevant to stay on Failure state
		 * when failing is due to wrong user input */
		service->state = CONNMAN_SERVICE_STATE_IDLE;

		if (!service->hidden) {
			/*
			 * If there was a real error when requesting
			 * hidden scan, then that error is returned already
			 * to the user somewhere above so do not try to
			 * do this again.
			 */
			__connman_service_return_error(service,	-err,
							user_data);
		}

		service_complete(service);
		__connman_connection_update_gateway();
	}
}

static void downgrade_connected_services(void)
{
	struct connman_service *up_service;
	GList *list;

	for (list = service_list; list; list = list->next) {
		up_service = list->data;

		if (!is_connected(up_service->state))
			continue;

		if (up_service->state == CONNMAN_SERVICE_STATE_ONLINE)
			return;

		downgrade_state(up_service);
	}
}

static int service_update_preferred_order(struct connman_service *default_service,
		struct connman_service *new_service,
		enum connman_service_state new_state)
{
	unsigned int *tech_array;
	int i;

	if (!default_service || default_service == new_service ||
			default_service->state != new_state)
		return 0;

	tech_array = connman_setting_get_uint_list("PreferredTechnologies");
	if (tech_array) {

		for (i = 0; tech_array[i] != 0; i += 1) {
			if (default_service->type == tech_array[i])
				return -EALREADY;

			if (new_service->type == tech_array[i]) {
				switch_default_service(default_service,
						new_service);
				__connman_connection_update_gateway();
				return 0;
			}
		}
	}

	return -EALREADY;
}

#if defined TIZEN_EXT
static gboolean __connman_service_can_drop(struct connman_service *service)
{
	if (is_connected(service->state) == TRUE || is_connecting(service->state) == TRUE) {
		if (service->type != CONNMAN_SERVICE_TYPE_CELLULAR)
			return TRUE;
		else if (connman_service_is_no_ref_user_pdn_connection(service) == TRUE)
			return TRUE;
	}
	return FALSE;
}

static struct connman_device *default_connecting_device = NULL;

static void __connman_service_disconnect_default(struct connman_service *service)
{
	struct connman_device *default_device = NULL;

	if (default_connecting_device == NULL)
		return;

	default_device = connman_network_get_device(
			__connman_service_get_network(service));

	DBG("Disconnecting service %p %s", service, service->path);
	DBG("Disconnecting device %p %p %s",
			default_connecting_device,
			default_device,
			connman_device_get_string(default_device, "Name"));

	if (default_connecting_device == default_device)
		default_connecting_device = NULL;
}

#if defined TIZEN_MAINTAIN_ONLINE
static void __connman_service_connect_default(struct connman_service *current,
								  enum connman_service_state old_state)
#else
static void __connman_service_connect_default(struct connman_service *current)
#endif
{
	int err;
	GList *list;
	bool default_internet;
	struct connman_service *service;
	struct connman_service *default_service = NULL;
	struct connman_device *default_device = NULL;

	if (current->type == CONNMAN_SERVICE_TYPE_CELLULAR) {
		switch (current->state) {
		case CONNMAN_SERVICE_STATE_UNKNOWN:
		case CONNMAN_SERVICE_STATE_ASSOCIATION:
		case CONNMAN_SERVICE_STATE_CONFIGURATION:
			return;
		default:
			break;
		}

		if (default_connecting_device &&
				__connman_service_is_internet_profile(current) == TRUE) {
			if (current->network == NULL)
				return;

			default_device = connman_network_get_device(current->network);
			if (default_connecting_device == default_device) {
				DBG("Cellular service[%s]  %p %s",
						state2string(current->state), current, current->path);
				DBG("Cellular device %p %p %s",
						default_connecting_device, default_device,
						connman_device_get_string(default_device, "Name"));

				default_connecting_device = NULL;
			}
		}

		return;
#if defined TIZEN_MAINTAIN_ONLINE
	} else if (current->state == CONNMAN_SERVICE_STATE_READY &&
			   old_state == CONNMAN_SERVICE_STATE_ONLINE) {
		DBG("Device is downgraded: online --> ready");
#endif
	} else if (is_connected(current->state) == TRUE || is_connecting(current->state) == TRUE)
		return;

	/* Always-on: keep default cellular connection as possible */
	for (list = service_list; list; list = list->next) {
		service = list->data;

		if (service->type != CONNMAN_SERVICE_TYPE_CELLULAR ||
				__connman_service_is_internet_profile(service) != TRUE ||
				service->network == NULL) {
			continue;
		}

		default_internet =
				connman_network_get_bool(service->network, "DefaultInternet");

		DBG("service: %p %s %s %s (default: %d)", service, service->name,
				__connman_service_type2string(service->type),
				state2string(service->state), default_internet);

		if (default_internet) {
			default_service = service;
			if (is_connected(default_service->state) == TRUE ||
					is_connecting(default_service->state) == TRUE)
				return;

			default_device = connman_network_get_device(default_service->network);
			if (default_connecting_device == default_device) {
				DBG("Device is connecting (%p)", default_connecting_device);
				return;
			}

			default_connecting_device = default_device;
			default_service->connect_reason = CONNMAN_SERVICE_CONNECT_REASON_USER;

			err = __connman_network_connect(default_service->network);
			DBG("Connecting default service %p %s [%d]",
					default_service, default_service->path, err);
			DBG("Connecting device %p %s", default_connecting_device,
					connman_device_get_string(default_connecting_device, "Name"));
			if (err < 0 && err != -EINPROGRESS) {
				default_connecting_device = NULL;
			} else
				break;
		}
	}
}
#endif

static void single_connected_tech(struct connman_service *allowed)
{
	struct connman_service *service;
	GSList *services = NULL, *list;
	GList *iter;

	DBG("keeping %p %s", allowed, allowed->path);

#if defined TIZEN_EXT
	if (!allowed || allowed->type == CONNMAN_SERVICE_TYPE_CELLULAR)
		return;
#endif

	for (iter = service_list; iter; iter = iter->next) {
		service = iter->data;

#if defined TIZEN_EXT
		if (service != allowed && service->type != allowed->type &&
				__connman_service_can_drop(service) == TRUE)
#else
		if (!is_connected(service->state))
			break;

		if (service == allowed)
			continue;
#endif

		services = g_slist_prepend(services, service);
	}

	for (list = services; list; list = list->next) {
		service = list->data;

		DBG("disconnecting %p %s", service, service->path);
#if defined TIZEN_EXT
		__connman_service_disconnect_default(service);
#endif
		__connman_service_disconnect(service);
	}

	g_slist_free(services);
}

#if defined TIZEN_EXT
static void set_priority_connected_service(void)
{
	struct connman_service *service;
	GList *list;

	for (list = service_list; list; list = list->next) {
		service = list->data;

		if (is_connected(service->state) == FALSE)
			service->order = 5;
		else
#if defined TIZEN_MAINTAIN_ONLINE
		{
			if (service->type == CONNMAN_SERVICE_TYPE_WIFI &&
				service->state == CONNMAN_SERVICE_STATE_ONLINE)
				service->order = 6;
			else if (service->type != CONNMAN_SERVICE_TYPE_WIFI)
				service->order = 6;
			else
				service->order = 5;
		}
#else
			service->order = 6;
#endif
	}
}
#endif

static const char *get_dbus_sender(struct connman_service *service)
{
	if (!service->pending)
		return NULL;

	return dbus_message_get_sender(service->pending);
}

static int service_indicate_state(struct connman_service *service)
{
	enum connman_service_state old_state, new_state;
	struct connman_service *def_service;
	enum connman_ipconfig_method method;
	int result;

	if (!service)
		return -EINVAL;

	old_state = service->state;
	new_state = combine_state(service->state_ipv4, service->state_ipv6);

	DBG("service %p old %s - new %s/%s => %s",
					service,
					state2string(old_state),
					state2string(service->state_ipv4),
					state2string(service->state_ipv6),
					state2string(new_state));

	if (old_state == new_state)
		return -EALREADY;

	def_service = connman_service_get_default();

	if (new_state == CONNMAN_SERVICE_STATE_ONLINE) {
		result = service_update_preferred_order(def_service,
				service, new_state);
		if (result == -EALREADY)
			return result;
	}

	if (old_state == CONNMAN_SERVICE_STATE_ONLINE)
		__connman_notifier_leave_online(service->type);

	if (is_connected(old_state) && !is_connected(new_state))
		searchdomain_remove_all(service);

	service->state = new_state;
	state_changed(service);

	if (!is_connected(old_state) && is_connected(new_state))
		searchdomain_add_all(service);

	switch(new_state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:

		break;

	case CONNMAN_SERVICE_STATE_IDLE:
		if (old_state != CONNMAN_SERVICE_STATE_DISCONNECT)
			__connman_service_disconnect(service);

		break;

	case CONNMAN_SERVICE_STATE_ASSOCIATION:

		break;

	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		if (!service->new_service &&
				__connman_stats_service_register(service) == 0) {
			/*
			 * For new services the statistics are updated after
			 * we have successfully connected.
			 */
			__connman_stats_get(service, false,
						&service->stats.data);
			__connman_stats_get(service, true,
						&service->stats_roaming.data);
		}

		break;

	case CONNMAN_SERVICE_STATE_READY:
		set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);

		if (service->new_service &&
				__connman_stats_service_register(service) == 0) {
			/*
			 * This is normally done after configuring state
			 * but for new service do this after we have connected
			 * successfully.
			 */
			__connman_stats_get(service, false,
						&service->stats.data);
			__connman_stats_get(service, true,
						&service->stats_roaming.data);
		}

		service->new_service = false;

		default_changed();

		def_service = connman_service_get_default();

		service_update_preferred_order(def_service, service, new_state);

		__connman_service_set_favorite(service, true);

		reply_pending(service, 0);

		if (service->type == CONNMAN_SERVICE_TYPE_WIFI &&
			connman_network_get_bool(service->network,
						"WiFi.UseWPS")) {
			const char *pass;

			pass = connman_network_get_string(service->network,
							"WiFi.Passphrase");

			__connman_service_set_passphrase(service, pass);

			connman_network_set_bool(service->network,
							"WiFi.UseWPS", false);
		}

		g_get_current_time(&service->modified);
		service_save(service);

		domain_changed(service);
		proxy_changed(service);

		if (old_state != CONNMAN_SERVICE_STATE_ONLINE)
			__connman_notifier_connect(service->type);

		method = __connman_ipconfig_get_method(service->ipconfig_ipv6);
		if (method == CONNMAN_IPCONFIG_METHOD_OFF)
			__connman_ipconfig_disable_ipv6(
						service->ipconfig_ipv6);

#if !defined TIZEN_MAINTAIN_ONLINE
		if (connman_setting_get_bool("SingleConnectedTechnology"))
			single_connected_tech(service);
		else if (service->type != CONNMAN_SERVICE_TYPE_VPN)
			vpn_auto_connect();
#else
		if (service->type != CONNMAN_SERVICE_TYPE_VPN)
			vpn_auto_connect();
#endif

#if defined TIZEN_EXT
		if (service->type == CONNMAN_SERVICE_TYPE_WIFI)
			set_priority_connected_service();
#endif

		break;

	case CONNMAN_SERVICE_STATE_ONLINE:
#if defined TIZEN_MAINTAIN_ONLINE
#if defined TIZEN_EXT
		if (service->type == CONNMAN_SERVICE_TYPE_WIFI)
			set_priority_connected_service();
#endif

		if (connman_setting_get_bool("SingleConnectedTechnology"))
			single_connected_tech(service);
#endif

#if defined TIZEN_EXT
		if (service->type == CONNMAN_SERVICE_TYPE_WIFI)
			connman_service_set_internet_connection(service, true);
#endif
		break;

	case CONNMAN_SERVICE_STATE_DISCONNECT:
		set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);

		reply_pending(service, ECONNABORTED);

		default_changed();

		__connman_wispr_stop(service);

		__connman_wpad_stop(service);

#if defined TIZEN_EXT
		/**
		 * Skip the functions if there is any connected profiles
		 * that use same interface
		 */
		if (service->type != CONNMAN_SERVICE_TYPE_CELLULAR ||
			__connman_service_get_connected_count_of_iface(
							service) <= 0) {
#endif
		domain_changed(service);
		proxy_changed(service);
#if defined TIZEN_EXT
		}
#endif

		/*
		 * Previous services which are connected and which states
		 * are set to online should reset relevantly ipconfig_state
		 * to ready so wispr/portal will be rerun on those
		 */
		downgrade_connected_services();

		__connman_service_auto_connect(CONNMAN_SERVICE_CONNECT_REASON_AUTO);
		break;

	case CONNMAN_SERVICE_STATE_FAILURE:
#if defined TIZEN_EXT
		if (service->type == CONNMAN_SERVICE_TYPE_WIFI)
			service->order = 5;
		__connman_service_auto_connect(CONNMAN_SERVICE_CONNECT_REASON_AUTO);
#endif
		if (service->connect_reason == CONNMAN_SERVICE_CONNECT_REASON_USER) {
			connman_agent_report_error(service, service->path,
						error2string(service->error),
						report_error_cb,
						get_dbus_sender(service),
						NULL);
		}
		service_complete(service);
		break;
	}

	service_list_sort();

#if defined TIZEN_EXT
#if defined TIZEN_MAINTAIN_ONLINE
	__connman_service_connect_default(service, old_state);
#else
	__connman_service_connect_default(service);
#endif
#endif

	__connman_connection_update_gateway();

	if ((old_state == CONNMAN_SERVICE_STATE_ONLINE &&
			new_state != CONNMAN_SERVICE_STATE_READY) ||
		(old_state == CONNMAN_SERVICE_STATE_READY &&
			new_state != CONNMAN_SERVICE_STATE_ONLINE)) {
		__connman_notifier_disconnect(service->type);
	}

	if (new_state == CONNMAN_SERVICE_STATE_ONLINE) {
		__connman_notifier_enter_online(service->type);
		default_changed();
	}

	return 0;
}

int __connman_service_indicate_error(struct connman_service *service,
					enum connman_service_error error)
{
	DBG("service %p error %d", service, error);

	if (!service)
		return -EINVAL;

	if (service->state == CONNMAN_SERVICE_STATE_FAILURE)
		return -EALREADY;

	set_error(service, error);

/* default internet service: fix not cleared if pdp activation*/
#if defined TIZEN_EXT
		/*
		 * If connection failed for default service(DefaultInternet),
		 * default_connecting_device should be cleared.
		 */
		if (service->type == CONNMAN_SERVICE_TYPE_CELLULAR &&
				service->error == CONNMAN_SERVICE_ERROR_CONNECT_FAILED)
			__connman_service_disconnect_default(service);

		if (service->type == CONNMAN_SERVICE_TYPE_WIFI &&
				service->error == CONNMAN_SERVICE_ERROR_INVALID_KEY) {
			g_free(service->passphrase);
			service->passphrase = NULL;
		}
#endif

	__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_FAILURE,
						CONNMAN_IPCONFIG_TYPE_IPV4);
	__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_FAILURE,
						CONNMAN_IPCONFIG_TYPE_IPV6);
	return 0;
}

int __connman_service_clear_error(struct connman_service *service)
{
	DBusMessage *pending, *provider_pending;

	DBG("service %p", service);

	if (!service)
		return -EINVAL;

	if (service->state != CONNMAN_SERVICE_STATE_FAILURE)
		return -EINVAL;

	pending = service->pending;
	service->pending = NULL;
	provider_pending = service->provider_pending;
	service->provider_pending = NULL;

	__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_IDLE,
						CONNMAN_IPCONFIG_TYPE_IPV6);

	__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_IDLE,
						CONNMAN_IPCONFIG_TYPE_IPV4);

	service->pending = pending;
	service->provider_pending = provider_pending;

	return 0;
}

int __connman_service_indicate_default(struct connman_service *service)
{
	DBG("service %p state %s", service, state2string(service->state));

	if (!is_connected(service->state)) {
		/*
		 * If service is not yet fully connected, then we must not
		 * change the default yet. The default gw will be changed
		 * after the service state is in ready.
		 */
		return -EINPROGRESS;
	}

	default_changed();

	return 0;
}

enum connman_service_state __connman_service_ipconfig_get_state(
					struct connman_service *service,
					enum connman_ipconfig_type type)
{
	if (!service)
		return CONNMAN_SERVICE_STATE_UNKNOWN;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		return service->state_ipv4;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		return service->state_ipv6;

	return CONNMAN_SERVICE_STATE_UNKNOWN;
}

static void check_proxy_setup(struct connman_service *service)
{
	/*
	 * We start WPAD if we haven't got a PAC URL from DHCP and
	 * if our proxy manual configuration is either empty or set
	 * to AUTO with an empty URL.
	 */

	if (service->proxy != CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN)
		goto done;

	if (service->proxy_config != CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN &&
		(service->proxy_config != CONNMAN_SERVICE_PROXY_METHOD_AUTO ||
			service->pac))
		goto done;

	if (__connman_wpad_start(service) < 0) {
		service->proxy = CONNMAN_SERVICE_PROXY_METHOD_DIRECT;
		__connman_notifier_proxy_changed(service);
		goto done;
	}

	return;

done:
	__connman_service_wispr_start(service, CONNMAN_IPCONFIG_TYPE_IPV4);
}

#if defined TIZEN_EXT
void connman_check_proxy_setup_and_wispr_start(struct connman_service *service){

	DBG("check the proxy and start wispr");
	check_proxy_setup(service);
	return;
}
#endif

/*
 * How many networks are connected at the same time. If more than 1,
 * then set the rp_filter setting properly (loose mode routing) so that network
 * connectivity works ok. This is only done for IPv4 networks as IPv6
 * does not have rp_filter knob.
 */
static int connected_networks_count;
static int original_rp_filter;

static void service_rp_filter(struct connman_service *service,
				bool connected)
{
	enum connman_ipconfig_method method;

	method = __connman_ipconfig_get_method(service->ipconfig_ipv4);

	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		return;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		break;
	}

	if (connected) {
		if (connected_networks_count == 1) {
			int filter_value;
			filter_value = __connman_ipconfig_set_rp_filter();
			if (filter_value < 0)
				return;

			original_rp_filter = filter_value;
		}
		connected_networks_count++;

	} else {
		if (connected_networks_count == 2)
			__connman_ipconfig_unset_rp_filter(original_rp_filter);

		connected_networks_count--;
		if (connected_networks_count < 0)
			connected_networks_count = 0;
	}

	DBG("%s %s ipconfig %p method %d count %d filter %d",
		connected ? "connected" : "disconnected", service->identifier,
		service->ipconfig_ipv4, method,
		connected_networks_count, original_rp_filter);
}

static void redo_wispr(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	service->online_timeout = 0;
	connman_service_unref(service);

	DBG("Retrying %s WISPr for %p %s",
		__connman_ipconfig_type2string(type),
		service, service->name);

	__connman_wispr_start(service, type);
}

static gboolean redo_wispr_ipv4(gpointer user_data)
{
	struct connman_service *service = user_data;

	redo_wispr(service, CONNMAN_IPCONFIG_TYPE_IPV4);

	return FALSE;
}

static gboolean redo_wispr_ipv6(gpointer user_data)
{
	struct connman_service *service = user_data;

	redo_wispr(service, CONNMAN_IPCONFIG_TYPE_IPV6);

	return FALSE;
}

#if defined TIZEN_MAINTAIN_ONLINE
static gboolean redo_wispr_ipv4(gpointer user_data)
{
	struct connman_service *service = user_data;

	DBG("");

	__connman_wispr_start(service, CONNMAN_IPCONFIG_TYPE_IPV4);

	return FALSE;
}
#endif

int __connman_service_online_check_failed(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	GSourceFunc redo_func;
	int *interval;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		interval = &service->online_check_interval_ipv4;
		redo_func = redo_wispr_ipv4;
	} else {
		interval = &service->online_check_interval_ipv6;
		redo_func = redo_wispr_ipv6;
	}

	DBG("service %p type %s interval %d", service,
		__connman_ipconfig_type2string(type), *interval);

	service->online_timeout = g_timeout_add_seconds(*interval * *interval,
				redo_func, connman_service_ref(service));

	/* Increment the interval for the next time, set a maximum timeout of
	 * ONLINE_CHECK_MAX_INTERVAL * ONLINE_CHECK_MAX_INTERVAL seconds.
	 */
	if (*interval < ONLINE_CHECK_MAX_INTERVAL)
		(*interval)++;

	return EAGAIN;
}

static void cancel_online_check(struct connman_service *service)
{
	if (service->online_timeout == 0)
		return;

	g_source_remove(service->online_timeout);
	service->online_timeout = 0;
	connman_service_unref(service);
}

int __connman_service_ipconfig_indicate_state(struct connman_service *service,
					enum connman_service_state new_state,
					enum connman_ipconfig_type type)
{
	struct connman_ipconfig *ipconfig = NULL;
	enum connman_service_state old_state;
	enum connman_ipconfig_method method;

	if (!service)
		return -EINVAL;

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
	case CONNMAN_IPCONFIG_TYPE_ALL:
		return -EINVAL;

	case CONNMAN_IPCONFIG_TYPE_IPV4:
		old_state = service->state_ipv4;
		ipconfig = service->ipconfig_ipv4;

		break;

	case CONNMAN_IPCONFIG_TYPE_IPV6:
		old_state = service->state_ipv6;
		ipconfig = service->ipconfig_ipv6;

		break;
	}

	if (!ipconfig)
		return -EINVAL;

	method = __connman_ipconfig_get_method(ipconfig);

	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		if (new_state != CONNMAN_SERVICE_STATE_IDLE)
			connman_warn("ipconfig state %d ipconfig method %d",
				new_state, method);

#if defined TIZEN_EXT
		if (old_state != CONNMAN_SERVICE_STATE_READY &&
				old_state != CONNMAN_SERVICE_STATE_ONLINE)
#endif
		new_state = CONNMAN_SERVICE_STATE_IDLE;
		break;

	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		break;

	}

	/* Any change? */
	if (old_state == new_state)
		return -EALREADY;

#if defined TIZEN_EXT
	__sync_synchronize();
	if (service->user_pdn_connection_refcount > 0 &&
			service->type == CONNMAN_SERVICE_TYPE_CELLULAR)
		if (new_state == CONNMAN_SERVICE_STATE_FAILURE ||
				new_state == CONNMAN_SERVICE_STATE_DISCONNECT ||
				new_state == CONNMAN_SERVICE_STATE_IDLE) {
			service->user_pdn_connection_refcount = 0;
			__sync_synchronize();
		}
#endif

	DBG("service %p (%s) old state %d (%s) new state %d (%s) type %d (%s)",
		service, service ? service->identifier : NULL,
		old_state, state2string(old_state),
		new_state, state2string(new_state),
		type, __connman_ipconfig_type2string(type));

	switch (new_state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
		break;
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		break;
	case CONNMAN_SERVICE_STATE_READY:
#if defined TIZEN_EXT
		if (service->type == CONNMAN_SERVICE_TYPE_CELLULAR &&
				__connman_service_is_internet_profile(service) != TRUE) {
			if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
				service_rp_filter(service, TRUE);

			break;
		}
#endif
		if (connman_setting_get_bool("EnableOnlineCheck"))
			if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
#if !defined TIZEN_EXT
				check_proxy_setup(service);
#endif
#if defined TIZEN_MAINTAIN_ONLINE
/*				if (old_state == CONNMAN_SERVICE_STATE_ONLINE) */
					check_proxy_setup(service);
#endif
			} else {
				__connman_service_wispr_start(service, type);
			}
		else
			connman_info("Online check disabled. "
				"Default service remains in READY state.");
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			service_rp_filter(service, true);
		set_mdns(service, service->mdns_config);
		break;
	case CONNMAN_SERVICE_STATE_ONLINE:
		break;
	case CONNMAN_SERVICE_STATE_DISCONNECT:
		if (service->state == CONNMAN_SERVICE_STATE_IDLE)
			return -EINVAL;

		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			service_rp_filter(service, false);

		break;

	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_FAILURE:
		__connman_ipconfig_disable(ipconfig);

		break;
	}

	if (is_connected(old_state) && !is_connected(new_state)) {
		nameserver_remove_all(service, type);
		cancel_online_check(service);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		service->state_ipv4 = new_state;
	else
		service->state_ipv6 = new_state;

	if (!is_connected(old_state) && is_connected(new_state))
		nameserver_add_all(service, type);

	__connman_timeserver_sync(service);

#if defined TIZEN_EXT
	int ret = service_indicate_state(service);
	/*Sent the Ready changed signal again in case IPv4 IP set
	  after IPv6 IP set*/

	if(ret == -EALREADY && type == CONNMAN_IPCONFIG_TYPE_IPV4
			&& new_state == CONNMAN_SERVICE_STATE_READY) {
		DBG("Notify IPv4 state new/old %d/%d", new_state,old_state);
		state_changed(service);
	}

	return ret;
#endif
	return service_indicate_state(service);
}

static bool prepare_network(struct connman_service *service)
{
	enum connman_network_type type;
	unsigned int ssid_len;

	type = connman_network_get_type(service->network);

	switch (type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
		return false;
	case CONNMAN_NETWORK_TYPE_WIFI:
		if (!connman_network_get_blob(service->network, "WiFi.SSID",
						&ssid_len))
			return false;

		if (service->passphrase)
			connman_network_set_string(service->network,
				"WiFi.Passphrase", service->passphrase);
		break;
	case CONNMAN_NETWORK_TYPE_ETHERNET:
	case CONNMAN_NETWORK_TYPE_GADGET:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
	case CONNMAN_NETWORK_TYPE_CELLULAR:
		break;
	}

	return true;
}

static void prepare_8021x(struct connman_service *service)
{
	if (service->eap)
		connman_network_set_string(service->network, "WiFi.EAP",
								service->eap);

	if (service->identity)
		connman_network_set_string(service->network, "WiFi.Identity",
							service->identity);

	if (service->anonymous_identity)
		connman_network_set_string(service->network,
						"WiFi.AnonymousIdentity",
						service->anonymous_identity);

	if (service->ca_cert_file)
		connman_network_set_string(service->network, "WiFi.CACertFile",
							service->ca_cert_file);

	if (service->subject_match)
		connman_network_set_string(service->network, "WiFi.SubjectMatch",
							service->subject_match);

	if (service->altsubject_match)
		connman_network_set_string(service->network, "WiFi.AltSubjectMatch",
							service->altsubject_match);

	if (service->domain_suffix_match)
		connman_network_set_string(service->network, "WiFi.DomainSuffixMatch",
							service->domain_suffix_match);

	if (service->domain_match)
		connman_network_set_string(service->network, "WiFi.DomainMatch",
							service->domain_match);

	if (service->client_cert_file)
		connman_network_set_string(service->network,
						"WiFi.ClientCertFile",
						service->client_cert_file);

	if (service->private_key_file)
		connman_network_set_string(service->network,
						"WiFi.PrivateKeyFile",
						service->private_key_file);

	if (service->private_key_passphrase)
		connman_network_set_string(service->network,
					"WiFi.PrivateKeyPassphrase",
					service->private_key_passphrase);

	if (service->phase2)
		connman_network_set_string(service->network, "WiFi.Phase2",
							service->phase2);

#if defined TIZEN_EXT
	if (service->keymgmt_type)
		connman_network_set_string(service->network, "WiFi.KeymgmtType",
							service->keymgmt_type);

	DBG("service->phase1 : %s", service->phase1);
	if (service->phase1)
		connman_network_set_string(service->network, "WiFi.Phase1",
							service->phase1);
#endif
}
#if defined TIZEN_EXT

static bool has_valid_configuration_object(struct connman_service *service)
{
	return service->connector && service->c_sign_key && service->net_access_key;
}

static void prepare_dpp(struct connman_service *service)
{
	DBG("prepare dpp");
	if (service->connector)
		connman_network_set_string(service->network, "WiFi.Connector",
								service->connector);

	if (service->c_sign_key)
		connman_network_set_string(service->network, "WiFi.CSignKey",
							service->c_sign_key);

	if (service->net_access_key)
		connman_network_set_string(service->network, "WiFi.NetAccessKey",
							service->net_access_key);
}
#endif

static int service_connect(struct connman_service *service)
{
	int err;

	if (service->hidden)
		return -EPERM;

#if defined TIZEN_EXT
	GList *list;
	int index;

	index = __connman_service_get_index(service);

	for (list = service_list; list; list = list->next) {
		struct connman_service *temp = list->data;

		if (service->type == CONNMAN_SERVICE_TYPE_CELLULAR)
			break;

		if (!is_connecting(temp->state) && !is_connected(temp->state))
			break;

		if (service == temp)
			continue;

		if (service->type != temp->type)
			continue;

		if (__connman_service_get_index(temp) == index &&
				__connman_service_disconnect(temp) == -EINPROGRESS)
			return -EINPROGRESS;
	}
#endif

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
#if defined TIZEN_EXT_WIFI_MESH
	case CONNMAN_SERVICE_TYPE_MESH:
#endif
		return -EINVAL;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_VPN:
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		switch (service->security) {
		case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		case CONNMAN_SERVICE_SECURITY_NONE:
#if defined TIZEN_EXT
		case CONNMAN_SERVICE_SECURITY_OWE:
#endif
			break;
		case CONNMAN_SERVICE_SECURITY_WEP:
		case CONNMAN_SERVICE_SECURITY_PSK:
		case CONNMAN_SERVICE_SECURITY_WPA:
		case CONNMAN_SERVICE_SECURITY_RSN:
#if defined TIZEN_EXT
		case CONNMAN_SERVICE_SECURITY_SAE:
#endif
			if (service->error == CONNMAN_SERVICE_ERROR_INVALID_KEY)
				return -ENOKEY;

			if (!service->passphrase) {
				if (!service->network)
					return -EOPNOTSUPP;

				if (!service->wps ||
					!connman_network_get_bool(service->network, "WiFi.UseWPS"))
					return -ENOKEY;
			}
			break;

#if defined TIZEN_EXT
		case CONNMAN_SERVICE_SECURITY_DPP:
			if (has_valid_configuration_object(service) &&
					!service->network)
				return -EINVAL;
			break;
#endif
		case CONNMAN_SERVICE_SECURITY_8021X:
			if (!service->eap) {
				connman_warn("EAP type has not been found. "
					"Most likely ConnMan is not able to "
					"find a configuration for given "
					"8021X network. "
					"Check SSID or Name match with the "
					"network name.");
				return -EINVAL;
			}

#if defined TIZEN_EXT
			/*
			 * never request credentials if using EAP-TLS, EAP-SIM
			 * or EAP-AKA (EAP-TLS, EAP-SIM and EAP-AKA networks
			 * need to be fully provisioned)
			 */
			DBG("service eap: %s", service->eap);
			if (g_str_equal(service->eap, "tls") ||
				g_str_equal(service->eap, "sim") ||
				g_str_equal(service->eap, "aka") ||
				g_str_equal(service->eap, "aka'") ||
				g_str_equal(service->eap, "pwd") ||
				g_str_equal(service->eap, "fast"))
				break;
#else
			/*
			 * never request credentials if using EAP-TLS
			 * (EAP-TLS networks need to be fully provisioned)
			 */
			if (g_str_equal(service->eap, "tls"))
				break;

#endif
			/*
			 * Return -ENOKEY if either identity or passphrase is
			 * missing. Agent provided credentials can be used as
			 * fallback if needed.
			 */
			if (((!service->identity &&
					!service->agent_identity) ||
					!service->passphrase) ||
					service->error == CONNMAN_SERVICE_ERROR_INVALID_KEY)
				return -ENOKEY;

			break;
		}
		break;
	}

	if (service->network) {
		if (!prepare_network(service))
			return -EINVAL;

		switch (service->security) {
		case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		case CONNMAN_SERVICE_SECURITY_NONE:
		case CONNMAN_SERVICE_SECURITY_WEP:
		case CONNMAN_SERVICE_SECURITY_PSK:
		case CONNMAN_SERVICE_SECURITY_WPA:
		case CONNMAN_SERVICE_SECURITY_RSN:
#if defined TIZEN_EXT
		case CONNMAN_SERVICE_SECURITY_SAE:
		case CONNMAN_SERVICE_SECURITY_OWE:
			break;
		case CONNMAN_SERVICE_SECURITY_DPP:
			prepare_dpp(service);
#endif
			break;
		case CONNMAN_SERVICE_SECURITY_8021X:
			prepare_8021x(service);
			break;
		}

		if (__connman_stats_service_register(service) == 0) {
			__connman_stats_get(service, false,
						&service->stats.data);
			__connman_stats_get(service, true,
						&service->stats_roaming.data);
		}

		err = __connman_network_connect(service->network);
	} else if (service->type == CONNMAN_SERVICE_TYPE_VPN &&
					service->provider)
		err = __connman_provider_connect(service->provider,
						get_dbus_sender(service));
	else
		return -EOPNOTSUPP;

	if (err < 0) {
		if (err != -EINPROGRESS) {
			__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_FAILURE,
						CONNMAN_IPCONFIG_TYPE_IPV4);
			__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_FAILURE,
						CONNMAN_IPCONFIG_TYPE_IPV6);
			__connman_stats_service_unregister(service);
		}
	}

	return err;
}

int __connman_service_connect(struct connman_service *service,
			enum connman_service_connect_reason reason)
{
	int err;

	DBG("service %p state %s connect reason %s -> %s",
		service, state2string(service->state),
		reason2string(service->connect_reason),
		reason2string(reason));

	if (is_connected(service->state))
		return -EISCONN;

	if (is_connecting(service->state))
		return -EALREADY;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
#if defined TIZEN_EXT_WIFI_MESH
	case CONNMAN_SERVICE_TYPE_MESH:
#endif
		return -EINVAL;

	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_WIFI:
		break;
	}

	if (!is_ipconfig_usable(service))
		return -ENOLINK;

	__connman_service_clear_error(service);

	err = service_connect(service);

	DBG("service %p err %d", service, err);

	service->connect_reason = reason;
#if defined TIZEN_EXT
	connect_reason_changed(service);
#endif

	if (err >= 0)
		return 0;

	if (err == -EINPROGRESS) {
		if (service->timeout == 0)
			service->timeout = g_timeout_add_seconds(
				CONNECT_TIMEOUT, connect_timeout, service);

		return -EINPROGRESS;
	}

	if (service->network)
		__connman_network_disconnect(service->network);
	else if (service->type == CONNMAN_SERVICE_TYPE_VPN &&
				service->provider)
			connman_provider_disconnect(service->provider);

	if (service->connect_reason == CONNMAN_SERVICE_CONNECT_REASON_USER) {
		if (err == -ENOKEY || err == -EPERM) {
			DBusMessage *pending = NULL;
			const char *dbus_sender = get_dbus_sender(service);

			/*
			 * We steal the reply here. The idea is that the
			 * connecting client will see the connection status
			 * after the real hidden network is connected or
			 * connection failed.
			 */
			if (service->hidden) {
				pending = service->pending;
				service->pending = NULL;
			}

			err = __connman_agent_request_passphrase_input(service,
					request_input_cb,
					dbus_sender,
					pending);
			if (service->hidden && err != -EINPROGRESS)
				service->pending = pending;

			return err;
		}
	}

	return err;
}

int __connman_service_disconnect(struct connman_service *service)
{
	int err;

	DBG("service %p", service);

	service->connect_reason = CONNMAN_SERVICE_CONNECT_REASON_NONE;
	service->proxy = CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;

	connman_agent_cancel(service);

	__connman_stats_service_unregister(service);

	if (service->network) {
		err = __connman_network_disconnect(service->network);
	} else if (service->type == CONNMAN_SERVICE_TYPE_VPN &&
					service->provider)
		err = connman_provider_disconnect(service->provider);
	else
		return -EOPNOTSUPP;

	if (err < 0 && err != -EINPROGRESS)
		return err;

	__connman_6to4_remove(service->ipconfig_ipv4);

	if (service->ipconfig_ipv4)
		__connman_ipconfig_set_proxy_autoconfig(service->ipconfig_ipv4,
							NULL);
	else
		__connman_ipconfig_set_proxy_autoconfig(service->ipconfig_ipv6,
							NULL);

#if defined TIZEN_EXT
	/**
	  * Skip the functions If there is any connected profiles
	  * that use same interface
	  */
	if (service->type != CONNMAN_SERVICE_TYPE_CELLULAR ||
		__connman_service_get_connected_count_of_iface(service) <= 0) {
#endif
	__connman_ipconfig_address_remove(service->ipconfig_ipv4);
	settings_changed(service, service->ipconfig_ipv4);

	__connman_ipconfig_address_remove(service->ipconfig_ipv6);
	settings_changed(service, service->ipconfig_ipv6);

	__connman_ipconfig_disable(service->ipconfig_ipv4);
	__connman_ipconfig_disable(service->ipconfig_ipv6);
#if defined TIZEN_EXT
	}
#endif

	return err;
}

int __connman_service_disconnect_all(void)
{
	struct connman_service *service;
	GSList *services = NULL, *list;
	GList *iter;

	DBG("");

	for (iter = service_list; iter; iter = iter->next) {
		service = iter->data;

		if (!is_connected(service->state))
			break;

		services = g_slist_prepend(services, service);
	}

	for (list = services; list; list = list->next) {
		struct connman_service *service = list->data;

		service->ignore = true;

		__connman_service_disconnect(service);
	}

	g_slist_free(services);

	return 0;
}

/**
 * lookup_by_identifier:
 * @identifier: service identifier
 *
 * Look up a service by identifier (reference count will not be increased)
 */
static struct connman_service *lookup_by_identifier(const char *identifier)
{
	return g_hash_table_lookup(service_hash, identifier);
}

struct connman_service *connman_service_lookup_from_identifier(const char* identifier)
{
	return identifier ? lookup_by_identifier(identifier) : NULL;
}

struct provision_user_data {
	const char *ident;
	int ret;
};

static void provision_changed(gpointer value, gpointer user_data)
{
	struct connman_service *service = value;
	struct provision_user_data *data = user_data;
	const char *path = data->ident;
	int ret;

	ret = __connman_config_provision_service_ident(service, path,
			service->config_file, service->config_entry);
	if (ret > 0)
		data->ret = ret;
}

int __connman_service_provision_changed(const char *ident)
{
	struct provision_user_data data = {
		.ident = ident,
		.ret = 0
	};

	g_list_foreach(service_list, provision_changed, (void *)&data);

	/*
	 * Because the provision_changed() might have set some services
	 * as favorite, we must sort the sequence now.
	 */
	if (services_dirty) {
		services_dirty = false;

		service_list_sort();

		__connman_connection_update_gateway();
	}

	return data.ret;
}

void __connman_service_set_config(struct connman_service *service,
				const char *file_id, const char *entry)
{
	if (!service)
		return;

	g_free(service->config_file);
	service->config_file = g_strdup(file_id);

	g_free(service->config_entry);
	service->config_entry = g_strdup(entry);
}

/**
 * __connman_service_get:
 * @identifier: service identifier
 *
 * Look up a service by identifier or create a new one if not found
 */
static struct connman_service *service_get(const char *identifier)
{
	struct connman_service *service;

	service = g_hash_table_lookup(service_hash, identifier);
	if (service) {
		connman_service_ref(service);
		return service;
	}

	service = connman_service_create();
	if (!service)
		return NULL;

	DBG("service %p", service);

	service->identifier = g_strdup(identifier);

	service_list = g_list_insert_sorted(service_list, service,
						service_compare);

	g_hash_table_insert(service_hash, service->identifier, service);

	return service;
}

static int service_register(struct connman_service *service)
{
	DBG("service %p", service);

	if (service->path)
		return -EALREADY;

	service->path = g_strdup_printf("%s/service/%s", CONNMAN_PATH,
						service->identifier);

	DBG("path %s", service->path);

#if defined TIZEN_EXT
	int ret;
	service_load(service);
	ret = service_ext_load(service);
	if (ret == -ERANGE)
		service_ext_save(service);
	ret = __connman_config_provision_service(service);
	if (ret < 0)
		DBG("Failed to provision service");
#else
	if (__connman_config_provision_service(service) < 0)
		service_load(service);
#endif

	g_dbus_register_interface(connection, service->path,
					CONNMAN_SERVICE_INTERFACE,
					service_methods, service_signals,
							NULL, service, NULL);

	service_list_sort();

	__connman_connection_update_gateway();

	return 0;
}

static void service_up(struct connman_ipconfig *ipconfig,
		const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);

	DBG("%s up", ifname);

	link_changed(service);

	service->stats.valid = false;
	service->stats_roaming.valid = false;
}

static void service_down(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	DBG("%s down", ifname);
}

static void service_lower_up(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);

	DBG("%s lower up", ifname);

	stats_start(service);
}

static void service_lower_down(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);

	DBG("%s lower down", ifname);

	stats_stop(service);
	service_save(service);
}

static void service_ip_bound(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);
	enum connman_ipconfig_method method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;
	enum connman_ipconfig_type type = CONNMAN_IPCONFIG_TYPE_UNKNOWN;
#if defined TIZEN_EXT
	int err;
#endif

	DBG("%s ip bound", ifname);

	type = __connman_ipconfig_get_config_type(ipconfig);
	method = __connman_ipconfig_get_method(ipconfig);

	DBG("service %p ipconfig %p type %d method %d", service, ipconfig,
							type, method);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
			method == CONNMAN_IPCONFIG_METHOD_AUTO)
#if defined TIZEN_EXT
	{
		err = __connman_ipconfig_gateway_add(ipconfig, service);

		if(err < 0)
			DBG("Failed to add gateway");
	}
#else
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV6);
#endif

	settings_changed(service, ipconfig);
	address_updated(service, type);
}

static void service_ip_release(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);
	enum connman_ipconfig_method method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;
	enum connman_ipconfig_type type = CONNMAN_IPCONFIG_TYPE_UNKNOWN;

	DBG("%s ip release", ifname);

	type = __connman_ipconfig_get_config_type(ipconfig);
	method = __connman_ipconfig_get_method(ipconfig);

	DBG("service %p ipconfig %p type %d method %d", service, ipconfig,
							type, method);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
			method == CONNMAN_IPCONFIG_METHOD_OFF)
		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV6);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
			method == CONNMAN_IPCONFIG_METHOD_OFF)
		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV4);

	settings_changed(service, ipconfig);
}

static void service_route_changed(struct connman_ipconfig *ipconfig,
				const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);

	DBG("%s route changed", ifname);

	settings_changed(service, ipconfig);
}

static const struct connman_ipconfig_ops service_ops = {
	.up		= service_up,
	.down		= service_down,
	.lower_up	= service_lower_up,
	.lower_down	= service_lower_down,
	.ip_bound	= service_ip_bound,
	.ip_release	= service_ip_release,
	.route_set	= service_route_changed,
	.route_unset	= service_route_changed,
};

static struct connman_ipconfig *create_ip4config(struct connman_service *service,
		int index, enum connman_ipconfig_method method)
{
	struct connman_ipconfig *ipconfig_ipv4;

	ipconfig_ipv4 = __connman_ipconfig_create(index,
						CONNMAN_IPCONFIG_TYPE_IPV4);
	if (!ipconfig_ipv4)
		return NULL;

	__connman_ipconfig_set_method(ipconfig_ipv4, method);

	__connman_ipconfig_set_data(ipconfig_ipv4, service);

	__connman_ipconfig_set_ops(ipconfig_ipv4, &service_ops);

	return ipconfig_ipv4;
}

static struct connman_ipconfig *create_ip6config(struct connman_service *service,
		int index)
{
	struct connman_ipconfig *ipconfig_ipv6;

	ipconfig_ipv6 = __connman_ipconfig_create(index,
						CONNMAN_IPCONFIG_TYPE_IPV6);
	if (!ipconfig_ipv6)
		return NULL;

	__connman_ipconfig_set_data(ipconfig_ipv6, service);

	__connman_ipconfig_set_ops(ipconfig_ipv6, &service_ops);

	return ipconfig_ipv6;
}

void __connman_service_read_ip4config(struct connman_service *service)
{
	GKeyFile *keyfile;

	if (!service->ipconfig_ipv4)
		return;

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile)
		return;

	__connman_ipconfig_load(service->ipconfig_ipv4, keyfile,
				service->identifier, "IPv4.");

	g_key_file_free(keyfile);
}

void connman_service_create_ip4config(struct connman_service *service,
					int index)
{
	DBG("ipv4 %p", service->ipconfig_ipv4);

	if (service->ipconfig_ipv4)
		return;

	service->ipconfig_ipv4 = create_ip4config(service, index,
			CONNMAN_IPCONFIG_METHOD_DHCP);
	__connman_service_read_ip4config(service);
}

void __connman_service_read_ip6config(struct connman_service *service)
{
	GKeyFile *keyfile;

	if (!service->ipconfig_ipv6)
		return;

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile)
		return;

	__connman_ipconfig_load(service->ipconfig_ipv6, keyfile,
				service->identifier, "IPv6.");

	g_key_file_free(keyfile);
}

void connman_service_create_ip6config(struct connman_service *service,
								int index)
{
	DBG("ipv6 %p", service->ipconfig_ipv6);

	if (service->ipconfig_ipv6)
		return;

	service->ipconfig_ipv6 = create_ip6config(service, index);

	__connman_service_read_ip6config(service);
}

/**
 * connman_service_lookup_from_network:
 * @network: network structure
 *
 * Look up a service by network (reference count will not be increased)
 */
struct connman_service *connman_service_lookup_from_network(struct connman_network *network)
{
	struct connman_service *service;
	const char *ident, *group;
	char *name;

	if (!network)
		return NULL;

	ident = __connman_network_get_ident(network);
	if (!ident)
		return NULL;

	group = connman_network_get_group(network);
	if (!group)
		return NULL;

	name = g_strdup_printf("%s_%s_%s",
			__connman_network_get_type(network), ident, group);
	service = lookup_by_identifier(name);
	g_free(name);

	return service;
}

struct connman_service *__connman_service_lookup_from_index(int index)
{
	struct connman_service *service;
	GList *list;

	for (list = service_list; list; list = list->next) {
		service = list->data;

		if (__connman_ipconfig_get_index(service->ipconfig_ipv4)
							== index)
			return service;

		if (__connman_ipconfig_get_index(service->ipconfig_ipv6)
							== index)
			return service;
	}

	return NULL;
}

const char *connman_service_get_identifier(struct connman_service *service)
{
	return service ? service->identifier : NULL;
}

const char *__connman_service_get_path(struct connman_service *service)
{
	return service->path;
}

const char *__connman_service_get_name(struct connman_service *service)
{
	return service->name;
}

enum connman_service_state connman_service_get_state(struct connman_service *service)
{
	return service ? service->state : CONNMAN_SERVICE_STATE_UNKNOWN;
}

static enum connman_service_type convert_network_type(struct connman_network *network)
{
	enum connman_network_type type = connman_network_get_type(network);

	switch (type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
		break;
	case CONNMAN_NETWORK_TYPE_ETHERNET:
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	case CONNMAN_NETWORK_TYPE_WIFI:
		return CONNMAN_SERVICE_TYPE_WIFI;
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
		return CONNMAN_SERVICE_TYPE_BLUETOOTH;
	case CONNMAN_NETWORK_TYPE_CELLULAR:
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	case CONNMAN_NETWORK_TYPE_GADGET:
		return CONNMAN_SERVICE_TYPE_GADGET;
	}

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

static enum connman_service_security convert_wifi_security(const char *security)
{
	if (!security)
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;
	else if (g_str_equal(security, "none"))
		return CONNMAN_SERVICE_SECURITY_NONE;
	else if (g_str_equal(security, "wep"))
		return CONNMAN_SERVICE_SECURITY_WEP;
	else if (g_str_equal(security, "psk"))
		return CONNMAN_SERVICE_SECURITY_PSK;
	else if (g_str_equal(security, "ieee8021x"))
		return CONNMAN_SERVICE_SECURITY_8021X;
	else if (g_str_equal(security, "wpa"))
		return CONNMAN_SERVICE_SECURITY_WPA;
	else if (g_str_equal(security, "rsn"))
		return CONNMAN_SERVICE_SECURITY_RSN;
#if defined TIZEN_EXT
	else if (g_str_equal(security, "sae"))
		return CONNMAN_SERVICE_SECURITY_SAE;
	else if (g_str_equal(security, "owe"))
		return CONNMAN_SERVICE_SECURITY_OWE;
	else if (g_str_equal(security, "dpp"))
		return CONNMAN_SERVICE_SECURITY_DPP;
	else if (g_str_equal(security, "ft_psk") == TRUE)
		return CONNMAN_SERVICE_SECURITY_PSK;
	else if (g_str_equal(security, "ft_ieee8021x") == TRUE)
		return CONNMAN_SERVICE_SECURITY_8021X;
#endif
	else
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;
}

#if defined TIZEN_EXT
int check_passphrase_ext(struct connman_network *network,
					const char *passphrase)
{
	const char *str;
	enum connman_service_security security;

	str = connman_network_get_string(network, "WiFi.Security");
	security = convert_wifi_security(str);

	return __connman_service_check_passphrase(security, passphrase);
}
#endif

static void update_wps_values(struct connman_service *service,
				struct connman_network *network)
{
	bool wps = connman_network_get_bool(network, "WiFi.WPS");
	bool wps_advertising = connman_network_get_bool(network,
							"WiFi.WPSAdvertising");

	if (service->wps != wps ||
			service->wps_advertizing != wps_advertising) {
		service->wps = wps;
		service->wps_advertizing = wps_advertising;
		security_changed(service);
	}
}

static void update_from_network(struct connman_service *service,
					struct connman_network *network)
{
	uint8_t strength = service->strength;
	const char *str;

	DBG("service %p network %p", service, network);

	if (is_connected(service->state))
		return;

	if (is_connecting(service->state))
		return;

	str = connman_network_get_string(network, "Name");
	if (str) {
		g_free(service->name);
		service->name = g_strdup(str);
		service->hidden = false;
	} else {
		g_free(service->name);
		service->name = NULL;
		service->hidden = true;
	}

	service->strength = connman_network_get_strength(network);
	service->roaming = connman_network_get_bool(network, "Roaming");

	if (service->strength == 0) {
		/*
		 * Filter out 0-values; it's unclear what they mean
		 * and they cause anomalous sorting of the priority list.
		 */
		service->strength = strength;
	}

	str = connman_network_get_string(network, "WiFi.Security");
	service->security = convert_wifi_security(str);

	if (service->type == CONNMAN_SERVICE_TYPE_WIFI)
		update_wps_values(service, network);

	if (service->strength > strength && service->network) {
		connman_network_unref(service->network);
		service->network = connman_network_ref(network);

		strength_changed(service);
	}

	if (!service->network)
		service->network = connman_network_ref(network);

	service_list_sort();
}

/**
 * __connman_service_create_from_network:
 * @network: network structure
 *
 * Look up service by network and if not found, create one
 */
struct connman_service * __connman_service_create_from_network(struct connman_network *network)
{
	struct connman_service *service;
	struct connman_device *device;
	const char *ident, *group;
	char *name;
	unsigned int *auto_connect_types, *favorite_types;
	int i, index;

	DBG("network %p", network);

	if (!network)
		return NULL;

	ident = __connman_network_get_ident(network);
	if (!ident)
		return NULL;

	group = connman_network_get_group(network);
	if (!group)
		return NULL;

	name = g_strdup_printf("%s_%s_%s",
			__connman_network_get_type(network), ident, group);
	service = service_get(name);
	g_free(name);

	if (!service)
		return NULL;

	if (__connman_network_get_weakness(network))
		return service;

	if (service->path) {
		update_from_network(service, network);
		__connman_connection_update_gateway();
		return service;
	}

	service->type = convert_network_type(network);

	auto_connect_types = connman_setting_get_uint_list("DefaultAutoConnectTechnologies");
	service->autoconnect = false;
	for (i = 0; auto_connect_types &&
		     auto_connect_types[i] != 0; i++) {
		if (service->type == auto_connect_types[i]) {
			service->autoconnect = true;
			break;
		}
	}

	favorite_types = connman_setting_get_uint_list("DefaultFavoriteTechnologies");
	service->favorite = false;
	for (i = 0; favorite_types && favorite_types[i] != 0; i++) {
		if (service->type == favorite_types[i]) {
			service->favorite = true;
			break;
		}
	}

	service->state_ipv4 = service->state_ipv6 = CONNMAN_SERVICE_STATE_IDLE;
	service->state = combine_state(service->state_ipv4, service->state_ipv6);

	update_from_network(service, network);

	index = connman_network_get_index(network);

	if (!service->ipconfig_ipv4)
		service->ipconfig_ipv4 = create_ip4config(service, index,
				CONNMAN_IPCONFIG_METHOD_DHCP);

	if (!service->ipconfig_ipv6)
		service->ipconfig_ipv6 = create_ip6config(service, index);

	service_register(service);
	service_schedule_added(service);

	if (service->favorite) {
		device = connman_network_get_device(service->network);
		if (device && !connman_device_get_scanning(device,
						CONNMAN_SERVICE_TYPE_UNKNOWN)) {

			switch (service->type) {
			case CONNMAN_SERVICE_TYPE_UNKNOWN:
			case CONNMAN_SERVICE_TYPE_SYSTEM:
			case CONNMAN_SERVICE_TYPE_P2P:
#if defined TIZEN_EXT_WIFI_MESH
			case CONNMAN_SERVICE_TYPE_MESH:
#endif
				break;

			case CONNMAN_SERVICE_TYPE_GADGET:
			case CONNMAN_SERVICE_TYPE_ETHERNET:
				if (service->autoconnect) {
					__connman_service_connect(service,
						CONNMAN_SERVICE_CONNECT_REASON_AUTO);
					break;
				}

				/* fall through */
			case CONNMAN_SERVICE_TYPE_BLUETOOTH:
			case CONNMAN_SERVICE_TYPE_GPS:
			case CONNMAN_SERVICE_TYPE_VPN:
			case CONNMAN_SERVICE_TYPE_WIFI:
			case CONNMAN_SERVICE_TYPE_CELLULAR:
				__connman_service_auto_connect(CONNMAN_SERVICE_CONNECT_REASON_AUTO);
				break;
			}
		}

#if defined TIZEN_EXT
		/* TIZEN synchronizes below information when the service creates */
		if (service->eap != NULL)
			connman_network_set_string(service->network, "WiFi.EAP",
								service->eap);
		if (service->identity != NULL)
			connman_network_set_string(service->network, "WiFi.Identity",
								service->identity);
		if (service->phase2 != NULL)
			connman_network_set_string(service->network, "WiFi.Phase2",
								service->phase2);
		if (service->eap != NULL)
			connman_network_set_string(service->network, "WiFi.Connector",
								service->connector);
		if (service->identity != NULL)
			connman_network_set_string(service->network, "WiFi.CSignKey",
								service->c_sign_key);
		if (service->phase2 != NULL)
			connman_network_set_string(service->network, "WiFi.NetAccessKey",
								service->net_access_key);
#endif
	}

	__connman_notifier_service_add(service, service->name);

	return service;
}

#if defined TIZEN_EXT
void __connman_service_notify_strength_changed(struct connman_network *network)
{
	struct connman_service *service;
	uint8_t strength = 0;

	service = connman_service_lookup_from_network(network);
	if (!service)
		return;

	if (!service->network)
		return;

	strength = connman_network_get_strength(service->network);
	if (strength == service->strength)
		return;

	service->strength = strength;
	DBG("Strength %d", strength);
	strength_changed(service);
	service_list_sort();
}
#endif

void __connman_service_update_from_network(struct connman_network *network)
{
	bool need_sort = false;
	struct connman_service *service;
	uint8_t strength;
	bool roaming;
	const char *name;
	bool stats_enable;
#if defined TIZEN_EXT
	bool need_save = false;
#endif

	service = connman_service_lookup_from_network(network);
	if (!service)
		return;

	if (!service->network)
		return;

#if defined TIZEN_EXT
	if (service->storage_reload) {
		service_load(service);
		__connman_service_set_storage_reload(service, false);
	}
#endif

	name = connman_network_get_string(service->network, "Name");
	if (g_strcmp0(service->name, name) != 0) {
		g_free(service->name);
		service->name = g_strdup(name);

		if (allow_property_changed(service))
			connman_dbus_property_changed_basic(service->path,
					CONNMAN_SERVICE_INTERFACE, "Name",
					DBUS_TYPE_STRING, &service->name);
	}

	if (service->type == CONNMAN_SERVICE_TYPE_WIFI)
		update_wps_values(service, network);

	strength = connman_network_get_strength(service->network);
	if (strength == service->strength)
		goto roaming;

	service->strength = strength;
	need_sort = true;

	strength_changed(service);

roaming:
	roaming = connman_network_get_bool(service->network, "Roaming");
	if (roaming == service->roaming)
		goto sorting;

	stats_enable = stats_enabled(service);
	if (stats_enable)
		stats_stop(service);

	service->roaming = roaming;
	need_sort = true;

	if (stats_enable)
		stats_start(service);

	roaming_changed(service);

sorting:
#if defined TIZEN_EXT
	need_save |= update_last_connected_bssid(service);
	need_save |= update_assoc_reject(service);
	if (need_save) {
		g_get_current_time(&service->modified);
		service_ext_save(service);
		need_sort = true;
	}
#endif

	if (need_sort) {
		service_list_sort();
	}
}

void __connman_service_remove_from_network(struct connman_network *network)
{
	struct connman_service *service;

	service = connman_service_lookup_from_network(network);

	DBG("network %p service %p", network, service);

	if (!service)
		return;

	service->ignore = true;

	__connman_connection_gateway_remove(service,
					CONNMAN_IPCONFIG_TYPE_ALL);

	connman_service_unref(service);
}

/**
 * __connman_service_create_from_provider:
 * @provider: provider structure
 *
 * Look up service by provider and if not found, create one
 */
struct connman_service *
__connman_service_create_from_provider(struct connman_provider *provider)
{
	struct connman_service *service;
	const char *ident, *str;
	char *name;
	int index = connman_provider_get_index(provider);

	DBG("provider %p", provider);

	ident = __connman_provider_get_ident(provider);
	if (!ident)
		return NULL;

	name = g_strdup_printf("vpn_%s", ident);
	service = service_get(name);
	g_free(name);

	if (!service)
		return NULL;

	service->type = CONNMAN_SERVICE_TYPE_VPN;
	service->order = service->do_split_routing ? 0 : 10;
	service->provider = connman_provider_ref(provider);
	service->autoconnect = false;
	service->favorite = true;

	service->state_ipv4 = service->state_ipv6 = CONNMAN_SERVICE_STATE_IDLE;
	service->state = combine_state(service->state_ipv4, service->state_ipv6);

	str = connman_provider_get_string(provider, "Name");
	if (str) {
		g_free(service->name);
		service->name = g_strdup(str);
		service->hidden = false;
	} else {
		g_free(service->name);
		service->name = NULL;
		service->hidden = true;
	}

	service->strength = 0;

	if (!service->ipconfig_ipv4)
		service->ipconfig_ipv4 = create_ip4config(service, index,
				CONNMAN_IPCONFIG_METHOD_MANUAL);

	if (!service->ipconfig_ipv6)
		service->ipconfig_ipv6 = create_ip6config(service, index);

	service_register(service);

	__connman_notifier_service_add(service, service->name);
	service_schedule_added(service);

	return service;
}

static void remove_unprovisioned_services(void)
{
	gchar **services;
	GKeyFile *keyfile, *configkeyfile;
	char *file, *section;
	int i = 0;

	services = connman_storage_get_services();
	if (!services)
		return;

	for (; services[i]; i++) {
		file = section = NULL;
		keyfile = configkeyfile = NULL;

		keyfile = connman_storage_load_service(services[i]);
		if (!keyfile)
			continue;

		file = g_key_file_get_string(keyfile, services[i],
					"Config.file", NULL);
		if (!file)
			goto next;

		section = g_key_file_get_string(keyfile, services[i],
					"Config.ident", NULL);
		if (!section)
			goto next;

		configkeyfile = __connman_storage_load_config(file);
		if (!configkeyfile) {
			/*
			 * Config file is missing, remove the provisioned
			 * service.
			 */
			__connman_storage_remove_service(services[i]);
			goto next;
		}

		if (!g_key_file_has_group(configkeyfile, section))
			/*
			 * Config section is missing, remove the provisioned
			 * service.
			 */
			__connman_storage_remove_service(services[i]);

	next:
		if (keyfile)
			g_key_file_free(keyfile);

		if (configkeyfile)
			g_key_file_free(configkeyfile);

		g_free(section);
		g_free(file);
	}

	g_strfreev(services);
}

static int agent_probe(struct connman_agent *agent)
{
	DBG("agent %p", agent);
	return 0;
}

static void agent_remove(struct connman_agent *agent)
{
	DBG("agent %p", agent);
}

static void *agent_context_ref(void *context)
{
	struct connman_service *service = context;

	return (void *)connman_service_ref(service);
}

static void agent_context_unref(void *context)
{
	struct connman_service *service = context;

	connman_service_unref(service);
}

static struct connman_agent_driver agent_driver = {
	.name		= "service",
	.interface      = CONNMAN_AGENT_INTERFACE,
	.probe		= agent_probe,
	.remove		= agent_remove,
	.context_ref	= agent_context_ref,
	.context_unref	= agent_context_unref,
};

#if defined TIZEN_EXT
static void ins_setting_init(void)
{
	int i;
	const char *string;
	char **string_list;
	unsigned int string_count;

	ins_settings.last_user_selection = connman_setting_get_bool("INSLastUserSelection");
	ins_settings.last_user_selection_time = connman_setting_get_uint("INSLastUserSelectionTime");
	ins_settings.last_connected = connman_setting_get_bool("INSLastConnected");

	string = connman_option_get_string("INSPreferredFreq");
	if (g_str_equal(string, "5GHz"))
		ins_settings.preferred_freq = CONNMAN_INS_PREFERRED_FREQ_5GHZ;
	else if (g_str_equal(string, "2.4GHz"))
		ins_settings.preferred_freq = CONNMAN_INS_PREFERRED_FREQ_24GHZ;
	else
		ins_settings.preferred_freq = CONNMAN_INS_PREFERRED_FREQ_UNKNOWN;

	ins_settings.security_priority_count = connman_setting_get_uint("INSSecurityPriorityCount");
	ins_settings.security_priority_score = connman_setting_get_uint("INSSecurityPriorityScore");
	string_count = ins_settings.security_priority_count;

	memset(ins_settings.security_priority, 0, sizeof(ins_settings.security_priority));
	string_list = connman_setting_get_string_list("INSSecurityPriority");
	for (i = 0; string_list && string_list[i]; i++) {
		unsigned int security_score = string_count * ins_settings.security_priority_score;

		if (g_str_equal(string_list[i], "WEP"))
			ins_settings.security_priority[CONNMAN_SERVICE_SECURITY_WEP] = security_score;
		else if (g_str_equal(string_list[i], "PSK"))
			ins_settings.security_priority[CONNMAN_SERVICE_SECURITY_PSK] = security_score;
		else if (g_str_equal(string_list[i], "8021X"))
			ins_settings.security_priority[CONNMAN_SERVICE_SECURITY_8021X] = security_score;
		else if (g_str_equal(string_list[i], "WPA"))
			ins_settings.security_priority[CONNMAN_SERVICE_SECURITY_WPA] = security_score;
		else if (g_str_equal(string_list[i], "RSN"))
			ins_settings.security_priority[CONNMAN_SERVICE_SECURITY_RSN] = security_score;
		else if (g_str_equal(string_list[i], "SAE"))
			ins_settings.security_priority[CONNMAN_SERVICE_SECURITY_SAE] = security_score;
		else if (g_str_equal(string_list[i], "OWE"))
			ins_settings.security_priority[CONNMAN_SERVICE_SECURITY_OWE] = security_score;
		else if (g_str_equal(string_list[i], "DPP"))
			ins_settings.security_priority[CONNMAN_SERVICE_SECURITY_DPP] = security_score;

		string_count--;
	}

	ins_settings.signal = connman_setting_get_bool("INSSignal");
	ins_settings.internet = connman_setting_get_bool("INSInternet");

	ins_settings.last_user_selection_score = connman_setting_get_uint("INSLastUserSelectionScore");
	ins_settings.last_connected_score = connman_setting_get_uint("INSLastConnectedScore");
	ins_settings.preferred_freq_score = connman_setting_get_uint("INSPreferredFreqScore");
	ins_settings.internet_score = connman_setting_get_uint("INSInternetScore");

	ins_settings.signal_level3_5ghz = connman_setting_get_int("INSSignalLevel3_5GHz");
	ins_settings.signal_level3_24ghz = connman_setting_get_int("INSSignalLevel3_24GHz");

	DBG("last_user_selection [%s]", ins_settings.last_user_selection ? "true" : "false");
	DBG("last_user_selection_time [%d]", ins_settings.last_user_selection_time);
	DBG("last_user_selection_score [%d]", ins_settings.last_user_selection_score);

	DBG("last_connected [%s]", ins_settings.last_connected ? "true" : "false");
	DBG("last_connected_score [%d]", ins_settings.last_connected_score);

	DBG("preferred_freq [%s]", ins_settings.preferred_freq ? "true" : "false");
	DBG("preferred_freq_score [%d]", ins_settings.preferred_freq_score);

	DBG("security_priority_count [%d]", ins_settings.security_priority_count);
	for (i = 0; i < CONNMAN_SERVICE_SECURITY_MAX; i++) {
		if (ins_settings.security_priority[i])
			DBG("security_priority %s [%d]", security2string(i),
					ins_settings.security_priority[i]);
	}
	DBG("security_priority_score [%d]", ins_settings.security_priority_score);

	DBG("signal [%s]", ins_settings.signal ? "true" : "false");

	DBG("internet [%s]", ins_settings.internet ? "true" : "false");
	DBG("internet_score [%d]", ins_settings.internet_score);

	DBG("signal_level3_5ghz [%d]", ins_settings.signal_level3_5ghz);
	DBG("signal_level3_24ghz [%d]", ins_settings.signal_level3_24ghz);
}
#endif

int __connman_service_init(void)
{
	int err;

	DBG("");

	err = connman_agent_driver_register(&agent_driver);
	if (err < 0) {
		connman_error("Cannot register agent driver for %s",
						agent_driver.name);
		return err;
	}

	set_always_connecting_technologies();

	connection = connman_dbus_get_connection();

	service_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, service_free);

	services_notify = g_new0(struct _services_notify, 1);
	services_notify->remove = g_hash_table_new_full(g_str_hash,
			g_str_equal, g_free, NULL);
	services_notify->add = g_hash_table_new(g_str_hash, g_str_equal);

	remove_unprovisioned_services();

#if defined TIZEN_EXT
	ins_setting_init();
#endif

	return 0;
}

void __connman_service_cleanup(void)
{
	DBG("");

	if (vpn_autoconnect_id) {
		g_source_remove(vpn_autoconnect_id);
		vpn_autoconnect_id = 0;
	}

	if (autoconnect_id != 0) {
		g_source_remove(autoconnect_id);
		autoconnect_id = 0;
	}

	connman_agent_driver_unregister(&agent_driver);

	g_list_free(service_list);
	service_list = NULL;

	g_hash_table_destroy(service_hash);
	service_hash = NULL;

	g_slist_free(counter_list);
	counter_list = NULL;

	if (services_notify->id != 0) {
		g_source_remove(services_notify->id);
		service_send_changed(NULL);
	}

	g_hash_table_destroy(services_notify->remove);
	g_hash_table_destroy(services_notify->add);
	g_free(services_notify);

	dbus_connection_unref(connection);
}
