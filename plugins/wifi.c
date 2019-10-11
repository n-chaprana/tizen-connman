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

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/wireless.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

#include <dbus/dbus.h>
#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/inet.h>
#include <connman/device.h>
#include <connman/rtnl.h>
#include <connman/technology.h>
#include <connman/service.h>
#include <connman/peer.h>
#include <connman/log.h>
#include <connman/option.h>
#include <connman/storage.h>
#include <include/setting.h>
#include <connman/provision.h>
#include <connman/utsname.h>
#include <connman/machine.h>
#include <connman/tethering.h>

#include <gsupplicant/gsupplicant.h>

#define CLEANUP_TIMEOUT   8	/* in seconds */
#define INACTIVE_TIMEOUT  12	/* in seconds */
#define FAVORITE_MAXIMUM_RETRIES 2

#define BGSCAN_DEFAULT "simple:30:-45:300"
#define AUTOSCAN_EXPONENTIAL "exponential:3:300"
#define AUTOSCAN_SINGLE "single:3"

#define P2P_FIND_TIMEOUT 30
#define P2P_CONNECTION_TIMEOUT 100
#define P2P_LISTEN_PERIOD 500
#define P2P_LISTEN_INTERVAL 2000

#define ASSOC_STATUS_NO_CLIENT 17
#if defined TIZEN_EXT
#define LOAD_SHAPING_MAX_RETRIES 7
#else
#define LOAD_SHAPING_MAX_RETRIES 3
#endif

#if defined TIZEN_EXT
#define WIFI_EAP_FAST_PAC_FILE		"/var/lib/wifi/wifi.pac"	/* path of Pac file for EAP-FAST */
#endif

static struct connman_technology *wifi_technology = NULL;
static struct connman_technology *p2p_technology = NULL;

enum wifi_ap_capability{
	WIFI_AP_UNKNOWN 	= 0,
	WIFI_AP_SUPPORTED 	= 1,
	WIFI_AP_NOT_SUPPORTED 	= 2,
};

enum wifi_scanning_type {
	WIFI_SCANNING_UNKNOWN	= 0,
	WIFI_SCANNING_PASSIVE	= 1,
	WIFI_SCANNING_ACTIVE	= 2,
};

struct hidden_params {
	char ssid[32];
	unsigned int ssid_len;
	char *identity;
	char *anonymous_identity;
	char *subject_match;
	char *altsubject_match;
	char *domain_suffix_match;
	char *domain_match;
	char *passphrase;
	char *security;
	GSupplicantScanParams *scan_params;
	gpointer user_data;
};

/**
 * Used for autoscan "emulation".
 * Should be removed when wpa_s autoscan support will be by default.
 */
struct autoscan_params {
	int base;
	int limit;
	int interval;
	unsigned int timeout;
};

struct wifi_tethering_info {
	struct wifi_data *wifi;
	struct connman_technology *technology;
	char *ifname;
	GSupplicantSSID *ssid;
};

struct wifi_data {
	char *identifier;
	struct connman_device *device;
	struct connman_network *network;
	struct connman_network *pending_network;
	GSList *networks;
	GSupplicantInterface *interface;
	GSupplicantState state;
	bool connected;
	bool disconnecting;
	bool tethering;
	enum wifi_ap_capability ap_supported;
	bool bridged;
	bool interface_ready;
	const char *bridge;
	int index;
	unsigned flags;
	unsigned int watch;
	int retries;
	int load_shaping_retries;
	struct hidden_params *hidden;
	bool postpone_hidden;
	struct wifi_tethering_info *tethering_param;
	/**
	 * autoscan "emulation".
	 */
	struct autoscan_params *autoscan;
	enum wifi_scanning_type scanning_type;
	GSupplicantScanParams *scan_params;
	unsigned int p2p_find_timeout;
	unsigned int p2p_connection_timeout;
	struct connman_peer *pending_peer;
	GSList *peers;
	bool p2p_connecting;
	bool p2p_device;
	int servicing;
#if defined TIZEN_EXT
	int assoc_retry_count;
	struct connman_network *scan_pending_network;
	bool allow_full_scan;
	unsigned int automaxspeed_timeout;
	GSupplicantScanParams *hidden_scan_params;
#endif
	int disconnect_code;
	int assoc_code;
#if defined TIZEN_EXT_WIFI_MESH
	bool mesh_interface;
	struct wifi_mesh_info *mesh_info;
#endif
};

#if defined TIZEN_EXT
#include "connman.h"
#include "dbus.h"

#define TIZEN_ASSOC_RETRY_COUNT		4

static gboolean wifi_first_scan = false;
static gboolean found_with_first_scan = false;
static gboolean is_wifi_notifier_registered = false;
static GHashTable *failed_bssids = NULL;
static unsigned char buff_bssid[WIFI_BSSID_LEN_MAX] = { 0, };
#endif


static GList *iface_list = NULL;

static GList *pending_wifi_device = NULL;
static GList *p2p_iface_list = NULL;
static bool wfd_service_registered = false;

static void start_autoscan(struct connman_device *device);
static int tech_set_tethering(struct connman_technology *technology,
				const char *identifier, const char *passphrase,
				const char *bridge, bool enabled);

#if defined TIZEN_EXT
#define NETCONFIG_SERVICE "net.netconfig"
#define NETCONFIG_WIFI_PATH "/net/netconfig/wifi"
#define NETCONFIG_WIFI_INTERFACE NETCONFIG_SERVICE ".wifi"

struct enc_method_call_data {
	DBusConnection *connection;
	struct connman_network *network;
};

static struct enc_method_call_data encrypt_request_data;

static void encryption_request_reply(DBusPendingCall *call,
						void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter args;
	char *out_data;
	struct connman_service *service;
	gchar* encrypted_value = NULL;
	struct connman_network *network = encrypt_request_data.network;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);
	if (dbus_set_error_from_message(&error, reply)) {
		DBG("send_encryption_request() %s %s", error.name, error.message);
		dbus_error_free(&error);
		goto done;
	}

	if (dbus_message_iter_init(reply, &args) == FALSE)
		goto done;

	dbus_message_iter_get_basic(&args, &out_data);

	encrypted_value = g_strdup((const gchar *)out_data);
	service = connman_service_lookup_from_network(network);

	if (!service) {
		DBG("encryption result: no service");
		goto done;
	}

	if (connman_service_get_favorite(service)) {
		__connman_service_set_passphrase(service, encrypted_value);
		__connman_service_save(service);
	} else
		connman_network_set_string(network, "WiFi.Passphrase",
							encrypted_value);

	DBG("encryption result: succeeded");

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
	dbus_connection_unref(encrypt_request_data.connection);
	g_free(encrypted_value);

	encrypt_request_data.connection = NULL;
	encrypt_request_data.network = NULL;
}

static int send_encryption_request(const char *passphrase,
				struct connman_network *network)
{
	DBusConnection *connection = NULL;
	DBusMessage *msg = NULL;
	DBusPendingCall *call;

	if (!passphrase) {
		DBG("Invalid parameter");
		return -EINVAL;
	}

	connection = connman_dbus_get_connection();
	if (!connection) {
		DBG("dbus connection does not exist");
		return -EINVAL;
	}

	msg = dbus_message_new_method_call(NETCONFIG_SERVICE, NETCONFIG_WIFI_PATH,
			NETCONFIG_WIFI_INTERFACE, "EncryptPassphrase");
	if (!msg) {
		dbus_connection_unref(connection);
		return -EINVAL;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &passphrase,
							DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection, msg,
				&call, DBUS_TIMEOUT_USE_DEFAULT)) {
		dbus_message_unref(msg);
		dbus_connection_unref(connection);
		return -EIO;
	}

	if (!call) {
		dbus_message_unref(msg);
		dbus_connection_unref(connection);
		return -EIO;
	}

	encrypt_request_data.connection = connection;
	encrypt_request_data.network = network;

	dbus_pending_call_set_notify(call, encryption_request_reply, NULL, NULL);
	dbus_message_unref(msg);

	return 0;
}
#endif

static int p2p_tech_probe(struct connman_technology *technology)
{
	p2p_technology = technology;

	return 0;
}

static void p2p_tech_remove(struct connman_technology *technology)
{
	p2p_technology = NULL;
}

static struct connman_technology_driver p2p_tech_driver = {
	.name		= "p2p",
	.type		= CONNMAN_SERVICE_TYPE_P2P,
	.probe		= p2p_tech_probe,
	.remove		= p2p_tech_remove,
};

static bool is_p2p_connecting(void)
{
	GList *list;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;

		if (wifi->p2p_connecting)
			return true;
	}

	return false;
}

static void add_pending_wifi_device(struct wifi_data *wifi)
{
	if (g_list_find(pending_wifi_device, wifi))
		return;

	pending_wifi_device = g_list_append(pending_wifi_device, wifi);
}

#if defined TIZEN_EXT_WIFI_MESH
struct wifi_mesh_info {
	struct wifi_data *wifi;
	GSupplicantInterface *interface;
	struct connman_mesh *mesh;
	char *parent_ifname;
	char *ifname;
	char *identifier;
	int index;
};

struct mesh_change_peer_status_info {
	char *peer_address;
	enum connman_mesh_peer_status peer_status;
	mesh_change_peer_status_cb_t callback;
	void *user_data;
};

static struct connman_technology_driver mesh_tech_driver = {
	.name = "mesh",
	.type = CONNMAN_SERVICE_TYPE_MESH,
};

static void mesh_interface_create_callback(int result,
					   GSupplicantInterface *interface,
					   void *user_data)
{
	struct wifi_mesh_info *mesh_info = user_data;
	struct wifi_data *wifi;
	bool success = false;

	DBG("result %d ifname %s, mesh_info %p", result,
				g_supplicant_interface_get_ifname(interface),
				mesh_info);

	if (result < 0 || !mesh_info)
		goto done;

	wifi = mesh_info->wifi;

	mesh_info->interface = interface;
	mesh_info->identifier = connman_inet_ifaddr(mesh_info->ifname);
	mesh_info->index = connman_inet_ifindex(mesh_info->ifname);
	DBG("Mesh Interface identifier %s", mesh_info->identifier);
	wifi->mesh_interface = true;
	wifi->mesh_info = mesh_info;
	g_supplicant_interface_set_data(interface, wifi);
	success = true;

done:
	connman_mesh_notify_interface_create(success);
}

static int add_mesh_interface(const char *ifname, const char *parent_ifname)
{
	GList *list;
	struct wifi_data *wifi;
	struct wifi_mesh_info *mesh_info;
	const char *wifi_ifname;
	bool parent_found = false;
	const char *driver = "nl80211";

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;

		if (!g_supplicant_interface_has_mesh(wifi->interface))
			continue;

		wifi_ifname = g_supplicant_interface_get_ifname(wifi->interface);
		if (!wifi_ifname)
			continue;

		if (!g_strcmp0(wifi_ifname, parent_ifname)) {
			parent_found = true;
			break;
		}
	}

	if (!parent_found) {
		DBG("Parent interface %s doesn't exist", parent_ifname);
		return -ENODEV;
	}

	mesh_info = g_try_malloc0(sizeof(struct wifi_mesh_info));
	if (!mesh_info)
		return -ENOMEM;

	mesh_info->wifi = wifi;
	mesh_info->ifname = g_strdup(ifname);
	mesh_info->parent_ifname = g_strdup(parent_ifname);

	g_supplicant_mesh_interface_create(ifname, driver, NULL, parent_ifname,
						mesh_interface_create_callback, mesh_info);
	return -EINPROGRESS;
}

static void mesh_interface_remove_callback(int result,
					GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_data *wifi = user_data;
	struct wifi_mesh_info *mesh_info = wifi->mesh_info;
	bool success = false;

	DBG("result %d mesh_info %p", result, mesh_info);

	if (result < 0 || !mesh_info)
		goto done;

	mesh_info->interface = NULL;
	g_free(mesh_info->parent_ifname);
	g_free(mesh_info->ifname);
	g_free(mesh_info->identifier);
	g_free(mesh_info);
	wifi->mesh_interface = false;
	wifi->mesh_info = NULL;
	success = true;

done:
	connman_mesh_notify_interface_remove(success);
}

static int remove_mesh_interface(const char *ifname)
{
	GList *list;
	struct wifi_data *wifi;
	struct wifi_mesh_info *mesh_info;
	bool mesh_if_found = false;
	int ret;

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;

		if (wifi->mesh_interface) {
			mesh_if_found = true;
			break;
		}
	}

	if (!mesh_if_found) {
		DBG("Mesh interface %s doesn't exist", ifname);
		return -ENODEV;
	}

	mesh_info = wifi->mesh_info;
	ret = g_supplicant_interface_remove(mesh_info->interface,
						mesh_interface_remove_callback, wifi);
	if (ret < 0)
		return ret;

	return -EINPROGRESS;
}

static void mesh_disconnect_callback(int result,
					GSupplicantInterface *interface, void *user_data)
{
	struct connman_mesh *mesh = user_data;

	DBG("result %d interface %p mesh %p", result, interface, mesh);
}

static int mesh_peer_disconnect(struct connman_mesh *mesh)
{
	GList *list;
	struct wifi_data *wifi;
	struct wifi_mesh_info *mesh_info;
	bool mesh_if_found = false;
	GSupplicantInterface *interface;

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;

		if (wifi->mesh_interface) {
			mesh_if_found = true;
			break;
		}
	}

	if (!mesh_if_found) {
		DBG("Mesh interface is not created");
		return -ENODEV;
	}

	mesh_info = wifi->mesh_info;

	interface = mesh_info->interface;
	return g_supplicant_interface_disconnect(interface,
						mesh_disconnect_callback, mesh);
}

static void mesh_connect_callback(int result, GSupplicantInterface *interface,
								  void *user_data)
{
	struct connman_mesh *mesh = user_data;
	DBG("mesh %p result %d", mesh, result);

	if (result < 0)
		connman_mesh_peer_set_state(mesh, CONNMAN_MESH_STATE_FAILURE);
	else
		connman_mesh_peer_set_state(mesh, CONNMAN_MESH_STATE_ASSOCIATION);
}

static GSupplicantSecurity mesh_network_security(const char *security)
{
	if (g_str_equal(security, "none"))
		return G_SUPPLICANT_SECURITY_NONE;
	else if (g_str_equal(security, "sae"))
		return G_SUPPLICANT_SECURITY_SAE;

	return G_SUPPLICANT_SECURITY_UNKNOWN;
}

static void mesh_ssid_init(GSupplicantSSID *ssid, struct connman_mesh *mesh)
{
	const char *name;
	const char *security;

	if (ssid->ssid)
		g_free(ssid->ssid);

	memset(ssid, 0, sizeof(*ssid));
	ssid->mode = G_SUPPLICANT_MODE_MESH;

	security = connman_mesh_get_security(mesh);
	ssid->security = mesh_network_security(security);

	if (ssid->security == G_SUPPLICANT_SECURITY_SAE)
		ssid->passphrase = connman_mesh_get_passphrase(mesh);

	ssid->freq = connman_mesh_get_frequency(mesh);
	name = connman_mesh_get_name(mesh);
	if (name) {
		ssid->ssid_len = strlen(name);
		ssid->ssid = g_malloc0(ssid->ssid_len + 1);
		memcpy(ssid->ssid, name, ssid->ssid_len);
		ssid->scan_ssid = 1;
	}
}

static int mesh_peer_connect(struct connman_mesh *mesh)
{
	GList *list;
	struct wifi_data *wifi;
	struct wifi_mesh_info *mesh_info;
	bool mesh_if_found = false;
	GSupplicantInterface *interface;
	GSupplicantSSID *ssid;

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;

		if (wifi->mesh_interface) {
			mesh_if_found = true;
			break;
		}
	}

	if (!mesh_if_found) {
		DBG("Mesh interface is not created");
		return -ENODEV;
	}

	mesh_info = wifi->mesh_info;

	interface = mesh_info->interface;

	ssid = g_try_malloc0(sizeof(GSupplicantSSID));
	if (!ssid)
		return -ENOMEM;

	mesh_info->mesh = mesh;

	mesh_ssid_init(ssid, mesh);
	return g_supplicant_interface_connect(interface, ssid,
						mesh_connect_callback, mesh);
}

static void mesh_peer_change_status_callback(int result,
					     GSupplicantInterface *interface,
					     void *user_data)
{
	struct mesh_change_peer_status_info *data = user_data;

	DBG("result %d Peer Status %d", result, data->peer_status);

	if (result == 0 && data->peer_status == CONNMAN_MESH_PEER_REMOVE) {
		/* WLAN_REASON_MESH_PEERING_CANCELLED = 52 */
		connman_mesh_remove_connected_peer(data->peer_address, 52);
	}

	if (data->callback)
		data->callback(result, data->user_data);

	g_free(data->peer_address);
	g_free(data);
	return;
}

static int mesh_change_peer_status(const char *peer_address,
				   enum connman_mesh_peer_status status,
				   mesh_change_peer_status_cb_t callback, void *user_data)
{
	GList *list;
	struct wifi_data *wifi;
	struct wifi_mesh_info *mesh_info;
	bool mesh_if_found = false;
	GSupplicantInterface *interface;
	struct mesh_change_peer_status_info *data;
	const char *method;

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;

		if (wifi->mesh_interface) {
			mesh_if_found = true;
			break;
		}
	}

	if (!mesh_if_found) {
		DBG("Mesh interface is not created");
		return -ENODEV;
	}

	mesh_info = wifi->mesh_info;

	interface = mesh_info->interface;

	switch (status) {
	case CONNMAN_MESH_PEER_ADD:
		method = "MeshPeerAdd";
		break;
	case CONNMAN_MESH_PEER_REMOVE:
		method = "MeshPeerRemove";
		break;
	default:
		DBG("Invalid method");
		return -EINVAL;
	}

	data = g_try_malloc0(sizeof(struct mesh_change_peer_status_info));
	if (data == NULL) {
		DBG("Memory allocation failed");
		return -ENOMEM;
	}

	data->peer_address = g_strdup(peer_address);
	data->peer_status = status;
	data->callback = callback;
	data->user_data = user_data;

	return g_supplicant_interface_mesh_peer_change_status(interface,
						mesh_peer_change_status_callback, peer_address, method,
						data);
}

static struct connman_mesh_driver mesh_driver = {
	.add_interface      = add_mesh_interface,
	.remove_interface   = remove_mesh_interface,
	.connect            = mesh_peer_connect,
	.disconnect         = mesh_peer_disconnect,
	.change_peer_status = mesh_change_peer_status,
};

static void mesh_support(GSupplicantInterface *interface)
{
	DBG("");

	if (!g_supplicant_interface_has_mesh(interface))
		return;

	if (connman_technology_driver_register(&mesh_tech_driver) < 0) {
		DBG("Could not register Mesh technology driver");
		return;
	}

	connman_mesh_driver_register(&mesh_driver);
}

static void check_mesh_technology(void)
{
	bool mesh_exists = false;
	GList *list;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *w = list->data;

		if (w->interface &&
				g_supplicant_interface_has_mesh(w->interface))
			mesh_exists = true;
	}

	if (!mesh_exists) {
		connman_technology_driver_unregister(&mesh_tech_driver);
		connman_mesh_driver_unregister(&mesh_driver);
	}
}

static void mesh_group_started(GSupplicantInterface *interface)
{
	struct wifi_data *wifi;
	struct wifi_mesh_info *mesh_info;
	struct connman_mesh *mesh;
	const unsigned char *ssid;
	unsigned int ssid_len;
	char name[33];

	ssid = g_supplicant_interface_get_mesh_group_ssid(interface, &ssid_len);
	memcpy(name, ssid, ssid_len);
	name[ssid_len] = '\0';
	DBG("name %s", name);
	wifi = g_supplicant_interface_get_data(interface);
	DBG("wifi %p", wifi);

	if (!wifi)
		return;

	mesh_info = wifi->mesh_info;
	if (!mesh_info)
		return;

	mesh = mesh_info->mesh;
	if (!mesh)
		return;

	connman_mesh_peer_set_state(mesh, CONNMAN_MESH_STATE_CONFIGURATION);
}

static void mesh_group_removed(GSupplicantInterface *interface)
{
	struct wifi_data *wifi;
	struct wifi_mesh_info *mesh_info;
	struct connman_mesh *mesh;
	const unsigned char *ssid;
	unsigned int ssid_len;
	int disconnect_reason;
	char name[33];

	ssid = g_supplicant_interface_get_mesh_group_ssid(interface, &ssid_len);
	memcpy(name, ssid, ssid_len);
	name[ssid_len] = '\0';
	DBG("name %s", name);

	disconnect_reason = g_supplicant_mesh_get_disconnect_reason(interface);
	DBG("Disconnect Reason %d", disconnect_reason);

	wifi = g_supplicant_interface_get_data(interface);
	DBG("wifi %p", wifi);

	if (!wifi)
		return;

	mesh_info = wifi->mesh_info;
	if (!mesh_info)
		return;

	mesh = connman_get_connected_mesh_from_name(name);
	if (!mesh) {
		DBG("%s is not connected", name);
		mesh = connman_get_connecting_mesh_from_name(name);
		if (!mesh) {
			DBG("%s is not connecting", name);
			return;
		}
	}

	connman_mesh_peer_set_disconnect_reason(mesh, disconnect_reason);
	connman_mesh_peer_set_state(mesh, CONNMAN_MESH_STATE_DISCONNECT);
}

static void mesh_peer_connected(GSupplicantMeshPeer *mesh_peer)
{
	const char *peer_address;

	peer_address = g_supplicant_mesh_peer_get_address(mesh_peer);

	if (!peer_address)
		return;

	DBG("Peer %s connected", peer_address);
	connman_mesh_add_connected_peer(peer_address);
}

static void mesh_peer_disconnected(GSupplicantMeshPeer *mesh_peer)
{
	const char *peer_address;
	int reason;

	peer_address = g_supplicant_mesh_peer_get_address(mesh_peer);

	if (!peer_address)
		return;

	reason = g_supplicant_mesh_peer_get_disconnect_reason(mesh_peer);

	DBG("Peer %s disconnected with reason %d", peer_address, reason);
	connman_mesh_remove_connected_peer(peer_address, reason);
}
#endif

static struct wifi_data *get_pending_wifi_data(const char *ifname)
{
	GList *list;

	for (list = pending_wifi_device; list; list = list->next) {
		struct wifi_data *wifi;
		const char *dev_name;

		wifi = list->data;
		if (!wifi || !wifi->device)
			continue;

		dev_name = connman_device_get_string(wifi->device, "Interface");
		if (!g_strcmp0(ifname, dev_name)) {
			pending_wifi_device = g_list_delete_link(
						pending_wifi_device, list);
			return wifi;
		}
	}

	return NULL;
}

static void remove_pending_wifi_device(struct wifi_data *wifi)
{
	GList *link;

	link = g_list_find(pending_wifi_device, wifi);

	if (!link)
		return;

	pending_wifi_device = g_list_delete_link(pending_wifi_device, link);
}

static void peer_cancel_timeout(struct wifi_data *wifi)
{
	if (wifi->p2p_connection_timeout > 0)
		g_source_remove(wifi->p2p_connection_timeout);

	wifi->p2p_connection_timeout = 0;
	wifi->p2p_connecting = false;

	if (wifi->pending_peer) {
		connman_peer_unref(wifi->pending_peer);
		wifi->pending_peer = NULL;
	}
}

static gboolean peer_connect_timeout(gpointer data)
{
	struct wifi_data *wifi = data;

	DBG("");

	if (wifi->p2p_connecting) {
		enum connman_peer_state state = CONNMAN_PEER_STATE_FAILURE;
		GSupplicantPeer *gs_peer =
			g_supplicant_interface_peer_lookup(wifi->interface,
				connman_peer_get_identifier(wifi->pending_peer));

		if (g_supplicant_peer_has_requested_connection(gs_peer))
			state = CONNMAN_PEER_STATE_IDLE;

		connman_peer_set_state(wifi->pending_peer, state);
	}

	peer_cancel_timeout(wifi);

	return FALSE;
}

static void peer_connect_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_data *wifi = user_data;
	struct connman_peer *peer = wifi->pending_peer;

	DBG("peer %p - %d", peer, result);

	if (!peer)
		return;

	if (result < 0) {
		peer_connect_timeout(wifi);
		return;
	}

	connman_peer_set_state(peer, CONNMAN_PEER_STATE_ASSOCIATION);

	wifi->p2p_connection_timeout = g_timeout_add_seconds(
						P2P_CONNECTION_TIMEOUT,
						peer_connect_timeout, wifi);
}

static int peer_connect(struct connman_peer *peer,
			enum connman_peer_wps_method wps_method,
			const char *wps_pin)
{
	struct connman_device *device = connman_peer_get_device(peer);
	GSupplicantPeerParams *peer_params;
	GSupplicantPeer *gs_peer;
	struct wifi_data *wifi;
	bool pbc, pin;
	int ret;

	DBG("peer %p", peer);

	if (!device)
		return -ENODEV;

	wifi = connman_device_get_data(device);
	if (!wifi || !wifi->interface)
		return -ENODEV;

	if (wifi->p2p_connecting)
		return -EBUSY;

	gs_peer = g_supplicant_interface_peer_lookup(wifi->interface,
					connman_peer_get_identifier(peer));
	if (!gs_peer)
		return -EINVAL;

	pbc = g_supplicant_peer_is_wps_pbc(gs_peer);
	pin = g_supplicant_peer_is_wps_pin(gs_peer);

	switch (wps_method) {
	case CONNMAN_PEER_WPS_UNKNOWN:
		if ((pbc && pin) || pin)
			return -ENOKEY;
		break;
	case CONNMAN_PEER_WPS_PBC:
		if (!pbc)
			return -EINVAL;
		wps_pin = NULL;
		break;
	case CONNMAN_PEER_WPS_PIN:
		if (!pin || !wps_pin)
			return -EINVAL;
		break;
	}

	peer_params = g_try_malloc0(sizeof(GSupplicantPeerParams));
	if (!peer_params)
		return -ENOMEM;

	peer_params->path = g_strdup(g_supplicant_peer_get_path(gs_peer));
	if (wps_pin)
		peer_params->wps_pin = g_strdup(wps_pin);

	peer_params->master = connman_peer_service_is_master();

	ret = g_supplicant_interface_p2p_connect(wifi->interface, peer_params,
						peer_connect_callback, wifi);
	if (ret == -EINPROGRESS) {
		wifi->pending_peer = connman_peer_ref(peer);
		wifi->p2p_connecting = true;
	} else if (ret < 0) {
		g_free(peer_params->path);
		g_free(peer_params->wps_pin);
		g_free(peer_params);
	}

	return ret;
}

static int peer_disconnect(struct connman_peer *peer)
{
	struct connman_device *device = connman_peer_get_device(peer);
	GSupplicantPeerParams peer_params = {};
	GSupplicantPeer *gs_peer;
	struct wifi_data *wifi;
	int ret;

	DBG("peer %p", peer);

	if (!device)
		return -ENODEV;

	wifi = connman_device_get_data(device);
	if (!wifi)
		return -ENODEV;

	gs_peer = g_supplicant_interface_peer_lookup(wifi->interface,
					connman_peer_get_identifier(peer));
	if (!gs_peer)
		return -EINVAL;

	peer_params.path = g_strdup(g_supplicant_peer_get_path(gs_peer));

	ret = g_supplicant_interface_p2p_disconnect(wifi->interface,
							&peer_params);
	g_free(peer_params.path);

	if (ret == -EINPROGRESS) {
		peer_cancel_timeout(wifi);
		wifi->p2p_device = false;
	}

	return ret;
}

struct peer_service_registration {
	peer_service_registration_cb_t callback;
	void *user_data;
};

static bool is_service_wfd(const unsigned char *specs, int length)
{
	if (length < 9 || specs[0] != 0 || specs[1] != 0 || specs[2] != 6)
		return false;

	return true;
}

static void apply_p2p_listen_on_iface(gpointer data, gpointer user_data)
{
	struct wifi_data *wifi = data;

	if (!wifi->interface ||
			!g_supplicant_interface_has_p2p(wifi->interface))
		return;

	if (!wifi->servicing) {
		g_supplicant_interface_p2p_listen(wifi->interface,
				P2P_LISTEN_PERIOD, P2P_LISTEN_INTERVAL);
	}

	wifi->servicing++;
}

static void register_wfd_service_cb(int result,
				GSupplicantInterface *iface, void *user_data)
{
	struct peer_service_registration *reg_data = user_data;

	DBG("");

	if (result == 0)
		g_list_foreach(iface_list, apply_p2p_listen_on_iface, NULL);

	if (reg_data && reg_data->callback) {
		reg_data->callback(result, reg_data->user_data);
		g_free(reg_data);
	}
}

static GSupplicantP2PServiceParams *fill_in_peer_service_params(
				const unsigned char *spec,
				int spec_length, const unsigned char *query,
				int query_length, int version)
{
	GSupplicantP2PServiceParams *params;

	params = g_try_malloc0(sizeof(GSupplicantP2PServiceParams));
	if (!params)
		return NULL;

	if (version > 0) {
		params->version = version;
		params->service = g_memdup(spec, spec_length);
	} else if (query_length > 0 && spec_length > 0) {
		params->query = g_memdup(query, query_length);
		params->query_length = query_length;

		params->response = g_memdup(spec, spec_length);
		params->response_length = spec_length;
	} else {
		params->wfd_ies = g_memdup(spec, spec_length);
		params->wfd_ies_length = spec_length;
	}

	return params;
}

static void free_peer_service_params(GSupplicantP2PServiceParams *params)
{
	if (!params)
		return;

	g_free(params->service);
	g_free(params->query);
	g_free(params->response);
	g_free(params->wfd_ies);

	g_free(params);
}

static int peer_register_wfd_service(const unsigned char *specification,
				int specification_length,
				peer_service_registration_cb_t callback,
				void *user_data)
{
	struct peer_service_registration *reg_data = NULL;
	static GSupplicantP2PServiceParams *params;
	int ret;

	DBG("");

	if (wfd_service_registered)
		return -EBUSY;

	params = fill_in_peer_service_params(specification,
					specification_length, NULL, 0, 0);
	if (!params)
		return -ENOMEM;

	reg_data = g_try_malloc0(sizeof(*reg_data));
	if (!reg_data) {
		ret = -ENOMEM;
		goto error;
	}

	reg_data->callback = callback;
	reg_data->user_data = user_data;

	ret = g_supplicant_set_widi_ies(params,
					register_wfd_service_cb, reg_data);
	if (ret < 0 && ret != -EINPROGRESS)
		goto error;

	wfd_service_registered = true;

	return ret;
error:
	free_peer_service_params(params);
	g_free(reg_data);

	return ret;
}

static void register_peer_service_cb(int result,
				GSupplicantInterface *iface, void *user_data)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(iface);
	struct peer_service_registration *reg_data = user_data;

#if defined TIZEN_EXT
	if (!wifi)
		return;
#endif

	DBG("");

	if (result == 0)
		apply_p2p_listen_on_iface(wifi, NULL);

	if (reg_data->callback)
		reg_data->callback(result, reg_data->user_data);

	g_free(reg_data);
}

static int peer_register_service(const unsigned char *specification,
				int specification_length,
				const unsigned char *query,
				int query_length, int version,
				peer_service_registration_cb_t callback,
				void *user_data)
{
	struct peer_service_registration *reg_data;
	GSupplicantP2PServiceParams *params;
	bool found = false;
	int ret, ret_f;
	GList *list;

	DBG("");

	if (specification && !version && !query &&
			is_service_wfd(specification, specification_length)) {
		return peer_register_wfd_service(specification,
				specification_length, callback, user_data);
	}

	reg_data = g_try_malloc0(sizeof(*reg_data));
	if (!reg_data)
		return -ENOMEM;

	reg_data->callback = callback;
	reg_data->user_data = user_data;

	ret_f = -EOPNOTSUPP;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;
		GSupplicantInterface *iface = wifi->interface;

		if (!g_supplicant_interface_has_p2p(iface))
			continue;

		params = fill_in_peer_service_params(specification,
						specification_length, query,
						query_length, version);
		if (!params)
			continue;

		if (!found) {
			ret_f = g_supplicant_interface_p2p_add_service(iface,
				register_peer_service_cb, params, reg_data);
			if (ret_f == 0 || ret_f == -EINPROGRESS)
				found = true;
			ret = ret_f;
		} else
			ret = g_supplicant_interface_p2p_add_service(iface,
				register_peer_service_cb, params, NULL);
		if (ret != 0 && ret != -EINPROGRESS)
			free_peer_service_params(params);
	}

	if (ret_f != 0 && ret_f != -EINPROGRESS)
		g_free(reg_data);

	return ret_f;
}

static int peer_unregister_wfd_service(void)
{
	GSupplicantP2PServiceParams *params;
	GList *list;

	if (!wfd_service_registered)
		return -EALREADY;

	params = fill_in_peer_service_params(NULL, 0, NULL, 0, 0);
	if (!params)
		return -ENOMEM;

	wfd_service_registered = false;

	g_supplicant_set_widi_ies(params, NULL, NULL);

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;

		if (!g_supplicant_interface_has_p2p(wifi->interface))
			continue;

		wifi->servicing--;
		if (!wifi->servicing || wifi->servicing < 0) {
			g_supplicant_interface_p2p_listen(wifi->interface,
									0, 0);
			wifi->servicing = 0;
		}
	}

	return 0;
}

static int peer_unregister_service(const unsigned char *specification,
						int specification_length,
						const unsigned char *query,
						int query_length, int version)
{
	GSupplicantP2PServiceParams *params;
	bool wfd = false;
	GList *list;
	int ret;

	if (specification && !version && !query &&
			is_service_wfd(specification, specification_length)) {
		ret = peer_unregister_wfd_service();
		if (ret != 0 && ret != -EINPROGRESS)
			return ret;
		wfd = true;
	}

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;
		GSupplicantInterface *iface = wifi->interface;

		if (wfd)
			goto stop_listening;

		if (!g_supplicant_interface_has_p2p(iface))
			continue;

		params = fill_in_peer_service_params(specification,
						specification_length, query,
						query_length, version);
		if (!params)
			continue;

		ret = g_supplicant_interface_p2p_del_service(iface, params);
		if (ret != 0 && ret != -EINPROGRESS)
			free_peer_service_params(params);
stop_listening:
		wifi->servicing--;
		if (!wifi->servicing || wifi->servicing < 0) {
			g_supplicant_interface_p2p_listen(iface, 0, 0);
			wifi->servicing = 0;
		}
	}

	return 0;
}

static struct connman_peer_driver peer_driver = {
	.connect    = peer_connect,
	.disconnect = peer_disconnect,
	.register_service = peer_register_service,
	.unregister_service = peer_unregister_service,
};

static void handle_tethering(struct wifi_data *wifi)
{
	if (!wifi->tethering)
		return;

	if (!wifi->bridge)
		return;

	if (wifi->bridged)
		return;

	DBG("index %d bridge %s", wifi->index, wifi->bridge);

	if (connman_inet_add_to_bridge(wifi->index, wifi->bridge) < 0)
		return;

	wifi->bridged = true;
}

static void wifi_newlink(unsigned flags, unsigned change, void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);

	if (!wifi)
		return;

	DBG("index %d flags %d change %d", wifi->index, flags, change);

	if ((wifi->flags & IFF_UP) != (flags & IFF_UP)) {
		if (flags & IFF_UP)
			DBG("interface up");
		else
			DBG("interface down");
	}

	if ((wifi->flags & IFF_LOWER_UP) != (flags & IFF_LOWER_UP)) {
		if (flags & IFF_LOWER_UP) {
			DBG("carrier on");

			handle_tethering(wifi);
		} else
			DBG("carrier off");
	}

	wifi->flags = flags;
}

static int wifi_probe(struct connman_device *device)
{
	struct wifi_data *wifi;

	DBG("device %p", device);

	wifi = g_try_new0(struct wifi_data, 1);
	if (!wifi)
		return -ENOMEM;

	wifi->state = G_SUPPLICANT_STATE_INACTIVE;
	wifi->ap_supported = WIFI_AP_UNKNOWN;
	wifi->tethering_param = NULL;

	connman_device_set_data(device, wifi);
	wifi->device = connman_device_ref(device);

	wifi->index = connman_device_get_index(device);
	wifi->flags = 0;

	wifi->watch = connman_rtnl_add_newlink_watch(wifi->index,
							wifi_newlink, device);
	if (is_p2p_connecting())
		add_pending_wifi_device(wifi);
	else
		iface_list = g_list_append(iface_list, wifi);

	return 0;
}

static void remove_networks(struct connman_device *device,
				struct wifi_data *wifi)
{
	GSList *list;

	for (list = wifi->networks; list; list = list->next) {
		struct connman_network *network = list->data;

		connman_device_remove_network(device, network);
		connman_network_unref(network);
	}

	g_slist_free(wifi->networks);
	wifi->networks = NULL;
}

static void remove_peers(struct wifi_data *wifi)
{
	GSList *list;

	for (list = wifi->peers; list; list = list->next) {
		struct connman_peer *peer = list->data;

		connman_peer_unregister(peer);
		connman_peer_unref(peer);
	}

	g_slist_free(wifi->peers);
	wifi->peers = NULL;
}

static void reset_autoscan(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	struct autoscan_params *autoscan;

	DBG("");

	if (!wifi || !wifi->autoscan)
		return;

	autoscan = wifi->autoscan;

	autoscan->interval = 0;

	if (autoscan->timeout == 0)
		return;

	g_source_remove(autoscan->timeout);
	autoscan->timeout = 0;

	connman_device_unref(device);
}

static void stop_autoscan(struct connman_device *device)
{
	const struct wifi_data *wifi = connman_device_get_data(device);

	if (!wifi || !wifi->autoscan)
		return;

	reset_autoscan(device);

	connman_device_set_scanning(device, CONNMAN_SERVICE_TYPE_WIFI, false);
}

static void check_p2p_technology(void)
{
	bool p2p_exists = false;
	GList *list;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *w = list->data;

		if (w->interface &&
				g_supplicant_interface_has_p2p(w->interface))
			p2p_exists = true;
	}

	if (!p2p_exists) {
		connman_technology_driver_unregister(&p2p_tech_driver);
		connman_peer_driver_unregister(&peer_driver);
	}
}

struct last_connected {
	GTimeVal modified;
	gchar *ssid;
	int freq;
};

static gint sort_entry(gconstpointer a, gconstpointer b, gpointer user_data)
{
	GTimeVal *aval = (GTimeVal *)a;
	GTimeVal *bval = (GTimeVal *)b;

	/* Note that the sort order is descending */
	if (aval->tv_sec < bval->tv_sec)
		return 1;

	if (aval->tv_sec > bval->tv_sec)
		return -1;

	return 0;
}

static void free_entry(gpointer data)
{
	struct last_connected *entry = data;

	g_free(entry->ssid);
	g_free(entry);
}

static void wifi_remove(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("device %p wifi %p", device, wifi);

	if (!wifi)
		return;

	stop_autoscan(device);

	if (wifi->p2p_device)
		p2p_iface_list = g_list_remove(p2p_iface_list, wifi);
	else
		iface_list = g_list_remove(iface_list, wifi);

	check_p2p_technology();
#if defined TIZEN_EXT_WIFI_MESH
	check_mesh_technology();
#endif

	remove_pending_wifi_device(wifi);

	if (connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_P2P)) {
		g_source_remove(wifi->p2p_find_timeout);
		connman_device_unref(wifi->device);
	}

	if (wifi->p2p_connection_timeout)
		g_source_remove(wifi->p2p_connection_timeout);

#if defined TIZEN_EXT
	if (wifi->automaxspeed_timeout != 0) {
		g_source_remove(wifi->automaxspeed_timeout);
		wifi->automaxspeed_timeout = 0;
	}
#endif

	remove_networks(device, wifi);
	remove_peers(wifi);

	connman_device_set_powered(device, false);
	connman_device_set_data(device, NULL);
	connman_device_unref(wifi->device);
	connman_rtnl_remove_watch(wifi->watch);

	g_supplicant_interface_set_data(wifi->interface, NULL);

	g_supplicant_interface_cancel(wifi->interface);

	if (wifi->scan_params)
		g_supplicant_free_scan_params(wifi->scan_params);
#if defined TIZEN_EXT
	if (wifi->hidden_scan_params) {
		while (wifi->hidden_scan_params->ssids) {
			struct scan_ssid *ssid;
			ssid = wifi->hidden_scan_params->ssids->data;
			wifi->hidden_scan_params->ssids = g_slist_remove(wifi->hidden_scan_params->ssids, ssid);
		}
		g_supplicant_free_scan_params(wifi->hidden_scan_params);
	}
#endif

	g_free(wifi->autoscan);
	g_free(wifi->identifier);
	g_free(wifi);
}

static bool is_duplicate(GSList *list, gchar *ssid, int ssid_len)
{
	GSList *iter;

	for (iter = list; iter; iter = g_slist_next(iter)) {
		struct scan_ssid *scan_ssid = iter->data;

		if (ssid_len == scan_ssid->ssid_len &&
				memcmp(ssid, scan_ssid->ssid, ssid_len) == 0)
			return true;
	}

	return false;
}

static int add_scan_param(gchar *hex_ssid, char *raw_ssid, int ssid_len,
			int freq, GSupplicantScanParams *scan_data,
			int driver_max_scan_ssids, char *ssid_name)
{
	unsigned int i;
	struct scan_ssid *scan_ssid;

	if ((driver_max_scan_ssids == 0 ||
			driver_max_scan_ssids > scan_data->num_ssids) &&
			(hex_ssid || raw_ssid)) {
		gchar *ssid;
		unsigned int j = 0, hex;

		if (hex_ssid) {
			size_t hex_ssid_len = strlen(hex_ssid);

			ssid = g_try_malloc0(hex_ssid_len / 2);
			if (!ssid)
				return -ENOMEM;

			for (i = 0; i < hex_ssid_len; i += 2) {
				sscanf(hex_ssid + i, "%02x", &hex);
				ssid[j++] = hex;
			}
		} else {
			ssid = raw_ssid;
			j = ssid_len;
		}

		/*
		 * If we have already added hidden AP to the list,
		 * then do not do it again. This might happen if you have
		 * used or are using multiple wifi cards, so in that case
		 * you might have multiple service files for same AP.
		 */
		if (is_duplicate(scan_data->ssids, ssid, j)) {
			if (hex_ssid)
				g_free(ssid);
			return 0;
		}

		scan_ssid = g_try_new(struct scan_ssid, 1);
		if (!scan_ssid) {
			if (hex_ssid)
				g_free(ssid);
			return -ENOMEM;
		}

		memcpy(scan_ssid->ssid, ssid, j);
		scan_ssid->ssid_len = j;
		scan_data->ssids = g_slist_prepend(scan_data->ssids,
								scan_ssid);

		scan_data->num_ssids++;

		DBG("SSID %s added to scanned list of %d entries", ssid_name,
							scan_data->num_ssids);

		if (hex_ssid)
			g_free(ssid);
	} else
		return -EINVAL;

	scan_data->ssids = g_slist_reverse(scan_data->ssids);

	if (!scan_data->freqs) {
		scan_data->freqs = g_try_malloc0(sizeof(uint16_t));
		if (!scan_data->freqs) {
			g_slist_free_full(scan_data->ssids, g_free);
			return -ENOMEM;
		}

		scan_data->num_freqs = 1;
		scan_data->freqs[0] = freq;
	} else {
		bool duplicate = false;

		/* Don't add duplicate entries */
		for (i = 0; i < scan_data->num_freqs; i++) {
			if (scan_data->freqs[i] == freq) {
				duplicate = true;
				break;
			}
		}

		if (!duplicate) {
			scan_data->num_freqs++;
			scan_data->freqs = g_try_realloc(scan_data->freqs,
				sizeof(uint16_t) * scan_data->num_freqs);
			if (!scan_data->freqs) {
				g_slist_free_full(scan_data->ssids, g_free);
				return -ENOMEM;
			}
			scan_data->freqs[scan_data->num_freqs - 1] = freq;
		}
	}

	return 1;
}

static int get_hidden_connections(GSupplicantScanParams *scan_data)
{
	struct connman_config_entry **entries;
	GKeyFile *keyfile;
#if defined TIZEN_EXT
	gchar **services = NULL;
#else
	gchar **services;
#endif /* defined TIZEN_EXT */
	char *ssid, *name;
	int i, ret;
	bool value;
	int num_ssids = 0, add_param_failed = 0;
#if defined TIZEN_EXT
	GSequenceIter *iter;
	GSequence *latest_list;
	struct last_connected *entry;
	GTimeVal modified;

	latest_list = g_sequence_new(free_entry);
	if (!latest_list)
		goto out;
#endif
	services = connman_storage_get_services();
	for (i = 0; services && services[i]; i++) {
		if (strncmp(services[i], "wifi_", 5) != 0)
			continue;

		keyfile = connman_storage_load_service(services[i]);
		if (!keyfile)
			continue;

		value = g_key_file_get_boolean(keyfile,
					services[i], "Hidden", NULL);
		if (!value) {
			g_key_file_free(keyfile);
			continue;
		}

		value = g_key_file_get_boolean(keyfile,
					services[i], "Favorite", NULL);
		if (!value) {
			g_key_file_free(keyfile);
			continue;
		}

#if defined TIZEN_EXT
		value = g_key_file_get_boolean(keyfile,
					services[i], "AutoConnect", NULL);
		if (!value) {
			g_key_file_free(keyfile);
			continue;
		}

		gchar *str = g_key_file_get_string(keyfile,
					services[i], "Modified", NULL);
		if (!str) {
			g_key_file_free(keyfile);
			continue;
		}
		g_time_val_from_iso8601(str, &modified);
		g_free(str);
#endif

		ssid = g_key_file_get_string(keyfile,
					services[i], "SSID", NULL);

		name = g_key_file_get_string(keyfile, services[i], "Name",
								NULL);

#if defined TIZEN_EXT
		entry = g_try_new(struct last_connected, 1);
		if (!entry) {
			g_sequence_free(latest_list);
			g_free(ssid);
			g_free(name);
			g_key_file_free(keyfile);
			goto out;
		}

		entry->modified = modified;
		entry->ssid = ssid;

		g_sequence_insert_sorted(latest_list, entry,
				sort_entry, NULL);
#else
		ret = add_scan_param(ssid, NULL, 0, 0, scan_data, 0, name);
		if (ret < 0)
			add_param_failed++;
		else if (ret > 0)
			num_ssids++;

		g_free(ssid);
#endif
		g_free(name);
		g_key_file_free(keyfile);
	}

#if defined TIZEN_EXT
	gint length = g_sequence_get_length(latest_list);
	iter = g_sequence_get_begin_iter(latest_list);

	for (i = 0; i < length; i++) {
		entry = g_sequence_get(iter);

		ret = add_scan_param(entry->ssid, NULL, 0, 0, scan_data, 0, entry->ssid);
		if (ret < 0)
			add_param_failed++;
		else if (ret > 0)
			num_ssids++;

		iter = g_sequence_iter_next(iter);
	}

	g_sequence_free(latest_list);
out:
#endif
	/*
	 * Check if there are any hidden AP that needs to be provisioned.
	 */
	entries = connman_config_get_entries("wifi");
	for (i = 0; entries && entries[i]; i++) {
		int len;

		if (!entries[i]->hidden)
			continue;

		if (!entries[i]->ssid) {
			ssid = entries[i]->name;
			len = strlen(ssid);
		} else {
			ssid = entries[i]->ssid;
			len = entries[i]->ssid_len;
		}

		if (!ssid)
			continue;

		ret = add_scan_param(NULL, ssid, len, 0, scan_data, 0, ssid);
		if (ret < 0)
			add_param_failed++;
		else if (ret > 0)
			num_ssids++;
	}

	connman_config_free_entries(entries);

	if (add_param_failed > 0)
		DBG("Unable to scan %d out of %d SSIDs",
					add_param_failed, num_ssids);

	g_strfreev(services);

	return num_ssids;
}

static int get_hidden_connections_params(struct wifi_data *wifi,
					GSupplicantScanParams *scan_params)
{
	int driver_max_ssids, i;
	GSupplicantScanParams *orig_params;

	/*
	 * Scan hidden networks so that we can autoconnect to them.
	 * We will assume 1 as a default number of ssid to scan.
	 */
	driver_max_ssids = g_supplicant_interface_get_max_scan_ssids(
							wifi->interface);
	if (driver_max_ssids == 0)
		driver_max_ssids = 1;

	DBG("max ssids %d", driver_max_ssids);

#if defined TIZEN_EXT
	if (!wifi->hidden_scan_params) {
		wifi->hidden_scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
		if (!wifi->hidden_scan_params)
			return 0;

		if (get_hidden_connections(wifi->hidden_scan_params) == 0) {
			g_supplicant_free_scan_params(wifi->hidden_scan_params);
			wifi->hidden_scan_params = NULL;

			return 0;
		}
	}

	orig_params = wifi->hidden_scan_params;
#else
	if (!wifi->scan_params) {
		wifi->scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
		if (!wifi->scan_params)
			return 0;

		if (get_hidden_connections(wifi->scan_params) == 0) {
			g_supplicant_free_scan_params(wifi->scan_params);
			wifi->scan_params = NULL;

			return 0;
		}
	}

	orig_params = wifi->scan_params;
#endif

	/* Let's transfer driver_max_ssids params */
	for (i = 0; i < driver_max_ssids; i++) {
		struct scan_ssid *ssid;

#if defined TIZEN_EXT
		if (!wifi->hidden_scan_params->ssids)
#else
		if (!wifi->scan_params->ssids)
#endif
			break;

		ssid = orig_params->ssids->data;
		orig_params->ssids = g_slist_remove(orig_params->ssids, ssid);
		scan_params->ssids = g_slist_prepend(scan_params->ssids, ssid);
	}

	if (i > 0) {
		scan_params->num_ssids = i;
		scan_params->ssids = g_slist_reverse(scan_params->ssids);

		scan_params->freqs = g_memdup(orig_params->freqs,
				sizeof(uint16_t) * orig_params->num_freqs);
		if (!scan_params->freqs)
			goto err;

		scan_params->num_freqs = orig_params->num_freqs;

	} else
		goto err;

	orig_params->num_ssids -= scan_params->num_ssids;

	return scan_params->num_ssids;

err:
	g_slist_free_full(scan_params->ssids, g_free);
#if defined TIZEN_EXT
	g_supplicant_free_scan_params(wifi->hidden_scan_params);
	wifi->hidden_scan_params = NULL;
#else
	g_supplicant_free_scan_params(wifi->scan_params);
	wifi->scan_params = NULL;
#endif

	return 0;
}

static int throw_wifi_scan(struct connman_device *device,
			GSupplicantInterfaceCallback callback)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	int ret;

	if (!wifi)
		return -ENODEV;

	DBG("device %p %p", device, wifi->interface);

	if (wifi->tethering)
		return -EBUSY;

#if defined TIZEN_EXT
	if (connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_WIFI)
	    && !wifi->allow_full_scan)
#else
	if (connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_WIFI))
#endif
		return -EALREADY;

	connman_device_ref(device);

	ret = g_supplicant_interface_scan(wifi->interface, NULL,
						callback, device);
	if (ret == 0) {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_WIFI, true);
	} else
		connman_device_unref(device);

	return ret;
}

static void hidden_free(struct hidden_params *hidden)
{
	if (!hidden)
		return;

	if (hidden->scan_params)
		g_supplicant_free_scan_params(hidden->scan_params);
	g_free(hidden->identity);
	g_free(hidden->passphrase);
	g_free(hidden->security);
	g_free(hidden);
}

#if defined TIZEN_EXT
static void service_state_changed(struct connman_service *service,
					enum connman_service_state state);

static int network_connect(struct connman_network *network);

static struct connman_notifier notifier = {
	.name			= "wifi",
	.priority		= CONNMAN_NOTIFIER_PRIORITY_DEFAULT,
	.service_state_changed	= service_state_changed,
};

static void service_state_changed(struct connman_service *service,
					enum connman_service_state state)
{
	enum connman_service_type type;

	type = connman_service_get_type(service);
	if (type != CONNMAN_SERVICE_TYPE_WIFI)
		return;

	DBG("service %p state %d", service, state);

	switch (state) {
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
	case CONNMAN_SERVICE_STATE_FAILURE:
		connman_notifier_unregister(&notifier);
		is_wifi_notifier_registered = FALSE;

		__connman_device_request_scan(type);
		break;

	default:
		break;
	}
}

static void scan_callback_hidden(int result,
			GSupplicantInterface *interface, void *user_data);
#endif

static void scan_callback(int result, GSupplicantInterface *interface,
						void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);
	bool scanning;

	DBG("result %d wifi %p", result, wifi);

	if (wifi) {
		if (wifi->hidden && !wifi->postpone_hidden) {
			connman_network_clear_hidden(wifi->hidden->user_data);
			hidden_free(wifi->hidden);
			wifi->hidden = NULL;
		}

		if (wifi->scan_params) {
			g_supplicant_free_scan_params(wifi->scan_params);
			wifi->scan_params = NULL;
		}

#if defined TIZEN_EXT
		if (wifi->hidden_scan_params && !wifi->hidden_scan_params->ssids) {
			g_supplicant_free_scan_params(wifi->hidden_scan_params);
			wifi->hidden_scan_params = NULL;
		}
#endif
	}

	if (result < 0)
		connman_device_reset_scanning(device);

	/* User is connecting to a hidden AP, let's wait for finished event */
	if (wifi && wifi->hidden && wifi->postpone_hidden) {
		GSupplicantScanParams *scan_params;
		int ret;

		wifi->postpone_hidden = false;
		scan_params = wifi->hidden->scan_params;
		wifi->hidden->scan_params = NULL;

		reset_autoscan(device);

		ret = g_supplicant_interface_scan(wifi->interface, scan_params,
							scan_callback, device);
		if (ret == 0)
			return;

		/* On error, let's recall scan_callback, which will cleanup */
		return scan_callback(ret, interface, user_data);
	}

#if defined TIZEN_EXT
	if (wifi && wifi->allow_full_scan) {
		int ret;
		DBG("Trigger Full Channel Scan");
		wifi->allow_full_scan = FALSE;

		ret = g_supplicant_interface_scan(wifi->interface, NULL,
							scan_callback_hidden, device);
		if (ret == 0)
			return;

		/* On error, let's recall scan_callback, which will cleanup */
		return scan_callback(ret, interface, user_data);
	}
#endif

	scanning = connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_WIFI);

	if (scanning) {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_WIFI, false);
	}

	if (result != -ENOLINK)
#if defined TIZEN_EXT
	if (result != -EIO)
#endif
		start_autoscan(device);

	/*
	 * If we are here then we were scanning; however, if we are
	 * also mid-flight disabling the interface, then wifi_disable
	 * has already cleared the device scanning state and
	 * unreferenced the device, obviating the need to do it here.
	 */

	if (scanning)
		connman_device_unref(device);

#if defined TIZEN_EXT
	if (wifi && wifi->scan_pending_network && result != -EIO) {
		network_connect(wifi->scan_pending_network);
		wifi->scan_pending_network = NULL;
		connman_network_set_connecting(wifi->network);
	}

	if (is_wifi_notifier_registered != true &&
			wifi_first_scan == true && found_with_first_scan == true) {
		wifi_first_scan = false;
		found_with_first_scan = false;

		connman_notifier_register(&notifier);
		is_wifi_notifier_registered = true;
	}
#endif
}

static void scan_callback_hidden(int result,
			GSupplicantInterface *interface, void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);
	GSupplicantScanParams *scan_params;
	int ret;

	DBG("result %d wifi %p", result, wifi);

	if (!wifi)
		goto out;

	/* User is trying to connect to a hidden AP */
	if (wifi->hidden && wifi->postpone_hidden)
		goto out;

	scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
	if (!scan_params)
		goto out;

	if (get_hidden_connections_params(wifi, scan_params) > 0) {
		ret = g_supplicant_interface_scan(wifi->interface,
							scan_params,
#if defined TIZEN_EXT
							scan_callback,
#else
							scan_callback_hidden,
#endif
							device);
		if (ret == 0)
			return;
	}

	g_supplicant_free_scan_params(scan_params);

out:
	scan_callback(result, interface, user_data);
}

static gboolean autoscan_timeout(gpointer data)
{
	struct connman_device *device = data;
	struct wifi_data *wifi = connman_device_get_data(device);
	struct autoscan_params *autoscan;
	int interval;

	if (!wifi)
		return FALSE;

	autoscan = wifi->autoscan;

	if (autoscan->interval <= 0) {
		interval = autoscan->base;
		goto set_interval;
	} else
		interval = autoscan->interval * autoscan->base;

#if defined TIZEN_EXT
	if (autoscan->interval >= autoscan->limit)
#else
	if (interval > autoscan->limit)
#endif
		interval = autoscan->limit;

	throw_wifi_scan(wifi->device, scan_callback_hidden);

	/*
	 * In case BackgroundScanning is disabled, interval will reach the
	 * limit exactly after the very first passive scanning. It allows
	 * to ensure at most one passive scan is performed in such cases.
	 */
	if (!connman_setting_get_bool("BackgroundScanning") &&
					interval == autoscan->limit) {
		g_source_remove(autoscan->timeout);
		autoscan->timeout = 0;

		connman_device_unref(device);

		return FALSE;
	}

set_interval:
	DBG("interval %d", interval);

	autoscan->interval = interval;

	autoscan->timeout = g_timeout_add_seconds(interval,
						autoscan_timeout, device);

	return FALSE;
}

static void start_autoscan(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	struct autoscan_params *autoscan;

	DBG("");

	if (!wifi)
		return;

	if (wifi->p2p_device)
		return;

	if (wifi->connected)
		return;

	autoscan = wifi->autoscan;
	if (!autoscan)
		return;

	if (autoscan->timeout > 0 || autoscan->interval > 0)
		return;

	connman_device_ref(device);

	autoscan_timeout(device);
}

static struct autoscan_params *parse_autoscan_params(const char *params)
{
	struct autoscan_params *autoscan;
	char **list_params;
	int limit;
	int base;

	DBG("");

	list_params = g_strsplit(params, ":", 0);
	if (list_params == 0)
		return NULL;

	if (!g_strcmp0(list_params[0], "exponential") &&
				g_strv_length(list_params) == 3) {
		base = atoi(list_params[1]);
		limit = atoi(list_params[2]);
	} else if (!g_strcmp0(list_params[0], "single") &&
				g_strv_length(list_params) == 2)
		base = limit = atoi(list_params[1]);
	else {
		g_strfreev(list_params);
		return NULL;
	}

	DBG("Setup %s autoscanning", list_params[0]);

	g_strfreev(list_params);

	autoscan = g_try_malloc0(sizeof(struct autoscan_params));
	if (!autoscan) {
		DBG("Could not allocate memory for autoscan");
		return NULL;
	}

	DBG("base %d - limit %d", base, limit);
	autoscan->base = base;
	autoscan->limit = limit;

	return autoscan;
}

static void setup_autoscan(struct wifi_data *wifi)
{
	/*
	 * If BackgroundScanning is enabled, setup exponential
	 * autoscanning if it has not been previously done.
	 */
	if (connman_setting_get_bool("BackgroundScanning")) {
		wifi->autoscan = parse_autoscan_params(AUTOSCAN_EXPONENTIAL);
		return;
	}

	/*
	 * On the contrary, if BackgroundScanning is disabled, update autoscan
	 * parameters based on the type of scanning that is being performed.
	 */
	if (wifi->autoscan) {
		g_free(wifi->autoscan);
		wifi->autoscan = NULL;
	}

	switch (wifi->scanning_type) {
	case WIFI_SCANNING_PASSIVE:
		/* Do not setup autoscan. */
		break;
	case WIFI_SCANNING_ACTIVE:
		/* Setup one single passive scan after active. */
		wifi->autoscan = parse_autoscan_params(AUTOSCAN_SINGLE);
		break;
	case WIFI_SCANNING_UNKNOWN:
		/* Setup autoscan in this case but we should never fall here. */
		wifi->autoscan = parse_autoscan_params(AUTOSCAN_SINGLE);
		break;
	}
}

static void finalize_interface_creation(struct wifi_data *wifi)
{
	DBG("interface is ready wifi %p tethering %d", wifi, wifi->tethering);

	if (!wifi->device) {
		connman_error("WiFi device not set");
		return;
	}

	connman_device_set_powered(wifi->device, true);

	if (wifi->p2p_device)
		return;

	if (!wifi->autoscan)
		setup_autoscan(wifi);

	start_autoscan(wifi->device);
}

static void interface_create_callback(int result,
					GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_data *wifi = user_data;

	DBG("result %d ifname %s, wifi %p", result,
				g_supplicant_interface_get_ifname(interface),
				wifi);

	if (result < 0 || !wifi)
		return;

	wifi->interface = interface;
	g_supplicant_interface_set_data(interface, wifi);

	if (g_supplicant_interface_get_ready(interface)) {
		wifi->interface_ready = true;
		finalize_interface_creation(wifi);
	}
}

static int wifi_enable(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	int index;
	char *interface;
	const char *driver = connman_option_get_string("wifi");
	int ret;

	DBG("device %p %p", device, wifi);

	index = connman_device_get_index(device);
	if (!wifi || index < 0)
		return -ENODEV;

	if (is_p2p_connecting())
		return -EINPROGRESS;

	interface = connman_inet_ifname(index);
	ret = g_supplicant_interface_create(interface, driver, NULL,
						interface_create_callback,
							wifi);
	g_free(interface);

	if (ret < 0)
		return ret;

	return -EINPROGRESS;
}

static int wifi_disable(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	int ret;

	DBG("device %p wifi %p", device, wifi);

	if (!wifi)
		return -ENODEV;

	wifi->connected = false;
	wifi->disconnecting = false;

	if (wifi->pending_network)
		wifi->pending_network = NULL;

#if !defined TIZEN_EXT
	stop_autoscan(device);
#endif

	if (connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_P2P)) {
		g_source_remove(wifi->p2p_find_timeout);
		wifi->p2p_find_timeout = 0;
		connman_device_set_scanning(device, CONNMAN_SERVICE_TYPE_P2P, false);
		connman_device_unref(wifi->device);
	}

#if defined TIZEN_EXT
	if (wifi->automaxspeed_timeout != 0) {
		g_source_remove(wifi->automaxspeed_timeout);
		wifi->automaxspeed_timeout = 0;
	}
#endif

	/* In case of a user scan, device is still referenced */
	if (connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_WIFI)) {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_WIFI, false);
		connman_device_unref(wifi->device);
	}

#if defined TIZEN_EXT
	stop_autoscan(device);
#endif

	remove_networks(device, wifi);
	remove_peers(wifi);

#if defined TIZEN_EXT
	wifi->scan_pending_network = NULL;

	if (is_wifi_notifier_registered == true) {
		connman_notifier_unregister(&notifier);
		is_wifi_notifier_registered = false;
	}
#endif

	ret = g_supplicant_interface_remove(wifi->interface, NULL, NULL);
	if (ret < 0)
		return ret;

	return -EINPROGRESS;
}

static int get_latest_connections(int max_ssids,
				GSupplicantScanParams *scan_data)
{
	GSequenceIter *iter;
	GSequence *latest_list;
	struct last_connected *entry;
	GKeyFile *keyfile;
	GTimeVal modified;
	gchar **services;
	gchar *str;
	char *ssid;
	int i, freq;
	int num_ssids = 0;

	latest_list = g_sequence_new(free_entry);
	if (!latest_list)
		return -ENOMEM;

	services = connman_storage_get_services();
	for (i = 0; services && services[i]; i++) {
		if (strncmp(services[i], "wifi_", 5) != 0)
			continue;

		keyfile = connman_storage_load_service(services[i]);
		if (!keyfile)
			continue;

		str = g_key_file_get_string(keyfile,
					services[i], "Favorite", NULL);
		if (!str || g_strcmp0(str, "true")) {
			g_free(str);
			g_key_file_free(keyfile);
			continue;
		}
		g_free(str);

		str = g_key_file_get_string(keyfile,
					services[i], "AutoConnect", NULL);
		if (!str || g_strcmp0(str, "true")) {
			g_free(str);
			g_key_file_free(keyfile);
			continue;
		}
		g_free(str);

		str = g_key_file_get_string(keyfile,
					services[i], "Modified", NULL);
		if (!str) {
			g_key_file_free(keyfile);
			continue;
		}
		g_time_val_from_iso8601(str, &modified);
		g_free(str);

		ssid = g_key_file_get_string(keyfile,
					services[i], "SSID", NULL);

		freq = g_key_file_get_integer(keyfile, services[i],
					"Frequency", NULL);
		if (freq) {
			entry = g_try_new(struct last_connected, 1);
			if (!entry) {
				g_sequence_free(latest_list);
				g_key_file_free(keyfile);
				g_free(ssid);
				return -ENOMEM;
			}

			entry->ssid = ssid;
			entry->modified = modified;
			entry->freq = freq;

			g_sequence_insert_sorted(latest_list, entry,
						sort_entry, NULL);
			num_ssids++;
		} else
			g_free(ssid);

		g_key_file_free(keyfile);
	}

	g_strfreev(services);

	num_ssids = num_ssids > max_ssids ? max_ssids : num_ssids;

	iter = g_sequence_get_begin_iter(latest_list);

	for (i = 0; i < num_ssids; i++) {
		entry = g_sequence_get(iter);

		DBG("ssid %s freq %d modified %lu", entry->ssid, entry->freq,
						entry->modified.tv_sec);

		add_scan_param(entry->ssid, NULL, 0, entry->freq, scan_data,
						max_ssids, entry->ssid);

		iter = g_sequence_iter_next(iter);
	}

	g_sequence_free(latest_list);
	return num_ssids;
}

static void wifi_update_scanner_type(struct wifi_data *wifi,
					enum wifi_scanning_type new_type)
{
	DBG("");

	if (!wifi || wifi->scanning_type == new_type)
		return;

	wifi->scanning_type = new_type;

	setup_autoscan(wifi);
}

static int wifi_scan_simple(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	reset_autoscan(device);

	/* Distinguish between devices performing passive and active scanning */
	if (wifi)
		wifi_update_scanner_type(wifi, WIFI_SCANNING_PASSIVE);

	return throw_wifi_scan(device, scan_callback_hidden);
}

static gboolean p2p_find_stop(gpointer data)
{
	struct connman_device *device = data;
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("");

	if (wifi) {
		wifi->p2p_find_timeout = 0;

		g_supplicant_interface_p2p_stop_find(wifi->interface);
	}

	connman_device_set_scanning(device, CONNMAN_SERVICE_TYPE_P2P, false);

	connman_device_unref(device);
	start_autoscan(device);

	return FALSE;
}

static void p2p_find_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("result %d wifi %p", result, wifi);

	if (!wifi)
		goto error;

	if (wifi->p2p_find_timeout) {
		g_source_remove(wifi->p2p_find_timeout);
		wifi->p2p_find_timeout = 0;
	}

	if (result)
		goto error;

	wifi->p2p_find_timeout = g_timeout_add_seconds(P2P_FIND_TIMEOUT,
							p2p_find_stop, device);
	if (!wifi->p2p_find_timeout)
		goto error;

	return;
error:
	p2p_find_stop(device);
}

static int p2p_find(struct connman_device *device)
{
	struct wifi_data *wifi;
	int ret;

	DBG("");

	if (!p2p_technology)
		return -ENOTSUP;

	wifi = connman_device_get_data(device);

	if (g_supplicant_interface_is_p2p_finding(wifi->interface))
		return -EALREADY;

	reset_autoscan(device);
	connman_device_ref(device);

	ret = g_supplicant_interface_p2p_find(wifi->interface,
						p2p_find_callback, device);
	if (ret) {
		connman_device_unref(device);
		start_autoscan(device);
	} else {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_P2P, true);
	}

	return ret;
}

#if defined TIZEN_EXT
static void specific_scan_callback(int result, GSupplicantInterface *interface,
						void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);
	bool scanning;

	DBG("result %d wifi %p", result, wifi);

	if (wifi && wifi->scan_params) {
		g_supplicant_free_scan_params(wifi->scan_params);
		wifi->scan_params = NULL;
	}

	scanning = connman_device_get_scanning(device,
					       CONNMAN_SERVICE_TYPE_WIFI);
	if (scanning) {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_WIFI, false);
		connman_device_unref(device);
	}
}

static int wifi_specific_scan(enum connman_service_type type,
			struct connman_device *device, int scan_type,
			GSList *specific_scan_list, void *user_data)
{
	GSList *list = NULL;
	char *ssid = NULL;
	struct wifi_data *wifi = connman_device_get_data(device);
	GSupplicantScanParams *scan_params = NULL;
	struct scan_ssid *scan_ssid = NULL;
	bool scanning;
	int ret;
	int freq;
	int count = 0;

	if (!wifi)
		return -ENODEV;

	if (wifi->p2p_device)
		return 0;

	if (type == CONNMAN_SERVICE_TYPE_P2P)
		return p2p_find(device);

	if (wifi->tethering)
		return 0;

	scanning =
		connman_device_get_scanning(device,
					    CONNMAN_SERVICE_TYPE_WIFI);
	if (scanning)
		return -EALREADY;

	DBG("scan_type: %d", scan_type);
	if (scan_type == CONNMAN_MULTI_SCAN_SSID) { /* ssid based scan */
		scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
		if (!scan_params) {
			DBG("Failed to allocate memory.");
			return -ENOMEM;
		}

		for (list = specific_scan_list; list; list = list->next) {
			ssid = (char *)list->data;
			int ssid_len = strlen(ssid);

			scan_ssid = g_try_new0(struct scan_ssid, 1);
			if (!scan_ssid) {
				DBG("Failed to allocate memory.");
				g_supplicant_free_scan_params(scan_params);
				return -ENOMEM;
			}

			memcpy(scan_ssid->ssid, ssid, (ssid_len + 1));
			/* DBG("scan ssid %s len: %d", scan_ssid->ssid, ssid_len); */
			scan_ssid->ssid_len = ssid_len;
			scan_params->ssids = g_slist_prepend(scan_params->ssids, scan_ssid);
			count++;
		}
		scan_params->num_ssids = count;

	} else if (scan_type == CONNMAN_MULTI_SCAN_FREQ) { /* frequency based scan */

		scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
		if (!scan_params) {
			DBG("Failed to allocate memory.");
			return -ENOMEM;
		}

		guint num_freqs = g_slist_length(specific_scan_list);
		DBG("num_freqs: %d", num_freqs);

		scan_params->freqs = g_try_new0(uint16_t, num_freqs);
		if (!scan_params->freqs) {
			DBG("Failed to allocate memory.");
			g_free(scan_params);
			return -ENOMEM;
		}

		count = 0;
		for (list = specific_scan_list; list; list = list->next) {
			freq = (int)list->data;

			scan_params->freqs[count] = freq;
			DBG("scan_params->freqs[%d]: %d", count, scan_params->freqs[count]);
			count++;
		}
		scan_params->num_freqs = count;

	} else if (scan_type == CONNMAN_MULTI_SCAN_SSID_FREQ) { /* SSID & Frequency mixed scan */
		int freq_count, ap_count;
		scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
		if (!scan_params) {
			DBG("Failed to allocate memory.");
			return -ENOMEM;
		}

		guint size = g_slist_length(specific_scan_list);

		scan_params->freqs = g_try_new0(uint16_t, size/2);
		if (!scan_params->freqs) {
			DBG("Failed to allocate memory.");
			g_free(scan_params);
			return -ENOMEM;
		}

		ap_count = freq_count = 0;
		for (list = specific_scan_list; list; list = list->next) {
			if (((connman_multi_scan_ap_s *)list->data)->flag == true) { /** ssid */
				ssid = ((connman_multi_scan_ap_s *)list->data)->str;
				int ssid_len = strlen(ssid);

				scan_ssid = g_try_new0(struct scan_ssid, 1);
				if (!scan_ssid) {
					DBG("Failed to allocate memory.");
					g_supplicant_free_scan_params(scan_params);
					return -ENOMEM;
				}

				memcpy(scan_ssid->ssid, ssid, (ssid_len + 1));
				/* DBG("scan ssid %s len: %d", scan_ssid->ssid, ssid_len); */
				scan_ssid->ssid_len = ssid_len;
				scan_params->ssids = g_slist_prepend(scan_params->ssids, scan_ssid);
				ap_count++;

			} else { /* freq */
				freq = atoi(((connman_multi_scan_ap_s *)list->data)->str);
				scan_params->freqs[freq_count] = freq;
				DBG("scan_params->freqs[%d]: %d", freq_count, scan_params->freqs[freq_count]);
				freq_count++;
			}
		}
		scan_params->num_ssids = ap_count;
		scan_params->num_freqs = freq_count;
	} else {
		DBG("Invalid scan");
		return -EINVAL;
	}

	reset_autoscan(device);
	connman_device_ref(device);

	ret = g_supplicant_interface_scan(wifi->interface, scan_params,
						specific_scan_callback, device);

	if (ret == 0) {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_WIFI, true);
	} else {
		g_supplicant_free_scan_params(scan_params);
		connman_device_unref(device);
	}

	return ret;
}
#endif

#if defined TIZEN_EXT_WIFI_MESH
static void mesh_scan_callback(int result, GSupplicantInterface *interface,
						void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);
	bool scanning;

	DBG("result %d wifi %p", result, wifi);

	scanning = connman_device_get_scanning(device,
					       CONNMAN_SERVICE_TYPE_MESH);
	if (scanning)
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_MESH, false);

	if (scanning)
		connman_device_unref(device);
}

static int mesh_scan(struct connman_device *device)
{
	struct wifi_data *wifi;
	struct wifi_mesh_info *mesh_info;
	int ret;

	DBG("");

	wifi = connman_device_get_data(device);

	if (!wifi->mesh_interface)
		return -ENOTSUP;

	mesh_info = wifi->mesh_info;
	reset_autoscan(device);
	connman_device_ref(device);

	ret = g_supplicant_interface_scan(mesh_info->interface, NULL,
						mesh_scan_callback, device);
	if (ret)
		connman_device_unref(device);
	else
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_MESH, true);

	return ret;
}

static void abort_scan_callback(int result, GSupplicantInterface *interface,
						void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("result %d wifi %p", result, wifi);

	__connman_technology_notify_abort_scan(CONNMAN_SERVICE_TYPE_MESH, result);
}

static int mesh_abort_scan(enum connman_service_type type,
						struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	struct wifi_mesh_info *mesh_info;
	bool scanning;
	int ret;

	if (!wifi || !wifi->mesh_interface)
		return -ENODEV;

	if (type != CONNMAN_SERVICE_TYPE_MESH)
		return -EINVAL;

	mesh_info = wifi->mesh_info;

	scanning = connman_device_get_scanning(device,
					       CONNMAN_SERVICE_TYPE_MESH);
	if (!scanning)
		return -EEXIST;

	ret = g_supplicant_interface_abort_scan(mesh_info->interface,
						abort_scan_callback, device);

	return ret;
}

static int mesh_specific_scan(enum connman_service_type type,
			      struct connman_device *device, const char *ssid,
			      unsigned int freq, void *user_data)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	GSupplicantScanParams *scan_params = NULL;
	struct wifi_mesh_info *mesh_info;
	struct scan_ssid *scan_ssid;
	bool scanning;
	int ret;

	if (!wifi || !wifi->mesh_interface)
		return -ENODEV;

	if (type != CONNMAN_SERVICE_TYPE_MESH)
		return -EINVAL;

	if (wifi->p2p_device)
		return 0;

	mesh_info = wifi->mesh_info;

	scanning = connman_device_get_scanning(device,
					       CONNMAN_SERVICE_TYPE_MESH);
	if (scanning)
		return -EALREADY;

	scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
	if (!scan_params)
		return -ENOMEM;

	scan_ssid = g_try_new(struct scan_ssid, 1);
	if (!scan_ssid) {
		g_free(scan_params);
		return -ENOMEM;
	}

	scan_ssid->ssid_len = strlen(ssid);
	memcpy(scan_ssid->ssid, ssid, scan_ssid->ssid_len);
	scan_params->ssids = g_slist_prepend(scan_params->ssids, scan_ssid);
	scan_params->num_ssids = 1;

	scan_params->freqs = g_try_new(uint16_t, 1);
	if (!scan_params->freqs) {
		g_slist_free_full(scan_params->ssids, g_free);
		g_free(scan_params);
		return -ENOMEM;
	}

	scan_params->freqs[0] = freq;
	scan_params->num_freqs = 1;

	reset_autoscan(device);
	connman_device_ref(device);

	ret = g_supplicant_interface_scan(mesh_info->interface, scan_params,
						mesh_scan_callback, device);

	if (ret == 0) {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_MESH, true);
	} else {
		g_supplicant_free_scan_params(scan_params);
		connman_device_unref(device);
	}

	return ret;
}
#endif

/*
 * Note that the hidden scan is only used when connecting to this specific
 * hidden AP first time. It is not used when system autoconnects to hidden AP.
 */
static int wifi_scan(struct connman_device *device,
			struct connman_device_scan_params *params)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	GSupplicantScanParams *scan_params = NULL;
	struct scan_ssid *scan_ssid;
	struct hidden_params *hidden;
	int ret;
	int driver_max_ssids = 0;
	bool do_hidden;
	bool scanning;

	if (!wifi)
		return -ENODEV;

	if (wifi->p2p_device)
		return -EBUSY;

	if (wifi->tethering)
		return -EBUSY;

	if (params->type == CONNMAN_SERVICE_TYPE_P2P)
		return p2p_find(device);

#if defined TIZEN_EXT_WIFI_MESH
	if (params->type == CONNMAN_SERVICE_TYPE_MESH)
		return mesh_scan(device);
#endif

	DBG("device %p wifi %p hidden ssid %s", device, wifi->interface,
		params->ssid);

	scanning = connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_WIFI);

	if (!params->ssid || params->ssid_len == 0 || params->ssid_len > 32) {
		if (scanning)
			return -EALREADY;

		driver_max_ssids = g_supplicant_interface_get_max_scan_ssids(
							wifi->interface);
		DBG("max ssids %d", driver_max_ssids);
		if (driver_max_ssids == 0)
			return wifi_scan_simple(device);

		do_hidden = false;
	} else {
		if (scanning && wifi->hidden && wifi->postpone_hidden)
			return -EALREADY;

		do_hidden = true;
	}

	scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
	if (!scan_params)
		return -ENOMEM;

	if (do_hidden) {
		scan_ssid = g_try_new(struct scan_ssid, 1);
		if (!scan_ssid) {
			g_free(scan_params);
			return -ENOMEM;
		}

		memcpy(scan_ssid->ssid, params->ssid, params->ssid_len);
		scan_ssid->ssid_len = params->ssid_len;
		scan_params->ssids = g_slist_prepend(scan_params->ssids,
								scan_ssid);
		scan_params->num_ssids = 1;

		hidden = g_try_new0(struct hidden_params, 1);
		if (!hidden) {
			g_supplicant_free_scan_params(scan_params);
			return -ENOMEM;
		}

		if (wifi->hidden) {
			hidden_free(wifi->hidden);
			wifi->hidden = NULL;
		}

		memcpy(hidden->ssid, params->ssid, params->ssid_len);
		hidden->ssid_len = params->ssid_len;
		hidden->identity = g_strdup(params->identity);
		hidden->passphrase = g_strdup(params->passphrase);
		hidden->security = g_strdup(params->security);
		hidden->user_data = params->user_data;
		wifi->hidden = hidden;

		if (scanning) {
			/* Let's keep this active scan for later,
			 * when current scan will be over. */
			wifi->postpone_hidden = TRUE;
			hidden->scan_params = scan_params;

			return 0;
		}
	} else if (wifi->connected) {
		g_supplicant_free_scan_params(scan_params);
		return wifi_scan_simple(device);
	} else if (!params->force_full_scan) {
		ret = get_latest_connections(driver_max_ssids, scan_params);
		if (ret <= 0) {
			g_supplicant_free_scan_params(scan_params);
			return wifi_scan_simple(device);
		}
	}

	/* Distinguish between devices performing passive and active scanning */
	wifi_update_scanner_type(wifi, WIFI_SCANNING_ACTIVE);

	connman_device_ref(device);

	reset_autoscan(device);

	ret = g_supplicant_interface_scan(wifi->interface, scan_params,
						scan_callback, device);
	if (ret == 0) {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_WIFI, true);
#if defined TIZEN_EXT
		/*To allow the Full Scan after ssid based scan, set the flag here
		  It is required because Tizen does not use the ConnMan specific
		  backgroung Scan feature.Tizen has added the BG Scan feature in
		  net-config. To sync with up ConnMan, we need to issue the Full Scan
		  after SSID specific scan.*/
		wifi->allow_full_scan = TRUE;
#endif
	} else {
		g_supplicant_free_scan_params(scan_params);
		connman_device_unref(device);

		if (do_hidden) {
			hidden_free(wifi->hidden);
			wifi->hidden = NULL;
		}
	}

	return ret;
}

static void wifi_stop_scan(enum connman_service_type type,
			struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("device %p wifi %p", device, wifi);

	if (!wifi)
		return;

	if (type == CONNMAN_SERVICE_TYPE_P2P) {
		if (connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_P2P)) {
			g_source_remove(wifi->p2p_find_timeout);
			p2p_find_stop(device);
		}
	}
}

static void wifi_regdom_callback(int result,
					const char *alpha2,
						void *user_data)
{
	struct connman_device *device = user_data;

	connman_device_regdom_notify(device, result, alpha2);

	connman_device_unref(device);
}

static int wifi_set_regdom(struct connman_device *device, const char *alpha2)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	int ret;

	if (!wifi)
		return -EINVAL;

	connman_device_ref(device);

	ret = g_supplicant_interface_set_country(wifi->interface,
						wifi_regdom_callback,
							alpha2, device);
	if (ret != 0)
		connman_device_unref(device);

	return ret;
}

static struct connman_device_driver wifi_ng_driver = {
	.name		= "wifi",
	.type		= CONNMAN_DEVICE_TYPE_WIFI,
	.priority	= CONNMAN_DEVICE_PRIORITY_LOW,
	.probe		= wifi_probe,
	.remove		= wifi_remove,
	.enable		= wifi_enable,
	.disable	= wifi_disable,
	.scan		= wifi_scan,
	.stop_scan	= wifi_stop_scan,
	.set_regdom	= wifi_set_regdom,
#if defined TIZEN_EXT
	.specific_scan  = wifi_specific_scan,
#endif
#if defined TIZEN_EXT_WIFI_MESH
	.abort_scan	= mesh_abort_scan,
	.mesh_specific_scan	= mesh_specific_scan,
#endif
};

static void system_ready(void)
{
	DBG("");

	if (connman_device_driver_register(&wifi_ng_driver) < 0)
		connman_error("Failed to register WiFi driver");
}

static void system_killed(void)
{
	DBG("");

	connman_device_driver_unregister(&wifi_ng_driver);
}

static int network_probe(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static void network_remove(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct wifi_data *wifi;

	DBG("network %p", network);

	wifi = connman_device_get_data(device);
	if (!wifi)
		return;

	if (wifi->network != network)
		return;

	wifi->network = NULL;

#if defined TIZEN_EXT
	wifi->disconnecting = false;

	if (wifi->pending_network == network)
		wifi->pending_network = NULL;

	if (wifi->scan_pending_network == network)
		wifi->scan_pending_network = NULL;
#endif
}

static void connect_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
#if defined TIZEN_EXT
	GList *list;
	struct wifi_data *wifi;
#endif
	struct connman_network *network = user_data;

	DBG("network %p result %d", network, result);

#if defined TIZEN_EXT
	set_connman_bssid(RESET_BSSID, NULL);

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;

		if (wifi && wifi->network == network)
			goto found;
	}

	/* wifi_data may be invalid because wifi is already disabled */
	return;

found:
#endif
	if (result == -ENOKEY) {
		connman_network_set_error(network,
					CONNMAN_NETWORK_ERROR_INVALID_KEY);
	} else if (result < 0) {
		connman_network_set_error(network,
					CONNMAN_NETWORK_ERROR_CONFIGURE_FAIL);
	}

	connman_network_unref(network);
}

static GSupplicantSecurity network_security(const char *security)
{
	if (g_str_equal(security, "none"))
		return G_SUPPLICANT_SECURITY_NONE;
	else if (g_str_equal(security, "wep"))
		return G_SUPPLICANT_SECURITY_WEP;
	else if (g_str_equal(security, "psk"))
		return G_SUPPLICANT_SECURITY_PSK;
	else if (g_str_equal(security, "wpa"))
		return G_SUPPLICANT_SECURITY_PSK;
	else if (g_str_equal(security, "rsn"))
		return G_SUPPLICANT_SECURITY_PSK;
	else if (g_str_equal(security, "ieee8021x"))
		return G_SUPPLICANT_SECURITY_IEEE8021X;
#if defined TIZEN_EXT
	else if (g_str_equal(security, "ft_psk") == TRUE)
		return G_SUPPLICANT_SECURITY_FT_PSK;
	else if (g_str_equal(security, "ft_ieee8021x") == TRUE)
		return G_SUPPLICANT_SECURITY_FT_IEEE8021X;
	else if (g_str_equal(security, "sae"))
		return G_SUPPLICANT_SECURITY_SAE;
	else if (g_str_equal(security, "owe"))
		return G_SUPPLICANT_SECURITY_OWE;
	else if (g_str_equal(security, "dpp"))
		return G_SUPPLICANT_SECURITY_DPP;
#endif

	return G_SUPPLICANT_SECURITY_UNKNOWN;
}

#if defined TIZEN_EXT
static GSupplicantEapKeymgmt network_eap_keymgmt(const char *security)
{
	if (security == NULL)
		return G_SUPPLICANT_EAP_KEYMGMT_NONE;

	if (g_str_equal(security, "FT") == TRUE)
		return G_SUPPLICANT_EAP_KEYMGMT_FT;
	else if (g_str_equal(security, "CCKM") == TRUE)
		return G_SUPPLICANT_EAP_KEYMGMT_CCKM;

	return G_SUPPLICANT_EAP_KEYMGMT_NONE;
}
#endif

static void ssid_init(GSupplicantSSID *ssid, struct connman_network *network)
{
	const char *security;
#if defined TIZEN_EXT
	const void *ssid_data;
#endif

	memset(ssid, 0, sizeof(*ssid));
	ssid->mode = G_SUPPLICANT_MODE_INFRA;
#if defined TIZEN_EXT
	ssid_data = connman_network_get_blob(network, "WiFi.SSID",
						&ssid->ssid_len);
	ssid->ssid = g_try_malloc0(ssid->ssid_len);

	if (!ssid->ssid)
		ssid->ssid_len = 0;
	else
		memcpy(ssid->ssid, ssid_data, ssid->ssid_len);
#else
	ssid->ssid = connman_network_get_blob(network, "WiFi.SSID",
						&ssid->ssid_len);
#endif
	ssid->scan_ssid = 1;
	security = connman_network_get_string(network, "WiFi.Security");
	ssid->security = network_security(security);
#if defined TIZEN_EXT
	ssid->ieee80211w = 1;
#endif
	ssid->passphrase = connman_network_get_string(network,
						"WiFi.Passphrase");

	ssid->eap = connman_network_get_string(network, "WiFi.EAP");

	/*
	 * If our private key password is unset,
	 * we use the supplied passphrase. That is needed
	 * for PEAP where 2 passphrases (identity and client
	 * cert may have to be provided.
	 */
	if (!connman_network_get_string(network, "WiFi.PrivateKeyPassphrase"))
		connman_network_set_string(network,
						"WiFi.PrivateKeyPassphrase",
						ssid->passphrase);
	/* We must have an identity for both PEAP and TLS */
	ssid->identity = connman_network_get_string(network, "WiFi.Identity");

	/* Use agent provided identity as a fallback */
	if (!ssid->identity || strlen(ssid->identity) == 0)
		ssid->identity = connman_network_get_string(network,
							"WiFi.AgentIdentity");

	ssid->anonymous_identity = connman_network_get_string(network,
						"WiFi.AnonymousIdentity");
	ssid->ca_cert_path = connman_network_get_string(network,
							"WiFi.CACertFile");
	ssid->subject_match = connman_network_get_string(network,
							"WiFi.SubjectMatch");
	ssid->altsubject_match = connman_network_get_string(network,
							"WiFi.AltSubjectMatch");
	ssid->domain_suffix_match = connman_network_get_string(network,
							"WiFi.DomainSuffixMatch");
	ssid->domain_match = connman_network_get_string(network,
							"WiFi.DomainMatch");
	ssid->client_cert_path = connman_network_get_string(network,
							"WiFi.ClientCertFile");
	ssid->private_key_path = connman_network_get_string(network,
							"WiFi.PrivateKeyFile");
	ssid->private_key_passphrase = connman_network_get_string(network,
						"WiFi.PrivateKeyPassphrase");
	ssid->phase2_auth = connman_network_get_string(network, "WiFi.Phase2");

	ssid->use_wps = connman_network_get_bool(network, "WiFi.UseWPS");
	ssid->pin_wps = connman_network_get_string(network, "WiFi.PinWPS");
#if defined TIZEN_EXT
	ssid->connector = connman_network_get_string(network,
							"WiFi.Connector");
	ssid->c_sign_key = connman_network_get_string(network,
							"WiFi.CSignKey");
	ssid->net_access_key = connman_network_get_string(network,
						"WiFi.NetAccessKey");
#endif

#if defined TIZEN_EXT
	if (set_connman_bssid(CHECK_BSSID, NULL) == 6) {
		ssid->bssid_for_connect_len = 6;
		set_connman_bssid(GET_BSSID, (char *)ssid->bssid_for_connect);
		DBG("BSSID : %02x:%02x:%02x:%02x:%02x:%02x",
			ssid->bssid_for_connect[0], ssid->bssid_for_connect[1],
			ssid->bssid_for_connect[2], ssid->bssid_for_connect[3],
			ssid->bssid_for_connect[4], ssid->bssid_for_connect[5]);
	} else {
		ssid->freq = connman_network_get_frequency(network);
	}

	GSList *bssid_list = (GSList *)connman_network_get_bssid_list(network);
	if (bssid_list && g_slist_length(bssid_list) > 1) {

		/* If there are more than one bssid,
		 * the user-specified bssid is tried only once at the beginning.
		 * After that, the bssids in the list are tried in order.
		 */
		if (set_connman_bssid(CHECK_BSSID, NULL) == 6) {
			set_connman_bssid(RESET_BSSID, NULL);
			goto done;
		}

		GSList *list;
		char buff[MAC_ADDRESS_LENGTH];
		for (list = bssid_list; list; list = list->next) {
			struct connman_bssids * bssids = (struct connman_bssids *)list->data;

			g_snprintf(buff, MAC_ADDRESS_LENGTH, "%02x:%02x:%02x:%02x:%02x:%02x",
					bssids->bssid[0], bssids->bssid[1], bssids->bssid[2],
					bssids->bssid[3], bssids->bssid[4], bssids->bssid[5]);
			buff[MAC_ADDRESS_LENGTH - 1] = '\0';

			gchar *curr_bssid = g_strdup((const gchar *)buff);

			if (g_hash_table_contains(failed_bssids, curr_bssid)) {
				DBG("bssid match, try next bssid");
				g_free(curr_bssid);
				continue;
			} else {
				g_hash_table_add(failed_bssids, curr_bssid);

				memcpy(buff_bssid, bssids->bssid, WIFI_BSSID_LEN_MAX);
				ssid->bssid = buff_bssid;
				ssid->freq = (unsigned int)bssids->frequency;
				break;
			}
		}

		if (!list) {
			ssid->bssid = connman_network_get_bssid(network);
			g_hash_table_remove_all(failed_bssids);
		}
	} else
		ssid->bssid = connman_network_get_bssid(network);

done:
	ssid->eap_keymgmt = network_eap_keymgmt(
			connman_network_get_string(network, "WiFi.KeymgmtType"));
	ssid->phase1 = connman_network_get_string(network, "WiFi.Phase1");

	if(g_strcmp0(ssid->eap, "fast") == 0)
		ssid->pac_file = g_strdup(WIFI_EAP_FAST_PAC_FILE);
#endif

	if (connman_setting_get_bool("BackgroundScanning"))
		ssid->bgscan = BGSCAN_DEFAULT;
}

static int network_connect(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct wifi_data *wifi;
	GSupplicantInterface *interface;
	GSupplicantSSID *ssid;

	DBG("network %p", network);

	if (!device)
		return -ENODEV;

	wifi = connman_device_get_data(device);
	if (!wifi)
		return -ENODEV;

	ssid = g_try_malloc0(sizeof(GSupplicantSSID));
	if (!ssid)
		return -ENOMEM;

	interface = wifi->interface;

	ssid_init(ssid, network);

	if (wifi->disconnecting) {
		wifi->pending_network = network;
#if defined TIZEN_EXT
		g_free(ssid->ssid);
#endif
		g_free(ssid);
	} else {
		wifi->network = connman_network_ref(network);
		wifi->retries = 0;
#if defined TIZEN_EXT
		wifi->scan_pending_network = NULL;
#endif

		return g_supplicant_interface_connect(interface, ssid,
						connect_callback, network);
	}

	return -EINPROGRESS;
}

static void disconnect_callback(int result, GSupplicantInterface *interface,
								void *user_data)
{
#if defined TIZEN_EXT
	GList *list;
	struct wifi_data *wifi;
	struct connman_network *network = user_data;

	DBG("network %p result %d", network, result);

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;

		if (wifi->network == NULL && wifi->disconnecting == true)
			wifi->disconnecting = false;

		if (wifi->network == network)
			goto found;
	}

	/* wifi_data may be invalid because wifi is already disabled */
	return;

found:
#else
	struct wifi_data *wifi = user_data;
#endif

	DBG("result %d supplicant interface %p wifi %p",
			result, interface, wifi);

	if (result == -ECONNABORTED) {
		DBG("wifi interface no longer available");
		return;
	}

	if (wifi->network != wifi->pending_network)
		connman_network_set_connected(wifi->network, false);
	wifi->network = NULL;

	wifi->disconnecting = false;
	wifi->connected = false;

	if (wifi->pending_network) {
		network_connect(wifi->pending_network);
		wifi->pending_network = NULL;
	}

	start_autoscan(wifi->device);
}

static int network_disconnect(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct wifi_data *wifi;
	int err;
#if defined TIZEN_EXT
	struct connman_service *service;
#endif

	DBG("network %p", network);

	wifi = connman_device_get_data(device);
	if (!wifi || !wifi->interface)
		return -ENODEV;

#if defined TIZEN_EXT
	if (connman_network_get_associating(network) == true) {
		connman_network_clear_associating(network);
		connman_network_set_bool(network, "WiFi.UseWPS", false);
	} else {
		service = connman_service_lookup_from_network(network);

		if (service != NULL &&
			(__connman_service_is_connected_state(service,
					CONNMAN_IPCONFIG_TYPE_IPV4) == false &&
			__connman_service_is_connected_state(service,
					CONNMAN_IPCONFIG_TYPE_IPV6) == false) &&
			(connman_service_get_favorite(service) == false))
					__connman_service_set_passphrase(service, NULL);
	}

	if (wifi->pending_network == network)
		wifi->pending_network = NULL;

	if (wifi->scan_pending_network == network)
		wifi->scan_pending_network = NULL;

#endif
	connman_network_set_associating(network, false);

	if (wifi->disconnecting)
		return -EALREADY;

	wifi->disconnecting = true;

#if defined TIZEN_EXT
	err = g_supplicant_interface_disconnect(wifi->interface,
						disconnect_callback, network);
#else
	err = g_supplicant_interface_disconnect(wifi->interface,
						disconnect_callback, wifi);
#endif

	if (err < 0)
		wifi->disconnecting = false;

	return err;
}

#if defined TIZEN_EXT
static void set_connection_mode(struct connman_network *network,
		int linkspeed)
{
	ieee80211_modes_e phy_mode;
	connection_mode_e conn_mode;

	phy_mode = connman_network_get_phy_mode(network);
	switch (phy_mode) {
	case IEEE80211_MODE_B:
		if (linkspeed > 0 && linkspeed <= 11)
			conn_mode = CONNECTION_MODE_IEEE80211B;
		else
			conn_mode = CONNECTION_MODE_IEEE80211_UNKNOWN;

		break;
	case IEEE80211_MODE_BG:
		if (linkspeed > 0 && linkspeed <= 11)
			conn_mode = CONNECTION_MODE_IEEE80211B;
		else if (linkspeed > 11 && linkspeed <= 54)
			conn_mode = CONNECTION_MODE_IEEE80211G;
		else
			conn_mode = CONNECTION_MODE_IEEE80211_UNKNOWN;

		break;
	case IEEE80211_MODE_BGN:
		if (linkspeed > 0 && linkspeed <= 11)
			conn_mode = CONNECTION_MODE_IEEE80211B;
		else if (linkspeed > 11 && linkspeed <= 54)
			conn_mode = CONNECTION_MODE_IEEE80211G;
		else if (linkspeed > 54 && linkspeed <= 450)
			conn_mode = CONNECTION_MODE_IEEE80211N;
		else
			conn_mode = CONNECTION_MODE_IEEE80211_UNKNOWN;

		break;
	case IEEE80211_MODE_A:
		if (linkspeed > 0 && linkspeed <= 54)
			conn_mode = CONNECTION_MODE_IEEE80211A;
		else
			conn_mode = CONNECTION_MODE_IEEE80211_UNKNOWN;

		break;
	case IEEE80211_MODE_AN:
		if (linkspeed > 0 && linkspeed <= 54)
			conn_mode = CONNECTION_MODE_IEEE80211A;
		else if (linkspeed > 54 && linkspeed <= 450)
			conn_mode = CONNECTION_MODE_IEEE80211N;
		else
			conn_mode = CONNECTION_MODE_IEEE80211_UNKNOWN;

		break;
	case IEEE80211_MODE_ANAC:
		if (linkspeed > 0 && linkspeed <= 54)
			conn_mode = CONNECTION_MODE_IEEE80211A;
		else if (linkspeed > 54 && linkspeed <= 450)
			conn_mode = CONNECTION_MODE_IEEE80211N;
		else if (linkspeed > 450 && linkspeed <= 1300)
			conn_mode = CONNECTION_MODE_IEEE80211AC;
		else
			conn_mode = CONNECTION_MODE_IEEE80211_UNKNOWN;

		break;
	default:
			conn_mode = CONNECTION_MODE_IEEE80211_UNKNOWN;
		break;
	}

	DBG("connection mode(%d)", conn_mode);
	connman_network_set_connection_mode(network, conn_mode);
}

static void signalpoll_callback(int result, int maxspeed, int strength,
				void *user_data)
{
	struct connman_network *network = user_data;

	if (result != 0) {
		DBG("Failed to get maxspeed from signalpoll !");
		return;
	}

	strength += 120;
	if (strength > 100)
		strength = 100;

	DBG("maxspeed = %d, strength = %d", maxspeed, strength);
	if (network) {
		connman_network_set_strength(network, (uint8_t)strength);
		connman_network_set_maxspeed(network, maxspeed);
		set_connection_mode(network, maxspeed);
	}
}

static int network_signalpoll(struct wifi_data *wifi)
{
	GSupplicantInterface *interface;
	struct connman_network *network;

	if (!wifi || !wifi->network)
		return -ENODEV;

	interface = wifi->interface;
	network = wifi->network;

	DBG("network %p", network);

	return g_supplicant_interface_signalpoll(interface, signalpoll_callback, network);
}

static gboolean autosignalpoll_timeout(gpointer data)
{
	struct wifi_data *wifi = data;

	if (!wifi || !wifi->automaxspeed_timeout) {
		DBG("automaxspeed_timeout is found to be zero. i.e. currently in disconnected state. !!");
		return FALSE;
	}

	int ret = network_signalpoll(wifi);
	if (ret < 0) {
		DBG("Fail to get max speed !!");
		wifi->automaxspeed_timeout = 0;
		return FALSE;
	}

	return TRUE;
}
#endif

static struct connman_network_driver network_driver = {
	.name		= "wifi",
	.type		= CONNMAN_NETWORK_TYPE_WIFI,
	.priority	= CONNMAN_NETWORK_PRIORITY_LOW,
	.probe		= network_probe,
	.remove		= network_remove,
	.connect	= network_connect,
	.disconnect	= network_disconnect,
};

static void interface_added(GSupplicantInterface *interface)
{
	const char *ifname = g_supplicant_interface_get_ifname(interface);
	const char *driver = g_supplicant_interface_get_driver(interface);
#if defined TIZEN_EXT
	bool is_5_0_ghz_supported = g_supplicant_interface_get_is_5_0_ghz_supported(interface);
#endif

	struct wifi_data *wifi;

	wifi = g_supplicant_interface_get_data(interface);
	if (!wifi) {
		wifi = get_pending_wifi_data(ifname);
		if (!wifi)
			return;

		wifi->interface = interface;
		g_supplicant_interface_set_data(interface, wifi);
		p2p_iface_list = g_list_append(p2p_iface_list, wifi);
		wifi->p2p_device = true;
	}

	DBG("ifname %s driver %s wifi %p tethering %d",
			ifname, driver, wifi, wifi->tethering);

	if (!wifi->device) {
		connman_error("WiFi device not set");
		return;
	}

	connman_device_set_powered(wifi->device, true);
#if defined TIZEN_EXT
	connman_techonology_wifi_set_5ghz_supported(wifi_technology, is_5_0_ghz_supported);
	/* Max number of SSIDs supported by wlan chipset that can be scanned */
	int max_scan_ssids = g_supplicant_interface_get_max_scan_ssids(interface);
	connman_techonology_set_max_scan_ssids(wifi_technology, max_scan_ssids);
#endif
}

static bool is_idle(struct wifi_data *wifi)
{
	DBG("state %d", wifi->state);

	switch (wifi->state) {
	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_DISABLED:
	case G_SUPPLICANT_STATE_DISCONNECTED:
	case G_SUPPLICANT_STATE_INACTIVE:
	case G_SUPPLICANT_STATE_SCANNING:
		return true;

	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
	case G_SUPPLICANT_STATE_COMPLETED:
		return false;
	}

	return false;
}

static bool is_idle_wps(GSupplicantInterface *interface,
						struct wifi_data *wifi)
{
	/* First, let's check if WPS processing did not went wrong */
	if (g_supplicant_interface_get_wps_state(interface) ==
		G_SUPPLICANT_WPS_STATE_FAIL)
		return false;

	/* Unlike normal connection, being associated while processing wps
	 * actually means that we are idling. */
	switch (wifi->state) {
	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_DISABLED:
	case G_SUPPLICANT_STATE_DISCONNECTED:
	case G_SUPPLICANT_STATE_INACTIVE:
	case G_SUPPLICANT_STATE_SCANNING:
	case G_SUPPLICANT_STATE_ASSOCIATED:
		return true;
	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
	case G_SUPPLICANT_STATE_COMPLETED:
		return false;
	}

	return false;
}

static bool handle_wps_completion(GSupplicantInterface *interface,
					struct connman_network *network,
					struct connman_device *device,
					struct wifi_data *wifi)
{
	bool wps;

	wps = connman_network_get_bool(network, "WiFi.UseWPS");
	if (wps) {
		const unsigned char *ssid, *wps_ssid;
		unsigned int ssid_len, wps_ssid_len;
		const char *wps_key;

		/* Checking if we got associated with requested
		 * network */
		ssid = connman_network_get_blob(network, "WiFi.SSID",
						&ssid_len);

		wps_ssid = g_supplicant_interface_get_wps_ssid(
			interface, &wps_ssid_len);

		if (!wps_ssid || wps_ssid_len != ssid_len ||
				memcmp(ssid, wps_ssid, ssid_len) != 0) {
			connman_network_set_associating(network, false);
#if defined TIZEN_EXT
			g_supplicant_interface_disconnect(wifi->interface,
						disconnect_callback, wifi->network);

			connman_network_set_bool(network, "WiFi.UseWPS", false);
			connman_network_set_string(network, "WiFi.PinWPS", NULL);
#else
			g_supplicant_interface_disconnect(wifi->interface,
						disconnect_callback, wifi);
#endif
			return false;
		}

		wps_key = g_supplicant_interface_get_wps_key(interface);
#if defined TIZEN_EXT
		/* Check the passphrase and encrypt it
		 */
		 int ret;
		 gchar *passphrase = g_strdup(wps_key);

		 connman_network_set_string(network, "WiFi.PinWPS", NULL);

		 if (check_passphrase_ext(network, passphrase) < 0) {
			 DBG("[WPS] Invalid passphrase");
			 g_free(passphrase);
			 return true;
		 }

		 ret = send_encryption_request(passphrase, network);

		 g_free(passphrase);

		 if (!ret)
			 DBG("[WPS] Encryption request succeeded");
		 else
			 DBG("[WPS] Encryption request failed %d", ret);

#else
		connman_network_set_string(network, "WiFi.Passphrase",
					wps_key);

		connman_network_set_string(network, "WiFi.PinWPS", NULL);
#endif
	}

	return true;
}

static bool handle_assoc_status_code(GSupplicantInterface *interface,
                                     struct wifi_data *wifi)
{
	if (wifi->state == G_SUPPLICANT_STATE_ASSOCIATING &&
#if defined TIZEN_EXT
			wifi->assoc_code > 0 &&
#else
			wifi->assoc_code == ASSOC_STATUS_NO_CLIENT &&
#endif
			wifi->load_shaping_retries < LOAD_SHAPING_MAX_RETRIES) {
		wifi->load_shaping_retries ++;
		return TRUE;
	}
	wifi->load_shaping_retries = 0;
	return FALSE;
}

static bool handle_4way_handshake_failure(GSupplicantInterface *interface,
					struct connman_network *network,
					struct wifi_data *wifi)
{
#if defined TIZEN_EXT
	const char *security;
	struct connman_service *service;

	if (wifi->connected)
		return false;

	security = connman_network_get_string(network, "WiFi.Security");

	if (security && g_str_equal(security, "ieee8021x") == true &&
			wifi->state == G_SUPPLICANT_STATE_ASSOCIATED) {
		wifi->retries = 0;
		connman_network_set_error(network, CONNMAN_NETWORK_ERROR_INVALID_KEY);

		return false;
	}

	if (wifi->state != G_SUPPLICANT_STATE_4WAY_HANDSHAKE)
		return false;
#else
	struct connman_service *service;

	if (wifi->state != G_SUPPLICANT_STATE_4WAY_HANDSHAKE)
		return false;

	if (wifi->connected)
		return false;
#endif

	service = connman_service_lookup_from_network(network);
	if (!service)
		return false;

	wifi->retries++;

	if (connman_service_get_favorite(service)) {
		if (wifi->retries < FAVORITE_MAXIMUM_RETRIES)
			return true;
	}

	wifi->retries = 0;
	connman_network_set_error(network, CONNMAN_NETWORK_ERROR_INVALID_KEY);

	return false;
}

#if defined TIZEN_EXT
static bool handle_wifi_assoc_retry(struct connman_network *network,
					struct wifi_data *wifi)
{
	const char *security;

	if (!wifi->network || wifi->connected || wifi->disconnecting ||
			connman_network_get_connecting(network) != true) {
		wifi->assoc_retry_count = 0;
		return false;
	}

	if (wifi->state != G_SUPPLICANT_STATE_ASSOCIATING &&
			wifi->state != G_SUPPLICANT_STATE_ASSOCIATED) {
		wifi->assoc_retry_count = 0;
		return false;
	}

	security = connman_network_get_string(network, "WiFi.Security");
	if (security && g_str_equal(security, "ieee8021x") == true &&
			wifi->state == G_SUPPLICANT_STATE_ASSOCIATED) {
		wifi->assoc_retry_count = 0;
		return false;
	}

	if (++wifi->assoc_retry_count >= TIZEN_ASSOC_RETRY_COUNT) {
		wifi->assoc_retry_count = 0;

		/* Honestly it's not an invalid-key error,
		 * however QA team recommends that the invalid-key error
		 * might be better to display for user experience.
		 */
		connman_network_set_error(network, CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL);

		return false;
	}

	return true;
}
#endif

static void interface_state(GSupplicantInterface *interface)
{
	struct connman_network *network;
	struct connman_device *device;
	struct wifi_data *wifi;
	GSupplicantState state = g_supplicant_interface_get_state(interface);
	bool wps;
	bool old_connected;

	wifi = g_supplicant_interface_get_data(interface);

	DBG("wifi %p interface state %d", wifi, state);

	if (!wifi)
		return;

	device = wifi->device;
	if (!device)
		return;

	if (state == G_SUPPLICANT_STATE_COMPLETED) {
		if (wifi->tethering_param) {
			g_free(wifi->tethering_param->ssid);
			g_free(wifi->tethering_param);
			wifi->tethering_param = NULL;
		}

		if (wifi->tethering)
			stop_autoscan(device);
	}

	if (g_supplicant_interface_get_ready(interface) &&
					!wifi->interface_ready) {
		wifi->interface_ready = true;
		finalize_interface_creation(wifi);
	}

	network = wifi->network;
	if (!network)
		return;

	switch (state) {
	case G_SUPPLICANT_STATE_SCANNING:
		if (wifi->connected)
			connman_network_set_connected(network, false);

		break;

	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
#if defined TIZEN_EXT
		reset_autoscan(device);
#else
		stop_autoscan(device);
#endif

		if (!wifi->connected)
			connman_network_set_associating(network, true);

		break;

	case G_SUPPLICANT_STATE_COMPLETED:
#if defined TIZEN_EXT
		/* though it should be already reset: */
		reset_autoscan(device);

		wifi->assoc_retry_count = 0;

		wifi->scan_pending_network = NULL;

		/* should be cleared scanning flag */
		bool scanning = connman_device_get_scanning(device,
					       CONNMAN_SERVICE_TYPE_WIFI);
		if (scanning){
			connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_WIFI, false);
			connman_device_unref(device);
		}

		if (!wifi->automaxspeed_timeout) {
			DBG("Going to start signalpoll timer!!");
			int ret = network_signalpoll(wifi);
			if (ret < 0)
				DBG("Fail to get max speed !!");
			else
				wifi->automaxspeed_timeout = g_timeout_add_seconds(10, autosignalpoll_timeout, wifi);
		}

		g_hash_table_remove_all(failed_bssids);
#else
		/* though it should be already stopped: */
		stop_autoscan(device);
#endif

		if (!handle_wps_completion(interface, network, device, wifi))
			break;

		connman_network_set_connected(network, true);

		wifi->disconnect_code = 0;
		wifi->assoc_code = 0;
		wifi->load_shaping_retries = 0;
		break;

	case G_SUPPLICANT_STATE_DISCONNECTED:
#if defined TIZEN_EXT
		connman_network_set_strength(network, 0);
		connman_network_set_maxspeed(network, 0);

		if (wifi->automaxspeed_timeout != 0) {
			g_source_remove(wifi->automaxspeed_timeout);
			wifi->automaxspeed_timeout = 0;
			DBG("Remove signalpoll timer!!");
		}
#endif
		/*
		 * If we're in one of the idle modes, we have
		 * not started association yet and thus setting
		 * those ones to FALSE could cancel an association
		 * in progress.
		 */
		wps = connman_network_get_bool(network, "WiFi.UseWPS");
		if (wps)
			if (is_idle_wps(interface, wifi))
				break;

		if (is_idle(wifi))
			break;

#if defined TIZEN_EXT
		if (handle_assoc_status_code(interface, wifi)) {
			GSList *bssid_list = (GSList *)connman_network_get_bssid_list(network);
			guint bssid_length = 0;

			if (bssid_list)
				bssid_length = g_slist_length(bssid_list);

			if (bssid_length > 1 && bssid_length > g_hash_table_size(failed_bssids)) {
				network_connect(network);
				break;
			}

			wifi->load_shaping_retries = 0;
		}

		g_hash_table_remove_all(failed_bssids);
#else
		if (handle_assoc_status_code(interface, wifi))
			break;
#endif

		/* If previous state was 4way-handshake, then
		 * it's either: psk was incorrect and thus we retry
		 * or if we reach the maximum retries we declare the
		 * psk as wrong */
		if (handle_4way_handshake_failure(interface,
						network, wifi))
			break;

		/* See table 8-36 Reason codes in IEEE Std 802.11 */
		switch (wifi->disconnect_code) {
		case 1: /* Unspecified reason */
			/* Let's assume it's because we got blocked */

		case 6: /* Class 2 frame received from nonauthenticated STA */
			connman_network_set_error(network,
						CONNMAN_NETWORK_ERROR_BLOCKED);
			break;

		default:
			break;
		}

#if defined TIZEN_EXT
		/* Some of Wi-Fi networks are not comply Wi-Fi specification.
		 * Retry association until its retry count is expired */
		if (handle_wifi_assoc_retry(network, wifi) == true) {
			throw_wifi_scan(wifi->device, scan_callback);
			wifi->scan_pending_network = wifi->network;
			break;
		}

		if(wifi->disconnect_code > 0){
			DBG("Set disconnect reason code(%d)", wifi->disconnect_code);
			connman_network_set_disconnect_reason(network, wifi->disconnect_code);
		}
#endif

		if (network != wifi->pending_network) {
			connman_network_set_connected(network, false);
			connman_network_set_associating(network, false);
		}
		wifi->disconnecting = false;

		start_autoscan(device);

		break;

	case G_SUPPLICANT_STATE_INACTIVE:
#if defined TIZEN_EXT
		if (handle_wps_completion(interface, network, device, wifi) == false)
			break;
#endif
		connman_network_set_associating(network, false);
		start_autoscan(device);

		break;

	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_DISABLED:
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
		break;
	}

	old_connected = wifi->connected;
	wifi->state = state;

	/* Saving wpa_s state policy:
	 * If connected and if the state changes are roaming related:
	 * --> We stay connected
	 * If completed
	 * --> We are connected
	 * All other case:
	 * --> We are not connected
	 * */
	switch (state) {
	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
		if (wifi->connected)
			connman_warn("Probably roaming right now!"
						" Staying connected...");
		break;
	case G_SUPPLICANT_STATE_SCANNING:
		wifi->connected = false;

		if (old_connected)
			start_autoscan(device);
		break;
	case G_SUPPLICANT_STATE_COMPLETED:
		wifi->connected = true;
		break;
	default:
		wifi->connected = false;
		break;
	}

	DBG("DONE");
}

static void interface_removed(GSupplicantInterface *interface)
{
	const char *ifname = g_supplicant_interface_get_ifname(interface);
	struct wifi_data *wifi;

	DBG("ifname %s", ifname);

	wifi = g_supplicant_interface_get_data(interface);

#if defined TIZEN_EXT_WIFI_MESH
	if (wifi && wifi->mesh_interface) {
		DBG("Notify mesh interface remove");
		connman_mesh_notify_interface_remove(true);
		struct wifi_mesh_info *mesh_info = wifi->mesh_info;
		g_free(mesh_info->parent_ifname);
		g_free(mesh_info->ifname);
		g_free(mesh_info->identifier);
		g_free(mesh_info);
		wifi->mesh_interface = false;
		wifi->mesh_info = NULL;
		return;
	}
#endif

	if (wifi)
		wifi->interface = NULL;

	if (wifi && wifi->tethering)
		return;

	if (!wifi || !wifi->device) {
		DBG("wifi interface already removed");
		return;
	}

	connman_device_set_powered(wifi->device, false);

	check_p2p_technology();
#if defined TIZEN_EXT_WIFI_MESH
	check_mesh_technology();
#endif
}

static void set_device_type(const char *type, char dev_type[17])
{
	const char *oui = "0050F204";
	const char *category = "0001";
	const char *sub_category = "0000";

	if (!g_strcmp0(type, "handset")) {
		category = "000A";
		sub_category = "0005";
	} else if (!g_strcmp0(type, "vm") || !g_strcmp0(type, "container"))
		sub_category = "0001";
	else if (!g_strcmp0(type, "server"))
		sub_category = "0002";
	else if (!g_strcmp0(type, "laptop"))
		sub_category = "0005";
	else if (!g_strcmp0(type, "desktop"))
		sub_category = "0006";
	else if (!g_strcmp0(type, "tablet"))
		sub_category = "0009";
	else if (!g_strcmp0(type, "watch"))
		category = "00FF";

	snprintf(dev_type, 17, "%s%s%s", category, oui, sub_category);
}

static void p2p_support(GSupplicantInterface *interface)
{
	char dev_type[17] = {};
	const char *hostname;

	DBG("");

	if (!interface)
		return;

	if (!g_supplicant_interface_has_p2p(interface))
		return;

	if (connman_technology_driver_register(&p2p_tech_driver) < 0) {
		DBG("Could not register P2P technology driver");
		return;
	}

	hostname = connman_utsname_get_hostname();
	if (!hostname)
		hostname = "ConnMan";

	set_device_type(connman_machine_get_type(), dev_type);
	g_supplicant_interface_set_p2p_device_config(interface,
							hostname, dev_type);
	connman_peer_driver_register(&peer_driver);
}

static void scan_started(GSupplicantInterface *interface)
{
	DBG("");
}

static void scan_finished(GSupplicantInterface *interface)
{
#if defined TIZEN_EXT
	struct wifi_data *wifi;
	bool is_associating = false;
	static bool is_scanning = true;
#endif

	DBG("");

#if defined TIZEN_EXT
	wifi = g_supplicant_interface_get_data(interface);
	if (wifi && wifi->scan_pending_network) {
		network_connect(wifi->scan_pending_network);
		wifi->scan_pending_network = NULL;
	}

	//service state - associating
	if(!wifi || !wifi->network)
		return;

	is_associating = connman_network_get_associating(wifi->network);
	if(is_associating && is_scanning){
		is_scanning = false;
		DBG("send scan for connecting");
		throw_wifi_scan(wifi->device, scan_callback);

		return;
	}
	is_scanning = true;

	//go scan

#endif
}

static void ap_create_fail(GSupplicantInterface *interface)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);
	int ret;

	if ((wifi->tethering) && (wifi->tethering_param)) {
		DBG("%s create AP fail \n",
				g_supplicant_interface_get_ifname(wifi->interface));

		connman_inet_remove_from_bridge(wifi->index, wifi->bridge);
		wifi->ap_supported = WIFI_AP_NOT_SUPPORTED;
		wifi->tethering = false;

		ret = tech_set_tethering(wifi->tethering_param->technology,
				wifi->tethering_param->ssid->ssid,
				wifi->tethering_param->ssid->passphrase,
				wifi->bridge, true);

		if ((ret == -EOPNOTSUPP) && (wifi_technology)) {
			connman_technology_tethering_notify(wifi_technology,false);
		}

		g_free(wifi->tethering_param->ssid);
		g_free(wifi->tethering_param);
		wifi->tethering_param = NULL;
	}
}

static unsigned char calculate_strength(GSupplicantNetwork *supplicant_network)
{
	unsigned char strength;

	strength = 120 + g_supplicant_network_get_signal(supplicant_network);
#if !defined TIZEN_EXT
	if (strength > 100)
		strength = 100;
#endif

	return strength;
}

#if defined TIZEN_EXT_WIFI_MESH
static void mesh_peer_added(GSupplicantNetwork *supplicant_network)
{
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	const char *name, *security;
	struct connman_mesh *connman_mesh;
	struct wifi_mesh_info *mesh_info;
	const unsigned char *bssid;
	const char *identifier;
	char *address;
	uint16_t frequency;
	int ret;

	interface = g_supplicant_network_get_interface(supplicant_network);
	wifi = g_supplicant_interface_get_data(interface);
	if (!wifi || !wifi->mesh_interface) {
		DBG("Virtual Mesh interface not created");
		return;
	}

	bssid = g_supplicant_network_get_bssid(supplicant_network);
	address = g_malloc0(19);
	snprintf(address, 19, "%02x:%02x:%02x:%02x:%02x:%02x", bssid[0], bssid[1],
								 bssid[2], bssid[3], bssid[4], bssid[5]);

	identifier = g_supplicant_network_get_identifier(supplicant_network);
	name = g_supplicant_network_get_name(supplicant_network);
	security = g_supplicant_network_get_security(supplicant_network);
	frequency = g_supplicant_network_get_frequency(supplicant_network);

	mesh_info = wifi->mesh_info;
	connman_mesh = connman_mesh_get(mesh_info->identifier, identifier);
	if (connman_mesh)
		goto done;

	DBG("Mesh Peer name %s identifier %s security %s added", name, identifier,
					security);
	connman_mesh = connman_mesh_create(mesh_info->identifier, identifier);
	connman_mesh_set_name(connman_mesh, name);
	connman_mesh_set_security(connman_mesh, security);
	connman_mesh_set_frequency(connman_mesh, frequency);
	connman_mesh_set_address(connman_mesh, address);
	connman_mesh_set_index(connman_mesh, mesh_info->index);
	connman_mesh_set_strength(connman_mesh,
						calculate_strength(supplicant_network));
	connman_mesh_set_peer_type(connman_mesh, CONNMAN_MESH_PEER_TYPE_DISCOVERED);

	ret = connman_mesh_register(connman_mesh);
	if (ret == -EALREADY)
		DBG("Mesh Peer is already registered");

done:
	g_free(address);
}

static void mesh_peer_removed(GSupplicantNetwork *supplicant_network)
{
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	struct connman_mesh *connman_mesh;
	struct wifi_mesh_info *mesh_info;
	const char *identifier;

	interface = g_supplicant_network_get_interface(supplicant_network);
	wifi = g_supplicant_interface_get_data(interface);
	if (!wifi || !wifi->mesh_interface) {
		DBG("Virtual Mesh interface not created");
		return;
	}

	identifier = g_supplicant_network_get_identifier(supplicant_network);
	if (!identifier) {
		DBG("Failed to get Mesh Peer identifier");
		return;
	}

	mesh_info = wifi->mesh_info;
	connman_mesh = connman_mesh_get(mesh_info->identifier, identifier);
	if (connman_mesh) {
		/* Do not unregister connected mesh peer */
		if (connman_mesh_peer_is_connected_state(connman_mesh)) {
			DBG("Mesh Peer %s is connected", identifier);
			return;
		}
		DBG("Mesh Peer identifier %s removed", identifier);
		connman_mesh_unregister(connman_mesh);
	}
}
#endif

static void network_added(GSupplicantNetwork *supplicant_network)
{
	struct connman_network *network;
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	const char *name, *identifier, *security, *group, *mode;
	const unsigned char *ssid;
	unsigned int ssid_len;
	bool wps;
	bool wps_pbc;
	bool wps_ready;
	bool wps_advertizing;

#if defined TIZEN_EXT
	GSList *vsie_list = NULL;
	const unsigned char *country_code;
	ieee80211_modes_e phy_mode;
#endif

	mode = g_supplicant_network_get_mode(supplicant_network);
	identifier = g_supplicant_network_get_identifier(supplicant_network);

	DBG("%s", identifier);

	if (!g_strcmp0(mode, "adhoc"))
		return;

#if defined TIZEN_EXT_WIFI_MESH
	if (!g_strcmp0(mode, "mesh")) {
		mesh_peer_added(supplicant_network);
		return;
	}
#endif

	interface = g_supplicant_network_get_interface(supplicant_network);
	wifi = g_supplicant_interface_get_data(interface);
	name = g_supplicant_network_get_name(supplicant_network);
	security = g_supplicant_network_get_security(supplicant_network);
	group = g_supplicant_network_get_identifier(supplicant_network);
	wps = g_supplicant_network_get_wps(supplicant_network);
	wps_pbc = g_supplicant_network_is_wps_pbc(supplicant_network);
	wps_ready = g_supplicant_network_is_wps_active(supplicant_network);
	wps_advertizing = g_supplicant_network_is_wps_advertizing(
							supplicant_network);

	if (!wifi)
		return;

	ssid = g_supplicant_network_get_ssid(supplicant_network, &ssid_len);

	network = connman_device_get_network(wifi->device, identifier);

	if (!network) {
		network = connman_network_create(identifier,
						CONNMAN_NETWORK_TYPE_WIFI);
		if (!network)
			return;

		connman_network_set_index(network, wifi->index);

		if (connman_device_add_network(wifi->device, network) < 0) {
			connman_network_unref(network);
			return;
		}

		wifi->networks = g_slist_prepend(wifi->networks, network);
	}

	if (name && name[0] != '\0')
		connman_network_set_name(network, name);

	connman_network_set_blob(network, "WiFi.SSID",
						ssid, ssid_len);
#if defined TIZEN_EXT
	vsie_list = (GSList *)g_supplicant_network_get_wifi_vsie(supplicant_network);
	if (vsie_list)
		connman_network_set_vsie_list(network, vsie_list);
	else
		DBG("vsie_list is NULL");
	country_code = g_supplicant_network_get_countrycode(supplicant_network);
	connman_network_set_countrycode(network, country_code);
	phy_mode = g_supplicant_network_get_phy_mode(supplicant_network);
	connman_network_set_phy_mode(network, phy_mode);
#endif
	connman_network_set_string(network, "WiFi.Security", security);
	connman_network_set_strength(network,
				calculate_strength(supplicant_network));
	connman_network_set_bool(network, "WiFi.WPS", wps);
	connman_network_set_bool(network, "WiFi.WPSAdvertising",
				wps_advertizing);

	if (wps) {
		/* Is AP advertizing for WPS association?
		 * If so, we decide to use WPS by default */
		if (wps_ready && wps_pbc &&
						wps_advertizing)
#if !defined TIZEN_EXT
			connman_network_set_bool(network, "WiFi.UseWPS", true);
#else
			DBG("wps is activating by ap but ignore it.");
#endif
	}

	connman_network_set_frequency(network,
			g_supplicant_network_get_frequency(supplicant_network));

#if defined TIZEN_EXT
	connman_network_set_bssid(network,
			g_supplicant_network_get_bssid(supplicant_network));
	connman_network_set_maxrate(network,
			g_supplicant_network_get_maxrate(supplicant_network));
	connman_network_set_enc_mode(network,
			g_supplicant_network_get_enc_mode(supplicant_network));
	connman_network_set_rsn_mode(network,
			g_supplicant_network_get_rsn_mode(supplicant_network));
	connman_network_set_keymgmt(network,
			g_supplicant_network_get_keymgmt(supplicant_network));
	connman_network_set_bool(network, "WiFi.HS20AP",
			g_supplicant_network_is_hs20AP(supplicant_network));
	connman_network_set_bssid_list(network,
			(GSList *)g_supplicant_network_get_bssid_list(supplicant_network));
#endif
	connman_network_set_available(network, true);
	connman_network_set_string(network, "WiFi.Mode", mode);

#if defined TIZEN_EXT
	if (group)
#else
	if (ssid)
#endif
		connman_network_set_group(network, group);

#if defined TIZEN_EXT
	if (wifi_first_scan == true)
		found_with_first_scan = true;
#endif

	if (wifi->hidden && ssid) {
#if defined TIZEN_EXT
		if (network_security(wifi->hidden->security) ==
			network_security(security) &&
#else
		if (!g_strcmp0(wifi->hidden->security, security) &&
#endif
				wifi->hidden->ssid_len == ssid_len &&
				!memcmp(wifi->hidden->ssid, ssid, ssid_len)) {
			connman_network_connect_hidden(network,
					wifi->hidden->identity,
					wifi->hidden->passphrase,
					wifi->hidden->user_data);
			wifi->hidden->user_data = NULL;
			hidden_free(wifi->hidden);
			wifi->hidden = NULL;
		}
	}
}

static void network_removed(GSupplicantNetwork *network)
{
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	const char *name, *identifier;
	struct connman_network *connman_network;

#if defined TIZEN_EXT_WIFI_MESH
	const char *mode;
	mode = g_supplicant_network_get_mode(network);
	if (!g_strcmp0(mode, "mesh")) {
		mesh_peer_removed(network);
		return;
	}
#endif

	interface = g_supplicant_network_get_interface(network);
	wifi = g_supplicant_interface_get_data(interface);
	identifier = g_supplicant_network_get_identifier(network);
	name = g_supplicant_network_get_name(network);

	DBG("name %s", name);

	if (!wifi)
		return;

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (!connman_network)
		return;

#if defined TIZEN_EXT
	if (connman_network == wifi->scan_pending_network)
		wifi->scan_pending_network = NULL;

	if (connman_network == wifi->pending_network)
		wifi->pending_network = NULL;

	if(connman_network_get_connecting(connman_network) == true){
		connman_network_set_connected(connman_network, false);
	}
#endif

	wifi->networks = g_slist_remove(wifi->networks, connman_network);

	connman_device_remove_network(wifi->device, connman_network);
	connman_network_unref(connman_network);
}

static void network_changed(GSupplicantNetwork *network, const char *property)
{
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	const char *name, *identifier;
	struct connman_network *connman_network;
	bool update_needed;

#if defined TIZEN_EXT
	const unsigned char *bssid;
	unsigned int maxrate;
	uint16_t frequency;
	bool wps;
	const unsigned char *country_code;
	ieee80211_modes_e phy_mode;
	GSList *bssid_list;
#endif

	interface = g_supplicant_network_get_interface(network);
	wifi = g_supplicant_interface_get_data(interface);
	identifier = g_supplicant_network_get_identifier(network);
	name = g_supplicant_network_get_name(network);

	DBG("name %s", name);

	if (!wifi)
		return;

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (!connman_network)
		return;

	if (g_str_equal(property, "WPSCapabilities")) {
		bool wps;
		bool wps_pbc;
		bool wps_ready;
		bool wps_advertizing;

		wps = g_supplicant_network_get_wps(network);
		wps_pbc = g_supplicant_network_is_wps_pbc(network);
		wps_ready = g_supplicant_network_is_wps_active(network);
		wps_advertizing =
			g_supplicant_network_is_wps_advertizing(network);

		connman_network_set_bool(connman_network, "WiFi.WPS", wps);
		connman_network_set_bool(connman_network,
				"WiFi.WPSAdvertising", wps_advertizing);

		if (wps) {
			/*
			 * Is AP advertizing for WPS association?
			 * If so, we decide to use WPS by default
			 */
			if (wps_ready && wps_pbc && wps_advertizing)
				connman_network_set_bool(connman_network,
							"WiFi.UseWPS", true);
		}

		update_needed = true;
	} else if (g_str_equal(property, "Signal")) {
		connman_network_set_strength(connman_network,
					calculate_strength(network));
		update_needed = true;
	} else
		update_needed = false;

	if (update_needed)
		connman_network_update(connman_network);

#if defined TIZEN_EXT
	bssid = g_supplicant_network_get_bssid(network);
	maxrate = g_supplicant_network_get_maxrate(network);
	frequency = g_supplicant_network_get_frequency(network);
	wps = g_supplicant_network_get_wps(network);
	phy_mode = g_supplicant_network_get_phy_mode(network);

	connman_network_set_bssid(connman_network, bssid);
	connman_network_set_maxrate(connman_network, maxrate);
	connman_network_set_frequency(connman_network, frequency);
	connman_network_set_bool(connman_network, "WiFi.WPS", wps);
	country_code = g_supplicant_network_get_countrycode(network);
	connman_network_set_countrycode(connman_network, country_code);
	bssid_list = (GSList *)g_supplicant_network_get_bssid_list(network);
	connman_network_set_bssid_list(connman_network, bssid_list);
	connman_network_set_phy_mode(connman_network, phy_mode);

	if (g_str_equal(property, "CheckMultiBssidConnect") &&
			connman_network_get_associating(connman_network))
		network_connect(connman_network);
#endif
}

static void network_associated(GSupplicantNetwork *network)
{
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	struct connman_network *connman_network;
	const char *identifier;

	DBG("");

	interface = g_supplicant_network_get_interface(network);
	if (!interface)
		return;

	wifi = g_supplicant_interface_get_data(interface);
	if (!wifi)
		return;

	/* P2P networks must not be treated as WiFi networks */
	if (wifi->p2p_connecting || wifi->p2p_device)
		return;

	identifier = g_supplicant_network_get_identifier(network);

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (!connman_network)
		return;

	if (wifi->network) {
		if (wifi->network == connman_network)
			return;

		/*
		 * This should never happen, we got associated with
		 * a network different than the one we were expecting.
		 */
		DBG("Associated to %p while expecting %p",
					connman_network, wifi->network);

		connman_network_set_associating(wifi->network, false);
	}

	DBG("Reconnecting to previous network %p from wpa_s", connman_network);

	wifi->network = connman_network_ref(connman_network);
	wifi->retries = 0;

	/*
	 * Interface state changes callback (interface_state) is always
	 * called before network_associated callback thus we need to call
	 * interface_state again in order to process the new state now that
	 * we have the network properly set.
	 */
	interface_state(interface);
}

static void sta_authorized(GSupplicantInterface *interface,
					const char *addr)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);

	DBG("wifi %p station %s authorized", wifi, addr);

	if (!wifi || !wifi->tethering)
		return;

	__connman_tethering_client_register(addr);
}

static void sta_deauthorized(GSupplicantInterface *interface,
					const char *addr)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);

	DBG("wifi %p station %s deauthorized", wifi, addr);

	if (!wifi || !wifi->tethering)
		return;

	__connman_tethering_client_unregister(addr);
}

static void apply_peer_services(GSupplicantPeer *peer,
				struct connman_peer *connman_peer)
{
	const unsigned char *data;
	int length;

	DBG("");

	connman_peer_reset_services(connman_peer);

	data = g_supplicant_peer_get_widi_ies(peer, &length);
	if (data) {
		connman_peer_add_service(connman_peer,
			CONNMAN_PEER_SERVICE_WIFI_DISPLAY, data, length);
	}
}

static void peer_found(GSupplicantPeer *peer)
{
	GSupplicantInterface *iface = g_supplicant_peer_get_interface(peer);
	struct wifi_data *wifi = g_supplicant_interface_get_data(iface);
	struct connman_peer *connman_peer;
	const char *identifier, *name;
	int ret;

#if defined TIZEN_EXT
	if (!wifi)
		return;
#endif
	identifier = g_supplicant_peer_get_identifier(peer);
	name = g_supplicant_peer_get_name(peer);

	DBG("ident: %s", identifier);

	connman_peer = connman_peer_get(wifi->device, identifier);
	if (connman_peer)
		return;

	connman_peer = connman_peer_create(identifier);
	connman_peer_set_name(connman_peer, name);
	connman_peer_set_device(connman_peer, wifi->device);
	apply_peer_services(peer, connman_peer);

	ret = connman_peer_register(connman_peer);
	if (ret < 0 && ret != -EALREADY)
		connman_peer_unref(connman_peer);
	else
		wifi->peers = g_slist_prepend(wifi->peers, connman_peer);
}

static void peer_lost(GSupplicantPeer *peer)
{
	GSupplicantInterface *iface = g_supplicant_peer_get_interface(peer);
	struct wifi_data *wifi = g_supplicant_interface_get_data(iface);
	struct connman_peer *connman_peer;
	const char *identifier;

	if (!wifi)
		return;

	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("ident: %s", identifier);

	connman_peer = connman_peer_get(wifi->device, identifier);
	if (connman_peer) {
		if (wifi->p2p_connecting &&
				wifi->pending_peer == connman_peer) {
			peer_connect_timeout(wifi);
		}
		connman_peer_unregister(connman_peer);
		connman_peer_unref(connman_peer);
	}

	wifi->peers = g_slist_remove(wifi->peers, connman_peer);
}

static void peer_changed(GSupplicantPeer *peer, GSupplicantPeerState state)
{
	GSupplicantInterface *iface = g_supplicant_peer_get_interface(peer);
	struct wifi_data *wifi = g_supplicant_interface_get_data(iface);
	enum connman_peer_state p_state = CONNMAN_PEER_STATE_UNKNOWN;
	struct connman_peer *connman_peer;
	const char *identifier;

	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("ident: %s", identifier);

	if (!wifi)
		return;

	connman_peer = connman_peer_get(wifi->device, identifier);
	if (!connman_peer)
		return;

	switch (state) {
	case G_SUPPLICANT_PEER_SERVICES_CHANGED:
		apply_peer_services(peer, connman_peer);
		connman_peer_services_changed(connman_peer);
		return;
	case G_SUPPLICANT_PEER_GROUP_CHANGED:
		if (!g_supplicant_peer_is_in_a_group(peer))
			p_state = CONNMAN_PEER_STATE_IDLE;
		else
			p_state = CONNMAN_PEER_STATE_CONFIGURATION;
		break;
	case G_SUPPLICANT_PEER_GROUP_STARTED:
		break;
	case G_SUPPLICANT_PEER_GROUP_FINISHED:
		p_state = CONNMAN_PEER_STATE_IDLE;
		break;
	case G_SUPPLICANT_PEER_GROUP_JOINED:
		connman_peer_set_iface_address(connman_peer,
				g_supplicant_peer_get_iface_address(peer));
		break;
	case G_SUPPLICANT_PEER_GROUP_DISCONNECTED:
		p_state = CONNMAN_PEER_STATE_IDLE;
		break;
	case G_SUPPLICANT_PEER_GROUP_FAILED:
		if (g_supplicant_peer_has_requested_connection(peer))
			p_state = CONNMAN_PEER_STATE_IDLE;
		else
			p_state = CONNMAN_PEER_STATE_FAILURE;
		break;
	}

	if (p_state == CONNMAN_PEER_STATE_CONFIGURATION ||
					p_state == CONNMAN_PEER_STATE_FAILURE) {
		if (wifi->p2p_connecting
				&& connman_peer == wifi->pending_peer)
			peer_cancel_timeout(wifi);
		else
			p_state = CONNMAN_PEER_STATE_UNKNOWN;
	}

	if (p_state == CONNMAN_PEER_STATE_UNKNOWN)
		return;

	if (p_state == CONNMAN_PEER_STATE_CONFIGURATION) {
		GSupplicantInterface *g_iface;
		struct wifi_data *g_wifi;

		g_iface = g_supplicant_peer_get_group_interface(peer);
		if (!g_iface)
			return;

		g_wifi = g_supplicant_interface_get_data(g_iface);
		if (!g_wifi)
			return;

		connman_peer_set_as_master(connman_peer,
					!g_supplicant_peer_is_client(peer));
		connman_peer_set_sub_device(connman_peer, g_wifi->device);

		/*
		 * If wpa_supplicant didn't create a dedicated p2p-group
		 * interface then mark this interface as p2p_device to avoid
		 * scan and auto-scan are launched on it while P2P is connected.
		 */
		if (!g_list_find(p2p_iface_list, g_wifi))
			wifi->p2p_device = true;
	}

	connman_peer_set_state(connman_peer, p_state);
}

static void peer_request(GSupplicantPeer *peer)
{
	GSupplicantInterface *iface = g_supplicant_peer_get_interface(peer);
	struct wifi_data *wifi = g_supplicant_interface_get_data(iface);
	struct connman_peer *connman_peer;
	const char *identifier;

#if defined TIZEN_EXT
	if (!wifi)
		return;
#endif

	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("ident: %s", identifier);

	connman_peer = connman_peer_get(wifi->device, identifier);
	if (!connman_peer)
		return;

	connman_peer_request_connection(connman_peer);
}

#if defined TIZEN_EXT
static void system_power_off(void)
{
	GList *list;
	struct wifi_data *wifi;
	struct connman_service *service;
	struct connman_ipconfig *ipconfig_ipv4;

	if (connman_setting_get_bool("WiFiDHCPRelease") == true) {
		for (list = iface_list; list; list = list->next) {
			wifi = list->data;

			if (wifi->network != NULL) {
				service = connman_service_lookup_from_network(wifi->network);
				ipconfig_ipv4 = __connman_service_get_ip4config(service);
				__connman_dhcp_stop(ipconfig_ipv4);
			}
		}
	}
}

static void network_merged(GSupplicantNetwork *network)
{
	GSupplicantInterface *interface;
	GSupplicantState state;
	struct wifi_data *wifi;
	const char *identifier;
	struct connman_network *connman_network;
	bool ishs20AP = 0;
	char *temp = NULL;

	interface = g_supplicant_network_get_interface(network);
	if (!interface)
		return;

	state = g_supplicant_interface_get_state(interface);
	if (state < G_SUPPLICANT_STATE_AUTHENTICATING)
		return;

	wifi = g_supplicant_interface_get_data(interface);
	if (!wifi)
		return;

	identifier = g_supplicant_network_get_identifier(network);

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (!connman_network)
		return;

	DBG("merged identifier %s", identifier);

	if (wifi->connected == FALSE) {
		switch (state) {
		case G_SUPPLICANT_STATE_AUTHENTICATING:
		case G_SUPPLICANT_STATE_ASSOCIATING:
		case G_SUPPLICANT_STATE_ASSOCIATED:
		case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
		case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
			connman_network_set_associating(connman_network, TRUE);
			break;
		case G_SUPPLICANT_STATE_COMPLETED:
			connman_network_set_connected(connman_network, TRUE);
			break;
		default:
			DBG("Not handled the state : %d", state);
			break;
		}
	}

	ishs20AP = g_supplicant_network_is_hs20AP(network);

	if (ishs20AP &&
		g_strcmp0(g_supplicant_network_get_security(network), "ieee8021x") == 0) {
		temp = g_ascii_strdown(g_supplicant_network_get_eap(network), -1);
		connman_network_set_string(connman_network, "WiFi.EAP",
				temp);
		connman_network_set_string(connman_network, "WiFi.Identity",
				g_supplicant_network_get_identity(network));
		connman_network_set_string(connman_network, "WiFi.Phase2",
				g_supplicant_network_get_phase2(network));

		g_free(temp);
	}

	wifi->network = connman_network;
}

static void assoc_failed(void *user_data)
{
	struct connman_network *network = user_data;
	connman_network_set_associating(network, false);
}
#endif

static void debug(const char *str)
{
	if (getenv("CONNMAN_SUPPLICANT_DEBUG"))
		connman_debug("%s", str);
}

static void disconnect_reasoncode(GSupplicantInterface *interface,
				int reasoncode)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);

	if (wifi != NULL) {
		wifi->disconnect_code = reasoncode;
	}
}

static void assoc_status_code(GSupplicantInterface *interface, int status_code)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);

	if (wifi != NULL) {
		wifi->assoc_code = status_code;
	}
}

static const GSupplicantCallbacks callbacks = {
	.system_ready		= system_ready,
	.system_killed		= system_killed,
	.interface_added	= interface_added,
	.interface_state	= interface_state,
	.interface_removed	= interface_removed,
	.p2p_support		= p2p_support,
	.scan_started		= scan_started,
	.scan_finished		= scan_finished,
	.ap_create_fail		= ap_create_fail,
	.network_added		= network_added,
	.network_removed	= network_removed,
	.network_changed	= network_changed,
	.network_associated	= network_associated,
	.sta_authorized		= sta_authorized,
	.sta_deauthorized	= sta_deauthorized,
	.peer_found		= peer_found,
	.peer_lost		= peer_lost,
	.peer_changed		= peer_changed,
	.peer_request		= peer_request,
#if defined TIZEN_EXT
	.system_power_off	= system_power_off,
	.network_merged	= network_merged,
	.assoc_failed		= assoc_failed,
#endif
	.debug			= debug,
	.disconnect_reasoncode  = disconnect_reasoncode,
	.assoc_status_code      = assoc_status_code,
#if defined TIZEN_EXT_WIFI_MESH
	.mesh_support		= mesh_support,
	.mesh_group_started = mesh_group_started,
	.mesh_group_removed = mesh_group_removed,
	.mesh_peer_connected = mesh_peer_connected,
	.mesh_peer_disconnected = mesh_peer_disconnected,
#endif
};


static int tech_probe(struct connman_technology *technology)
{
	wifi_technology = technology;

	return 0;
}

static void tech_remove(struct connman_technology *technology)
{
	wifi_technology = NULL;
}

static GSupplicantSSID *ssid_ap_init(const char *ssid, const char *passphrase)
{
	GSupplicantSSID *ap;

	ap = g_try_malloc0(sizeof(GSupplicantSSID));
	if (!ap)
		return NULL;

	ap->mode = G_SUPPLICANT_MODE_MASTER;
#if defined TIZEN_EXT
	ap->ssid = (void *) ssid;
#else
	ap->ssid = ssid;
#endif
	ap->ssid_len = strlen(ssid);
	ap->scan_ssid = 0;
	ap->freq = 2412;

	if (!passphrase || strlen(passphrase) == 0) {
		ap->security = G_SUPPLICANT_SECURITY_NONE;
		ap->passphrase = NULL;
	} else {
	       ap->security = G_SUPPLICANT_SECURITY_PSK;
	       ap->protocol = G_SUPPLICANT_PROTO_RSN;
	       ap->pairwise_cipher = G_SUPPLICANT_PAIRWISE_CCMP;
	       ap->group_cipher = G_SUPPLICANT_GROUP_CCMP;
	       ap->passphrase = passphrase;
	}

	return ap;
}

static void ap_start_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_tethering_info *info = user_data;

	DBG("result %d index %d bridge %s",
		result, info->wifi->index, info->wifi->bridge);

	if ((result < 0) || (info->wifi->ap_supported != WIFI_AP_SUPPORTED)) {
		connman_inet_remove_from_bridge(info->wifi->index,
							info->wifi->bridge);

		if (info->wifi->ap_supported == WIFI_AP_SUPPORTED) {
			connman_technology_tethering_notify(info->technology, false);
			g_free(info->wifi->tethering_param->ssid);
			g_free(info->wifi->tethering_param);
			info->wifi->tethering_param = NULL;
		}
	}

	g_free(info->ifname);
	g_free(info);
}

static void ap_create_callback(int result,
				GSupplicantInterface *interface,
					void *user_data)
{
	struct wifi_tethering_info *info = user_data;

	DBG("result %d ifname %s", result,
				g_supplicant_interface_get_ifname(interface));

	if ((result < 0) || (info->wifi->ap_supported != WIFI_AP_SUPPORTED)) {
		connman_inet_remove_from_bridge(info->wifi->index,
							info->wifi->bridge);

		if (info->wifi->ap_supported == WIFI_AP_SUPPORTED) {
			connman_technology_tethering_notify(info->technology, false);
			g_free(info->wifi->tethering_param->ssid);
			g_free(info->wifi->tethering_param);
			info->wifi->tethering_param = NULL;

		}

		g_free(info->ifname);
		g_free(info->ssid);
		g_free(info);
		return;
	}

	info->wifi->interface = interface;
	g_supplicant_interface_set_data(interface, info->wifi);

	if (g_supplicant_interface_set_apscan(interface, 2) < 0)
		connman_error("Failed to set interface ap_scan property");

	g_supplicant_interface_connect(interface, info->ssid,
						ap_start_callback, info);
}

static void sta_remove_callback(int result,
				GSupplicantInterface *interface,
					void *user_data)
{
	struct wifi_tethering_info *info = user_data;
	const char *driver = connman_option_get_string("wifi");

	DBG("ifname %s result %d ", info->ifname, result);

	if ((result < 0) || (info->wifi->ap_supported != WIFI_AP_SUPPORTED)) {
		info->wifi->tethering = false;
		connman_technology_tethering_notify(info->technology, false);
#if !defined TIZEN_EXT

		g_free(info->ifname);
		g_free(info->ssid);
		g_free(info);
#endif /* !defined TIZEN_EXT */

		if (info->wifi->ap_supported == WIFI_AP_SUPPORTED) {
			g_free(info->wifi->tethering_param->ssid);
			g_free(info->wifi->tethering_param);
			info->wifi->tethering_param = NULL;
		}
#if defined TIZEN_EXT

		g_free(info->ifname);
		g_free(info->ssid);
		g_free(info);
#endif /* defined TIZEN_EXT */
		return;
	}

	info->wifi->interface = NULL;

	g_supplicant_interface_create(info->ifname, driver, info->wifi->bridge,
						ap_create_callback,
							info);
}

static int enable_wifi_tethering(struct connman_technology *technology,
				const char *bridge, const char *identifier,
				const char *passphrase, bool available)
{
	GList *list;
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	struct wifi_tethering_info *info;
	const char *ifname;
	unsigned int mode;
	int err, berr = 0;

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;

		DBG("wifi %p network %p pending_network %p", wifi,
			wifi->network, wifi->pending_network);

		interface = wifi->interface;

		if (!interface)
			continue;

		ifname = g_supplicant_interface_get_ifname(wifi->interface);
		if (!ifname)
			continue;

		if (wifi->ap_supported == WIFI_AP_NOT_SUPPORTED) {
			DBG("%s does not support AP mode (detected)", ifname);
			continue;
		}

		mode = g_supplicant_interface_get_mode(interface);
		if ((mode & G_SUPPLICANT_CAPABILITY_MODE_AP) == 0) {
			wifi->ap_supported = WIFI_AP_NOT_SUPPORTED;
			DBG("%s does not support AP mode (capability)", ifname);
			continue;
		}

		if (wifi->network && available)
			continue;

		info = g_try_malloc0(sizeof(struct wifi_tethering_info));
		if (!info)
			return -ENOMEM;

		wifi->tethering_param = g_try_malloc0(sizeof(struct wifi_tethering_info));
		if (!wifi->tethering_param) {
			g_free(info);
			return -ENOMEM;
		}

		info->wifi = wifi;
		info->technology = technology;
		info->wifi->bridge = bridge;
		info->ssid = ssid_ap_init(identifier, passphrase);
		if (!info->ssid)
			goto failed;

		info->ifname = g_strdup(ifname);

		wifi->tethering_param->technology = technology;
		wifi->tethering_param->ssid = ssid_ap_init(identifier, passphrase);
		if (!wifi->tethering_param->ssid)
			goto failed;

		info->wifi->tethering = true;
		info->wifi->ap_supported = WIFI_AP_SUPPORTED;

		berr = connman_technology_tethering_notify(technology, true);
		if (berr < 0)
			goto failed;

		err = g_supplicant_interface_remove(interface,
						sta_remove_callback,
							info);
		if (err >= 0) {
			DBG("tethering wifi %p ifname %s", wifi, ifname);
			return 0;
		}

	failed:
		g_free(info->ifname);
		g_free(info->ssid);
		g_free(info);
		g_free(wifi->tethering_param);
		wifi->tethering_param = NULL;

		/*
		 * Remove bridge if it was correctly created but remove
		 * operation failed. Instead, if bridge creation failed then
		 * break out and do not try again on another interface,
		 * bridge set-up does not depend on it.
		 */
		if (berr == 0)
			connman_technology_tethering_notify(technology, false);
		else
			break;
	}

	return -EOPNOTSUPP;
}

static int tech_set_tethering(struct connman_technology *technology,
				const char *identifier, const char *passphrase,
				const char *bridge, bool enabled)
{
	GList *list;
	struct wifi_data *wifi;
	int err;

	DBG("");

	if (!enabled) {
		for (list = iface_list; list; list = list->next) {
			wifi = list->data;

			if (wifi->tethering) {
				wifi->tethering = false;

				connman_inet_remove_from_bridge(wifi->index,
									bridge);
				wifi->bridged = false;
			}
		}

		connman_technology_tethering_notify(technology, false);

		return 0;
	}

	DBG("trying tethering for available devices");
	err = enable_wifi_tethering(technology, bridge, identifier, passphrase,
				true);

	if (err < 0) {
		DBG("trying tethering for any device");
		err = enable_wifi_tethering(technology, bridge, identifier,
					passphrase, false);
	}

	return err;
}

static void regdom_callback(int result, const char *alpha2, void *user_data)
{
	DBG("");

	if (!wifi_technology)
		return;

	if (result != 0)
		alpha2 = NULL;

	connman_technology_regdom_notify(wifi_technology, alpha2);
}

static int tech_set_regdom(struct connman_technology *technology, const char *alpha2)
{
	return g_supplicant_set_country(alpha2, regdom_callback, NULL);
}

static struct connman_technology_driver tech_driver = {
	.name		= "wifi",
	.type		= CONNMAN_SERVICE_TYPE_WIFI,
	.probe		= tech_probe,
	.remove		= tech_remove,
	.set_tethering	= tech_set_tethering,
	.set_regdom	= tech_set_regdom,
};

static int wifi_init(void)
{
	int err;

	err = connman_network_driver_register(&network_driver);
	if (err < 0)
		return err;

	err = g_supplicant_register(&callbacks);
	if (err < 0) {
		connman_network_driver_unregister(&network_driver);
		return err;
	}

	err = connman_technology_driver_register(&tech_driver);
	if (err < 0) {
		g_supplicant_unregister(&callbacks);
		connman_network_driver_unregister(&network_driver);
		return err;
	}

#if defined TIZEN_EXT
	failed_bssids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
#endif
	return 0;
}

static void wifi_exit(void)
{
	DBG();

	connman_technology_driver_unregister(&tech_driver);

	g_supplicant_unregister(&callbacks);

	connman_network_driver_unregister(&network_driver);

#if defined TIZEN_EXT
	g_hash_table_unref(failed_bssids);
#endif
}

CONNMAN_PLUGIN_DEFINE(wifi, "WiFi interface plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, wifi_init, wifi_exit)
