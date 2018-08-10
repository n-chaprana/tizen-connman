/*
 *
 *  Connection Manager
 *
 *
 *  Copyright (C) 2017 Samsung Electronics Co., Ltd.
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
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 *  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <gdbus.h>

#include <connman/storage.h>
#include "connman.h"
#include <sys/types.h>
#include <dirent.h>
#include <linux/if_bridge.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "mesh-netlink.h"

static DBusConnection *connection;

static GHashTable *mesh_table;
static GHashTable *connected_peer_table;
static GHashTable *disconnected_peer_table;

static struct connman_mesh_driver *mesh_driver;
static struct connman_mesh_eth_driver *mesh_eth_driver;

char *mesh_ifname;
char *bridge_interface;
static unsigned int mesh_autoconnect_timeout;
static bool is_mesh_if_created;
bool eth_if_bridged;
mesh_nl80211_global *nl80211_global;

struct connman_mesh {
	int refcount;
	char *identifier;
	char *name;
	char *path;
	char *address;
	char *interface_addr;
	enum connman_mesh_security security;
	char *passphrase;
	enum connman_mesh_state state;
	enum connman_mesh_peer_type peer_type;
	enum connman_mesh_peer_disconnect_reason disconnect_reason;
	uint16_t frequency;
	uint8_t strength;
	bool registered;
	bool favorite;
	DBusMessage *pending;
	int index;
	int br_index;
	uint16_t ieee80211w;
	struct connman_ipconfig *ipconfig;
};

struct connman_mesh_connected_peer {
	char *peer_address;
};

struct connman_mesh_disconnected_peer {
	char *peer_address;
	enum connman_mesh_peer_disconnect_reason disconnect_reason;
};

struct connman_mesh_change_peer_data {
	DBusMessage *pending;
	char *peer_address;
	enum connman_mesh_peer_status status;
};

static void mesh_dhcp_callback(struct connman_ipconfig *ipconfig,
				struct connman_network *network, bool success, gpointer data);

static void mesh_free(gpointer data)
{
	struct connman_mesh *mesh = data;

	connman_mesh_unregister(mesh);

	g_free(mesh->path);

	if (mesh->state == CONNMAN_MESH_STATE_CONFIGURATION ||
			mesh->state == CONNMAN_MESH_STATE_READY)
		__connman_dhcp_stop(mesh->ipconfig);

	if (mesh->ipconfig) {
		__connman_ipconfig_set_ops(mesh->ipconfig, NULL);
		__connman_ipconfig_set_data(mesh->ipconfig, NULL);
		__connman_ipconfig_unref(mesh->ipconfig);
		mesh->ipconfig = NULL;
	}
	g_free(mesh->identifier);
	g_free(mesh->name);
	g_free(mesh->passphrase);
	g_free(mesh->interface_addr);
	g_free(mesh->address);
	g_free(mesh);
}

static void mesh_connected_peer_free(gpointer data)
{
	struct connman_mesh_connected_peer *peer = data;

	g_free(peer->peer_address);
	g_free(peer);
}

static void mesh_disconnected_peer_free(gpointer data)
{
	struct connman_mesh_disconnected_peer *peer = data;

	g_free(peer->peer_address);
	g_free(peer);
}

static void __mesh_load_and_create_network(char *mesh_id)
{
	GKeyFile *keyfile;
	GString *str;
	struct connman_mesh *connman_mesh;
	gchar *name, *passphrase, *peer_type;
	char *identifier, *group, *address;
	const char *sec_type, *mesh_ifname;
	int freq, i;

	keyfile = connman_storage_load_service(mesh_id);
	if (!keyfile) {
		DBG("Mesh profile doesn't exist");
		return;
	}

	peer_type = g_key_file_get_string(keyfile, mesh_id, "PeerType", NULL);
	if (g_strcmp0(peer_type, "created")) {
		DBG("Mesh Profile was not created");
		goto done;
	}

	name = g_key_file_get_string(keyfile, mesh_id, "Name", NULL);
	if (!name) {
		DBG("Failed to get Mesh Profile Name");
		goto done;
	}

	passphrase = g_key_file_get_string(keyfile, mesh_id, "Passphrase", NULL);
	if (passphrase)
		sec_type = "sae";
	else
		sec_type = "none";

	freq = g_key_file_get_integer(keyfile, mesh_id, "Frequency", NULL);

	mesh_ifname = connman_mesh_get_interface_name();

	str = g_string_sized_new((strlen(name) * 2) + 24);

	for (i = 0; name[i]; i++)
		g_string_append_printf(str, "%02x", name[i]);

	g_string_append_printf(str, "_mesh");

	if (g_strcmp0(sec_type, "none") == 0)
		g_string_append_printf(str, "_none");
	else if (g_strcmp0(sec_type, "sae") == 0)
		g_string_append_printf(str, "_sae");

	group = g_string_free(str, FALSE);

	identifier = connman_inet_ifaddr(mesh_ifname);
	address = connman_inet_ifname2addr(mesh_ifname);

	connman_mesh = connman_mesh_create(identifier, group);
	connman_mesh_set_name(connman_mesh, name);
	connman_mesh_set_address(connman_mesh, address);
	connman_mesh_set_security(connman_mesh, sec_type);
	connman_mesh_set_frequency(connman_mesh, freq);
	connman_mesh_set_index(connman_mesh, connman_inet_ifindex(mesh_ifname));
	connman_mesh_set_peer_type(connman_mesh, CONNMAN_MESH_PEER_TYPE_CREATED);

	connman_mesh_register(connman_mesh);
	g_free(group);
	g_free(identifier);
	g_free(address);
done:
	g_key_file_free(keyfile);
}

static bool is_connected(struct connman_mesh *mesh)
{
	if (mesh->state == CONNMAN_MESH_STATE_READY)
		return true;

	return false;
}

static void mesh_peer_dhcp_refresh(gpointer key, gpointer value,
								   gpointer user_data)
{
	struct connman_mesh *mesh = value;

	DBG("mesh %p state %d", mesh, mesh->state);

	if (is_connected(mesh))
		__connman_mesh_dhcp_start(mesh->ipconfig, mesh_dhcp_callback, mesh);
}

int connman_inet_set_stp(int stp)
{
	int sk, err = 0;
	struct ifreq ifr;
	unsigned long args[4];

	if (!bridge_interface)
		return -EINVAL;

	sk = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sk < 0) {
		err = -errno;
		goto out;
	}

	args[0] = BRCTL_SET_BRIDGE_STP_STATE;
	args[1] = stp;
	args[2] = args[3] = 0;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, bridge_interface, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_data = (char *)args;

	if (ioctl(sk, SIOCDEVPRIVATE, &ifr) < 0)
		err = -errno;

	close(sk);

out:
	if (err < 0)
		DBG("Set STP Failed error %s", strerror(-err));

	return err;
}

int __connman_mesh_set_stp_gate_announce(bool gate_announce, int hwmp_rootmode,
						int stp)
{
	int err;

	if (!mesh_ifname)
		return -EINVAL;

	err = connman_inet_set_stp(stp);
	if (err < 0)
		return err;

	err = __connman_mesh_netlink_set_gate_announce(nl80211_global,
						connman_inet_ifindex(mesh_ifname), gate_announce,
						hwmp_rootmode);

	return err;
}

void __connman_mesh_add_ethernet_to_bridge(void)
{
	if (is_mesh_if_created) {
		DBG("");
		mesh_eth_driver->add_to_bridge(bridge_interface);
		eth_if_bridged = true;
		g_hash_table_foreach(mesh_table, mesh_peer_dhcp_refresh, NULL);
		connman_inet_set_stp(1);
		__connman_mesh_netlink_set_gate_announce(nl80211_global,
							connman_inet_ifindex(mesh_ifname), true,
							MESH_HWMP_ROOTMODE_RANN);
	}
}

void __connman_mesh_remove_ethernet_from_bridge(void)
{
	if (eth_if_bridged) {
		DBG("");
		mesh_eth_driver->remove_from_bridge(bridge_interface);
		eth_if_bridged = false;
		g_hash_table_foreach(mesh_table, mesh_peer_dhcp_refresh, NULL);
		connman_inet_set_stp(0);
		__connman_mesh_netlink_set_gate_announce(nl80211_global,
							connman_inet_ifindex(mesh_ifname), false,
							MESH_HWMP_ROOTMODE_NO_ROOT);
	}
}

int connman_mesh_notify_interface_create(bool success)
{
	int ret;
	int index;
	const char *error = NULL;
	DIR *dir;
	struct dirent *d;

	if (!success) {
		error = "Operation Failed";
		goto done;
	}

	if (!bridge_interface) {
		DBG("Don't create bridge interface");
		goto done;
	}

	DBG("Creating bridge [%s]", bridge_interface);

	/* Create bridge interface */
	ret = __connman_bridge_create(bridge_interface);
	if (0 != ret) {
		DBG("Failed to create bridge [%s] : [%s]", bridge_interface,
				strerror(-ret));
		error = "Bridge Creation";
		success = false;
		goto done;
	}

	/* Get Mesh Interface Index */
	index = connman_inet_ifindex(mesh_ifname);
	if (index < 0) {
		DBG("Failed to get interface index for %s", mesh_ifname);
		error = "Operation Failed";
		success = false;
		goto done;
	}

	/* Add mesh interface into bridge */
	ret = connman_inet_add_to_bridge(index, bridge_interface);
	if (0 != ret) {
		DBG("Failed to add interface[%s] into bridge[%s]", mesh_ifname,
					bridge_interface);
		error = "Add Mesh into bridge";
		success = false;
		goto done;
	}

	if (__connman_technology_get_connected(CONNMAN_SERVICE_TYPE_ETHERNET)) {
		mesh_eth_driver->add_to_bridge(bridge_interface);
		eth_if_bridged = true;
	}

	index = connman_inet_ifindex(bridge_interface);
	if (index < 0) {
		DBG("Failed to get interface index for %s", bridge_interface);
		error = "Operation Failed";
		success = false;
		goto done;
	}

	/* Make bridge interface UP */
	ret = connman_inet_ifup(index);
	if (0 != ret) {
		DBG("Failed to change bridge interface state");
		error = "Make bridge interface UP";
		success = false;
	}

done:
	if (success) {
		is_mesh_if_created = true;

		/* Load previously created mesh profiles */
		dir = opendir(STORAGEDIR);
		if (!dir) {
			DBG("Failed to open %s directory", STORAGEDIR);
			__connman_technology_mesh_interface_create_finished(
				CONNMAN_SERVICE_TYPE_MESH, success, error);
			return 0;
		}

		while ((d = readdir(dir))) {
			if (g_str_has_prefix(d->d_name, "mesh_")) {
				DBG("%s is a mesh profile", d->d_name);
				__mesh_load_and_create_network(d->d_name);
				__connman_mesh_auto_connect();
			}
		}

		closedir(dir);

	} else {
		if (eth_if_bridged)
			mesh_eth_driver->remove_from_bridge(bridge_interface);

		__connman_bridge_disable(bridge_interface);

		__connman_bridge_remove(bridge_interface);

		mesh_driver->remove_interface(mesh_ifname);
	}
	__connman_technology_mesh_interface_create_finished(
			    CONNMAN_SERVICE_TYPE_MESH, success, error);
	return 0;
}

int __connman_mesh_add_virtual_interface(const char *ifname,
						const char *parent_ifname, const char *bridge_ifname)
{
	int ret;

	if (!ifname || !parent_ifname)
		return -EINVAL;

	ret = mesh_driver->add_interface(ifname, parent_ifname);
	if (ret != -EINPROGRESS) {
		DBG("Failed to add virtual mesh interface");
		return ret;
	}

	mesh_ifname = g_strdup(ifname);
	bridge_interface = g_strdup(bridge_ifname);
	DBG("Success adding virtual mesh interface");
	return 0;
}

int connman_mesh_notify_interface_remove(bool success)
{
	struct connman_device *device;
	int index;
	if (success) {
		g_free(mesh_ifname);
		mesh_ifname = NULL;
		g_hash_table_remove_all(mesh_table);
		is_mesh_if_created = false;

		if (eth_if_bridged) {
			if (bridge_interface)
				mesh_eth_driver->remove_from_bridge(bridge_interface);

			device = __connman_device_find_device(
									CONNMAN_SERVICE_TYPE_ETHERNET);
			if (device) {
				index = connman_device_get_index(device);
				connman_inet_ifup(index);
			}
			eth_if_bridged = false;
		}

		if (bridge_interface) {
			__connman_bridge_disable(bridge_interface);
			if (__connman_bridge_remove(bridge_interface))
				DBG("Failed to remove bridge [%s]", bridge_interface);

			g_free(bridge_interface);
			bridge_interface = NULL;
		}
	}

	__connman_technology_mesh_interface_remove_finished(
						CONNMAN_SERVICE_TYPE_MESH, success);
	return 0;
}

int __connman_mesh_remove_virtual_interface(const char *ifname)
{
	int ret;
	int index;

	if (!ifname)
		return -EINVAL;

	if (bridge_interface) {
		index = connman_inet_ifindex(mesh_ifname);
		if (index < 0) {
			DBG("Failed to get interface index for %s", mesh_ifname);
			return -EINVAL;
		}

		ret = connman_inet_remove_from_bridge(index, bridge_interface);
		if (0 != ret) {
			DBG("Failed to remove interface[%s] freom bridge[%s]", mesh_ifname,
				bridge_interface);
			return -EINVAL;
		}

		if (eth_if_bridged)
			mesh_eth_driver->remove_from_bridge(bridge_interface);

		__connman_bridge_disable(bridge_interface);

		ret = __connman_bridge_remove(bridge_interface);
		if (0 != ret) {
			DBG("Failed to remove bridge [%s]", bridge_interface);
			return -EINVAL;
		}

		g_free(bridge_interface);
		bridge_interface = NULL;
	}

	ret = mesh_driver->remove_interface(ifname);
	if (ret != -EINPROGRESS) {
		DBG("Failed to remove virtual mesh interface");
		return ret;
	}

	DBG("Success removing virtual mesh interface");
	return 0;
}

const char *connman_mesh_get_interface_name(void)
{
	return mesh_ifname;
}

bool connman_mesh_is_interface_created(void)
{
	DBG("Mesh interface is %screated", is_mesh_if_created ? "" : "not ");
	return is_mesh_if_created;
}

struct connman_mesh *connman_mesh_create(const char *interface_addr,
					  const char *identifier)
{
	struct connman_mesh *mesh;

	mesh = g_malloc0(sizeof(struct connman_mesh));
	mesh->identifier = g_strdup_printf("mesh_%s_%s", interface_addr,
					   identifier);
	mesh->interface_addr = g_strdup(interface_addr);
	mesh->state = CONNMAN_MESH_STATE_IDLE;

	mesh->refcount = 1;

	return mesh;
}

void connman_mesh_set_name(struct connman_mesh *mesh, const char *name)
{
	g_free(mesh->name);
	mesh->name = g_strdup(name);
}

const char *connman_mesh_get_name(struct connman_mesh *mesh)
{
	return mesh->name;
}

void connman_mesh_set_passphrase(struct connman_mesh *mesh,
				  const char *passphrase)
{
	g_free(mesh->passphrase);
	mesh->passphrase = g_strdup(passphrase);
}

const char *connman_mesh_get_passphrase(struct connman_mesh *mesh)
{
	return mesh->passphrase;
}

void connman_mesh_set_address(struct connman_mesh *mesh, const char *address)
{
	g_free(mesh->address);
	mesh->address = g_strdup(address);
}

void connman_mesh_set_security(struct connman_mesh *mesh, const char *security)
{
	if (!g_strcmp0(security, "none"))
		mesh->security = CONNMAN_MESH_SECURITY_NONE;
	else if (!g_strcmp0(security, "sae"))
		mesh->security = CONNMAN_MESH_SECURITY_SAE;
	else
		mesh->security = CONNMAN_MESH_SECURITY_UNKNOWN;
}

static const char *security2string(enum connman_mesh_security security)
{
	switch (security) {
	case CONNMAN_MESH_SECURITY_UNKNOWN:
		break;
	case CONNMAN_MESH_SECURITY_NONE:
		return "none";
	case CONNMAN_MESH_SECURITY_SAE:
		return "sae";
	}

	return NULL;
}

const char *connman_mesh_get_security(struct connman_mesh *mesh)
{
	return security2string(mesh->security);
}

void connman_mesh_set_frequency(struct connman_mesh *mesh, uint16_t frequency)
{
	mesh->frequency = frequency;
}

uint16_t connman_mesh_get_frequency(struct connman_mesh *mesh)
{
	return mesh->frequency;
}

void connman_mesh_set_ieee80211w(struct connman_mesh *mesh, uint16_t ieee80211w)
{
	mesh->ieee80211w = ieee80211w;
}

uint16_t connman_mesh_get_ieee80211w(struct connman_mesh *mesh)
{
	return mesh->ieee80211w;
}

void connman_mesh_set_index(struct connman_mesh *mesh, int index)
{
	mesh->index = index;

	if (bridge_interface)
		mesh->br_index = connman_inet_ifindex(bridge_interface);
}

void connman_mesh_set_strength(struct connman_mesh *mesh, uint8_t strength)
{
	mesh->strength = strength;
}

static const char *peertype2string(enum connman_mesh_peer_type type)
{
	switch (type) {
	case CONNMAN_MESH_PEER_TYPE_CREATED:
		return "created";
	case CONNMAN_MESH_PEER_TYPE_DISCOVERED:
		return "discovered";
	}

	return NULL;
}

void connman_mesh_set_peer_type(struct connman_mesh *mesh,
								enum connman_mesh_peer_type type)
{
	mesh->peer_type = type;
}

static const char *state2string(enum connman_mesh_state state)
{
	switch (state) {
	case CONNMAN_MESH_STATE_UNKNOWN:
		break;
	case CONNMAN_MESH_STATE_IDLE:
		return "idle";
	case CONNMAN_MESH_STATE_ASSOCIATION:
		return "association";
	case CONNMAN_MESH_STATE_CONFIGURATION:
		return "configuration";
	case CONNMAN_MESH_STATE_READY:
		return "ready";
	case CONNMAN_MESH_STATE_DISCONNECT:
		return "disconnect";
	case CONNMAN_MESH_STATE_FAILURE:
		return "failure";
	}

	return NULL;
}

static enum connman_mesh_peer_disconnect_reason convert_to_disconnect_reason(
									int reason)
{
	switch (reason) {
	case 3:
		return CONNMAN_MESH_DEAUTH_LEAVING;
	case 52:
		return CONNMAN_MESH_PEERING_CANCELLED;
	case 53:
		return CONNMAN_MESH_MAX_PEERS;
	case 54:
		return CONNMAN_MESH_CONFIG_POLICY_VIOLATION;
	case 55:
		return CONNMAN_MESH_CLOSE_RCVD;
	case 56:
		return CONNMAN_MESH_MAX_RETRIES;
	case 57:
		return CONNMAN_MESH_CONFIRM_TIMEOUT;
	case 58:
		return CONNMAN_MESH_INVALID_GTK;
	case 59:
		return CONNMAN_MESH_INCONSISTENT_PARAMS;
	case 60:
		return CONNMAN_MESH_INVALID_SECURITY_CAP;
	}

	return CONNMAN_MESH_REASON_UNKNOWN;
}

void connman_mesh_peer_set_disconnect_reason(struct connman_mesh *mesh,
						int disconnect_reason)
{
	mesh->disconnect_reason = convert_to_disconnect_reason(disconnect_reason);
}

static bool is_connecting(struct connman_mesh *mesh)
{
	if (mesh->state == CONNMAN_MESH_STATE_ASSOCIATION ||
			mesh->state == CONNMAN_MESH_STATE_CONFIGURATION)
		return true;

	return false;
}

static int mesh_load(struct connman_mesh *mesh)
{
	GKeyFile *keyfile;
	bool favorite;
	GError *error = NULL;
	gchar *str;

	keyfile = connman_storage_load_service(mesh->identifier);
	if (!keyfile) {
		DBG("Mesh profile is new");
		return -EIO;
	}

	favorite = g_key_file_get_boolean(keyfile,
				mesh->identifier, "Favorite", &error);

	if (!error)
		mesh->favorite = favorite;

	g_clear_error(&error);

	str = g_key_file_get_string(keyfile, mesh->identifier, "Passphrase", NULL);

	if (str) {
		g_free(mesh->passphrase);
		mesh->passphrase = str;
	}

	return 0;
}

static int mesh_save(struct connman_mesh *mesh)
{
	GKeyFile *keyfile;

	keyfile = __connman_storage_open_service(mesh->identifier);
	if (!keyfile)
		return -EIO;

	g_key_file_set_string(keyfile, mesh->identifier, "Name", mesh->name);
	g_key_file_set_integer(keyfile, mesh->identifier, "Frequency",
								mesh->frequency);
	g_key_file_set_boolean(keyfile, mesh->identifier, "Favorite",
								mesh->favorite);

	if (mesh->passphrase)
		g_key_file_set_string(keyfile, mesh->identifier, "Passphrase",
							  mesh->passphrase);

	g_key_file_set_string(keyfile, mesh->identifier, "PeerType",
								peertype2string(mesh->peer_type));

	__connman_storage_save_service(keyfile, mesh->identifier);

	g_key_file_free(keyfile);

	return 0;
}

static void reply_pending(struct connman_mesh *mesh, int error)
{
	if (!mesh->pending)
		return;

	connman_dbus_reply_pending(mesh->pending, error, NULL);
	mesh->pending = NULL;
}

static void state_changed(struct connman_mesh *mesh)
{
	const char *state;

	state = state2string(mesh->state);
	if (!state)
		return;

	connman_dbus_property_changed_basic(mesh->path,
					 CONNMAN_MESH_INTERFACE, "State",
					 DBUS_TYPE_STRING, &state);
}

static void mesh_dhcp_callback(struct connman_ipconfig *ipconfig,
				struct connman_network *network, bool success, gpointer data)
{
	struct connman_mesh *mesh = data;
	int err;

	if (!success)
		goto error;

	err = __connman_ipconfig_address_add(ipconfig);
	if (err < 0)
		goto error;

	return;

error:
	connman_mesh_peer_set_state(mesh, CONNMAN_MESH_STATE_FAILURE);
}

static int mesh_start_dhcp_client(struct connman_mesh *mesh)
{
	DBG("");

	__connman_ipconfig_enable(mesh->ipconfig);

	return __connman_mesh_dhcp_start(mesh->ipconfig, mesh_dhcp_callback, mesh);
}

static void mesh_remove_connected_peer(gpointer key, gpointer value,
						gpointer user_data)
{
	struct connman_mesh_connected_peer *peer = value;

	DBG("Remove Peer %s", peer->peer_address);
	g_hash_table_remove(connected_peer_table, key);
}

static void mesh_remove_disconnected_peer(gpointer key, gpointer value,
						gpointer user_data)
{
	struct connman_mesh_disconnected_peer *peer = value;

	DBG("Remove Peer %s", peer->peer_address);
	g_hash_table_remove(disconnected_peer_table, key);
}

int connman_mesh_peer_set_state(struct connman_mesh *mesh,
						enum connman_mesh_state new_state)
{
	enum connman_mesh_state old_state = mesh->state;

	DBG("mesh peer %s old state %s new state %s", mesh->name,
					state2string(old_state), state2string(new_state));

	if (old_state == new_state)
		return -EALREADY;

	switch (new_state) {
	case CONNMAN_MESH_STATE_UNKNOWN:
		return -EINVAL;
	case CONNMAN_MESH_STATE_IDLE:
	case CONNMAN_MESH_STATE_ASSOCIATION:
		break;
	case CONNMAN_MESH_STATE_CONFIGURATION:
		/* Start Link Local IP Address */
		mesh_start_dhcp_client(mesh);
		break;
	case CONNMAN_MESH_STATE_READY:
		reply_pending(mesh, 0);
		mesh->favorite = true;
		__connman_notifier_connect(CONNMAN_SERVICE_TYPE_MESH);

		/* Set Gate Announce option */
		if (eth_if_bridged) {
			connman_inet_set_stp(1);
			__connman_mesh_netlink_set_gate_announce(nl80211_global,
								connman_inet_ifindex(mesh_ifname), true,
								MESH_HWMP_ROOTMODE_RANN);
		}

		mesh_save(mesh);
		break;
	case CONNMAN_MESH_STATE_DISCONNECT:
		__connman_dhcp_stop(mesh->ipconfig);
		g_hash_table_foreach(connected_peer_table, mesh_remove_connected_peer,
							 NULL);
		g_hash_table_foreach(disconnected_peer_table,
							 mesh_remove_disconnected_peer, NULL);
		__connman_notifier_disconnect(CONNMAN_SERVICE_TYPE_MESH);
		break;
	case CONNMAN_MESH_STATE_FAILURE:
		reply_pending(mesh, ECONNABORTED);
		break;
	}

	mesh->state = new_state;
	state_changed(mesh);

	return 0;
}

bool connman_mesh_peer_is_connected_state(struct connman_mesh *mesh)
{
	switch (mesh->state) {
	case CONNMAN_MESH_STATE_UNKNOWN:
	case CONNMAN_MESH_STATE_IDLE:
	case CONNMAN_MESH_STATE_ASSOCIATION:
	case CONNMAN_MESH_STATE_CONFIGURATION:
	case CONNMAN_MESH_STATE_DISCONNECT:
	case CONNMAN_MESH_STATE_FAILURE:
		break;
	case CONNMAN_MESH_STATE_READY:
		return true;
	}

	return false;
}

struct connman_mesh *connman_get_connected_mesh_from_name(char *name)
{
	GList *list, *start;

	list = g_hash_table_get_values(mesh_table);
	start = list;
	for (; list; list = list->next) {
		struct connman_mesh *mesh = list->data;

		if (!g_strcmp0(mesh->name, name) &&
					mesh->state == CONNMAN_MESH_STATE_READY) {
			g_list_free(start);
			return mesh;
		}
	}

	g_list_free(start);

	return NULL;
}

struct connman_mesh *connman_get_connecting_mesh_from_name(char *name)
{
	GList *list, *start;

	list = g_hash_table_get_values(mesh_table);
	start = list;
	for (; list; list = list->next) {
		struct connman_mesh *mesh = list->data;

		if (!g_strcmp0(mesh->name, name) && is_connecting(mesh)) {
			g_list_free(start);
			return mesh;
		}
	}

	g_list_free(start);

	return NULL;
}

static void mesh_append_ethernet(DBusMessageIter *iter, void *user_data)
{
	struct connman_mesh *mesh = user_data;

	if (mesh->ipconfig)
		__connman_ipconfig_append_ethernet(mesh->ipconfig, iter);
}

static void mesh_append_ipv4(DBusMessageIter *iter, void *user_data)
{
	struct connman_mesh *mesh = user_data;

	if (!is_connected(mesh))
		return;

	if (mesh->ipconfig)
		__connman_ipconfig_append_ipv4(mesh->ipconfig, iter);
}

static void mesh_append_ipv4config(DBusMessageIter *iter, void *user_data)
{
	struct connman_mesh *mesh = user_data;

	if (mesh->ipconfig)
		__connman_ipconfig_append_ipv4config(mesh->ipconfig, iter);
}

static void append_properties(DBusMessageIter *iter, struct connman_mesh *mesh)
{
	const char *state = state2string(mesh->state);
	const char *security = security2string(mesh->security);
	const char *peer_type = peertype2string(mesh->peer_type);
	const char *type = "mesh";
	DBusMessageIter dict;

	connman_dbus_dict_open(iter, &dict);

	connman_dbus_dict_append_basic(&dict, "Type", DBUS_TYPE_STRING, &type);
	connman_dbus_dict_append_basic(&dict, "Name",
					DBUS_TYPE_STRING, &mesh->name);
	connman_dbus_dict_append_basic(&dict, "BSSID",
					DBUS_TYPE_STRING, &mesh->address);
	connman_dbus_dict_append_basic(&dict, "State", DBUS_TYPE_STRING, &state);
	if (security)
		connman_dbus_dict_append_basic(&dict, "Security",
								DBUS_TYPE_STRING, &security);
	connman_dbus_dict_append_basic(&dict, "Frequency",
					DBUS_TYPE_UINT16, &mesh->frequency);
	connman_dbus_dict_append_basic(&dict, "Favorite",
					DBUS_TYPE_BOOLEAN, &mesh->favorite);
	connman_dbus_dict_append_basic(&dict, "Strength",
					DBUS_TYPE_BYTE, &mesh->strength);
	connman_dbus_dict_append_basic(&dict, "PeerType",
					DBUS_TYPE_STRING, &peer_type);
	connman_dbus_dict_append_basic(&dict, "DisconnectReason",
					DBUS_TYPE_INT32, &mesh->disconnect_reason);

	connman_dbus_dict_append_dict(&dict, "Ethernet", mesh_append_ethernet,
					mesh);

	connman_dbus_dict_append_dict(&dict, "IPv4", mesh_append_ipv4, mesh);

	connman_dbus_dict_append_dict(&dict, "IPv4.Configuration",
					mesh_append_ipv4config, mesh);

	connman_dbus_dict_close(iter, &dict);
}

static void append_mesh_peer_struct(gpointer key, gpointer value,
						gpointer user_data)
{
	DBusMessageIter *array = user_data;
	struct connman_mesh *mesh = value;
	DBusMessageIter entry;

	DBG("Mesh Peer path %s", mesh->path);
	dbus_message_iter_open_container(array, DBUS_TYPE_STRUCT,
							NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
							&mesh->path);
	append_properties(&entry, mesh);
	dbus_message_iter_close_container(array, &entry);
}

void __connman_mesh_peer_list_struct(DBusMessageIter *array)
{
	g_hash_table_foreach(mesh_table, append_mesh_peer_struct, array);
}

static DBusMessage *get_mesh_peer_properties(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct connman_mesh *mesh = data;
	DBusMessageIter dict;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &dict);
	append_properties(&dict, mesh);

	return reply;
}

static void append_mesh_disconnected_peer_struct(gpointer key, gpointer value,
						gpointer user_data)
{
	DBusMessageIter *array = user_data;
	struct connman_mesh_disconnected_peer *peer = value;
	DBusMessageIter entry;
	DBusMessageIter dict;

	dbus_message_iter_open_container(array, DBUS_TYPE_STRUCT,
							NULL, &entry);

	connman_dbus_dict_open(&entry, &dict);

	connman_dbus_dict_append_basic(&dict, "PeerAddress",
					DBUS_TYPE_STRING, &peer->peer_address);

	connman_dbus_dict_append_basic(&dict, "DisconnectReason",
					DBUS_TYPE_INT32, &peer->disconnect_reason);

	connman_dbus_dict_close(&entry, &dict);
	dbus_message_iter_close_container(array, &entry);
}

void __connman_mesh_disconnected_peer_list_struct(DBusMessageIter *array)
{
	g_hash_table_foreach(disconnected_peer_table,
						append_mesh_disconnected_peer_struct, array);
}

static void append_mesh_connected_peer_struct(gpointer key, gpointer value,
						gpointer user_data)
{
	DBusMessageIter *array = user_data;
	struct connman_mesh_connected_peer *peer = value;
	DBusMessageIter entry;
	DBusMessageIter dict;

	dbus_message_iter_open_container(array, DBUS_TYPE_STRUCT,
							NULL, &entry);

	connman_dbus_dict_open(&entry, &dict);

	connman_dbus_dict_append_basic(&dict, "PeerAddress",
					DBUS_TYPE_STRING, &peer->peer_address);

	connman_dbus_dict_close(&entry, &dict);
	dbus_message_iter_close_container(array, &entry);
}

void __connman_mesh_connected_peer_list_struct(DBusMessageIter *array)
{
	g_hash_table_foreach(connected_peer_table,
						append_mesh_connected_peer_struct, array);
}

int connman_mesh_add_connected_peer(const char *peer_address)
{
	struct connman_mesh_connected_peer *peer;
	struct connman_mesh_connected_peer *temp_peer;
	struct connman_mesh_disconnected_peer *disconn_peer;

	temp_peer = g_hash_table_lookup(connected_peer_table, peer_address);

	if (temp_peer) {
		DBG("Mesh Peer %s is already connected", peer_address);
		return 0;
	}

	peer = g_malloc0(sizeof(struct connman_mesh_connected_peer));
	peer->peer_address = g_strdup(peer_address);
	DBG("Peer %s", peer->peer_address);

	g_hash_table_insert(connected_peer_table, peer->peer_address, peer);

	/* Remove from disconnected Peer Table */
	disconn_peer = g_hash_table_lookup(disconnected_peer_table, peer_address);
	if (!disconn_peer) {
		DBG("Peer %s was never disconnected", peer_address);
		goto done;
	}

	g_hash_table_remove(disconnected_peer_table, peer_address);
done:
	return 0;
}

int connman_mesh_remove_connected_peer(const char *peer_address, int reason)
{
	struct connman_mesh_connected_peer *peer;
	struct connman_mesh_disconnected_peer *disconn_peer;

	peer = g_hash_table_lookup(connected_peer_table, peer_address);

	if (!peer) {
		DBG("Peer %s not connected", peer_address);
		return 0;
	}

	g_hash_table_remove(connected_peer_table, peer_address);

	/* Add to Disconnected Peer Table */
	disconn_peer = g_malloc0(sizeof(struct connman_mesh_disconnected_peer));
	disconn_peer->peer_address = g_strdup(peer_address);
	disconn_peer->disconnect_reason = convert_to_disconnect_reason(reason);

	g_hash_table_insert(disconnected_peer_table, disconn_peer->peer_address,
						disconn_peer);

	DBG("Mesh Peer %s removed due to reason %d", peer_address, reason);
	return 0;
}

static void __mesh_change_peer_status_cb(int result, void *user_data)
{
	struct connman_mesh_change_peer_data *data = user_data;

	DBG("Status %d Peer Address %s result %d", data->status, data->peer_address,
										result);

	connman_dbus_reply_pending(data->pending, -result, NULL);

	data->pending = NULL;
	g_free(data->peer_address);
	g_free(data);
}

int __connman_mesh_change_peer_status(DBusMessage *msg,
									  const char *peer_address,
									  enum connman_mesh_peer_status status)
{
	struct connman_mesh_connected_peer *conn_peer;
	struct connman_mesh_disconnected_peer *disconn_peer;
	int err = -ENOTSUP;
	struct connman_mesh_change_peer_data *data;

	switch (status) {
	case CONNMAN_MESH_PEER_ADD:
		conn_peer = g_hash_table_lookup(connected_peer_table, peer_address);

		if (conn_peer) {
			DBG("Peer %s already connected", peer_address);
			return -EEXIST;
		}

		break;

	case CONNMAN_MESH_PEER_REMOVE:
		disconn_peer = g_hash_table_lookup(disconnected_peer_table,
									peer_address);

		if (disconn_peer) {
			DBG("Peer %s already disconnected", peer_address);
			return -EEXIST;
		}

		break;

	default:
		DBG("Invalid Status type");
		return err;
	}

	if (mesh_driver->change_peer_status) {
		data = g_try_malloc0(sizeof(struct connman_mesh_disconnected_peer));
		if (data == NULL) {
			DBG("Memory allocation failed");
			return -ENOMEM;
		}

		data->pending = dbus_message_ref(msg);
		data->peer_address = g_strdup(peer_address);
		data->status = status;

		err = mesh_driver->change_peer_status(peer_address, status,
								__mesh_change_peer_status_cb, data);

		if (err < 0) {
			dbus_message_unref(data->pending);
			g_free(data->peer_address);
			g_free(data);
		}
	}

	return err;
}

static int mesh_peer_connect(struct connman_mesh *mesh)
{
	int err = -ENOTSUP;
	if (mesh_driver->connect)
		err = mesh_driver->connect(mesh);

	/* Reset Disconnect Reason */
	mesh->disconnect_reason = CONNMAN_MESH_REASON_UNKNOWN;
	return err;
}

static DBusMessage *connect_mesh_peer(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_mesh *mesh = user_data;
	int err;

	DBG("mesh %p", mesh);

	if (mesh->state == CONNMAN_MESH_STATE_READY) {
		DBG("mesh %s already connected", mesh->name);
		return __connman_error_already_exists(msg);
	}

	if (mesh->pending)
		return __connman_error_in_progress(msg);

	mesh->pending = dbus_message_ref(msg);

	err = mesh_peer_connect(mesh);
	if (err == -EINPROGRESS)
		return NULL;

	if (err < 0) {
		dbus_message_unref(mesh->pending);
		mesh->pending = NULL;
		return __connman_error_failed(msg, -err);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void auto_connect_mesh_peer(gpointer key, gpointer value,
						gpointer user_data)
{
	bool *conn_started = user_data;
	struct connman_mesh *mesh = value;
	int err;

	if (*conn_started)
		return;

	if (!mesh->favorite || mesh->state != CONNMAN_MESH_STATE_IDLE)
		return;

	err = mesh_peer_connect(mesh);
	if (err == -EINPROGRESS)
		*conn_started = 1;
}

static gboolean run_mesh_auto_connect(gpointer data)
{
	bool conn_started;

	mesh_autoconnect_timeout = 0;
	DBG("");

	conn_started = false;
	g_hash_table_foreach(mesh_table, auto_connect_mesh_peer, &conn_started);
	return FALSE;
}

void __connman_mesh_auto_connect(void)
{
	DBG("");

	if (mesh_autoconnect_timeout != 0)
		return;

	mesh_autoconnect_timeout = g_idle_add(run_mesh_auto_connect, NULL);
}

static void mesh_peer_up(struct connman_ipconfig *ipconfig, const char *ifname)
{
	DBG("%s up", ifname);
}

static void mesh_peer_down(struct connman_ipconfig *ipconfig,
						const char *ifname)
{
	DBG("%s down", ifname);
}

static void mesh_peer_lower_up(struct connman_ipconfig *ipconfig,
							const char *ifname)
{
	DBG("%s lower up", ifname);
}

static void mesh_peer_lower_down(struct connman_ipconfig *ipconfig,
							const char *ifname)
{
	DBG("%s lower down", ifname);
}

static void mesh_peer_ip_bound(struct connman_ipconfig *ipconfig,
							const char *ifname)
{
	struct connman_mesh *mesh = __connman_ipconfig_get_data(ipconfig);

	DBG("%s ip bound", ifname);

	connman_mesh_peer_set_state(mesh, CONNMAN_MESH_STATE_READY);
}

static void mesh_peer_ip_release(struct connman_ipconfig *ipconfig,
							const char *ifname)
{
	DBG("%s ip release", ifname);
}

static const struct connman_ipconfig_ops mesh_peer_ip_ops = {
	.up			= mesh_peer_up,
	.down		= mesh_peer_down,
	.lower_up	= mesh_peer_lower_up,
	.lower_down	= mesh_peer_lower_down,
	.ip_bound	= mesh_peer_ip_bound,
	.ip_release	= mesh_peer_ip_release,
	.route_set	= NULL,
	.route_unset	= NULL,
};

static struct connman_ipconfig *create_ipconfig(int index, void *user_data)
{
	struct connman_ipconfig *ipconfig;

	ipconfig = __connman_ipconfig_create(index,
						CONNMAN_IPCONFIG_TYPE_IPV4);
	if (!ipconfig)
		return NULL;

	__connman_ipconfig_set_method(ipconfig, CONNMAN_IPCONFIG_METHOD_DHCP);
	__connman_ipconfig_set_data(ipconfig, user_data);
	__connman_ipconfig_set_ops(ipconfig, &mesh_peer_ip_ops);

	return ipconfig;
}

static int __connman_mesh_peer_disconnect(struct connman_mesh *mesh)
{
	int err;

	reply_pending(mesh, ECONNABORTED);

	if (!is_connected(mesh) && !is_connecting(mesh))
		return -ENOTCONN;

	err = mesh_driver->disconnect(mesh);
	if (err < 0 && err != -EINPROGRESS)
		return err;

	return err;
}

static DBusMessage *disconnect_mesh_peer(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_mesh *mesh = user_data;
	int err;

	DBG("mesh %p", mesh);
	err = __connman_mesh_peer_disconnect(mesh);
	if (err < 0 && err != -EINPROGRESS)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static bool __connman_mesh_peer_remove(struct connman_mesh *mesh)
{
	if (!mesh->favorite)
		return false;

	__connman_mesh_peer_disconnect(mesh);

	mesh->favorite = false;

	__connman_storage_remove_service(mesh->identifier);

	return true;
}

static DBusMessage *remove_mesh_peer(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_mesh *mesh = user_data;

	DBG("mesh %p", mesh);

	if (!__connman_mesh_peer_remove(mesh))
		return __connman_error_not_supported(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *set_mesh_peer_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_mesh *mesh = user_data;
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("mesh %p", mesh);

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

	if (g_str_equal(name, "Passphrase")) {
		char *passphrase;

		if (type != DBUS_TYPE_STRING)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &passphrase);

		connman_mesh_set_passphrase(mesh, passphrase);
	} else {
		DBG("Invalid Property %s", name);
		return __connman_error_invalid_property(msg);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable mesh_methods[] = {
	{ GDBUS_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_mesh_peer_properties) },
	{ GDBUS_ASYNC_METHOD("Connect", NULL, NULL, connect_mesh_peer) },
	{ GDBUS_METHOD("Disconnect", NULL, NULL, disconnect_mesh_peer) },
	{ GDBUS_METHOD("Remove", NULL, NULL, remove_mesh_peer) },
	{ GDBUS_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_mesh_peer_property) },
	{ },
};

static const GDBusSignalTable mesh_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ },
};

int connman_mesh_register(struct connman_mesh *mesh)
{
	struct connman_mesh *temp;
	DBG("mesh %p", mesh);

	if (mesh->path)
		return -EALREADY;

	mesh->path = g_strdup_printf("%s/mesh/%s", CONNMAN_PATH,
				     mesh->identifier);
	DBG("path %s", mesh->path);

	temp = g_hash_table_lookup(mesh_table, mesh->path);
	if (temp) {
		DBG("mesh path %s already exists", mesh->path);

		if (mesh->frequency != temp->frequency) {
			DBG("Update frequency for mesh network %s", mesh->name);
			connman_mesh_set_frequency(temp, mesh->frequency);
		}

		mesh_free(mesh);
		return -EALREADY;
	}

	if (mesh->br_index > 0)
		mesh->ipconfig = create_ipconfig(mesh->br_index, mesh);
	else
		mesh->ipconfig = create_ipconfig(mesh->index, mesh);

	if (!mesh->ipconfig)
		return -ENOMEM;

	g_hash_table_insert(mesh_table, mesh->path, mesh);

	mesh_load(mesh);

	g_dbus_register_interface(connection, mesh->path,
					CONNMAN_MESH_INTERFACE,
					mesh_methods, mesh_signals,
					NULL, mesh, NULL);
	mesh->registered = true;
	return 0;
}

void connman_mesh_unregister(struct connman_mesh *mesh)
{
	DBG("mesh %p", mesh);

	if (!mesh->path || !mesh->registered)
		return;

	g_dbus_unregister_interface(connection, mesh->path,
								CONNMAN_MESH_INTERFACE);
	mesh->registered = false;

	g_hash_table_remove(mesh_table, mesh->path);
}

struct connman_mesh *connman_mesh_get(const char *interface_addr,
									const char *identifier)
{
	char *ident = g_strdup_printf("%s/mesh/mesh_%s_%s", CONNMAN_PATH,
									interface_addr, identifier);
	struct connman_mesh *mesh;

	mesh = g_hash_table_lookup(mesh_table, ident);
	g_free(ident);

	return mesh;
}

int connman_mesh_driver_register(struct connman_mesh_driver *driver)
{
	if (mesh_driver && mesh_driver != driver)
		return -EINVAL;

	mesh_driver = driver;

	return 0;
}

void connman_mesh_driver_unregister(struct connman_mesh_driver *driver)
{
	if (mesh_driver != driver)
		return;

	mesh_driver = NULL;
}

int connman_mesh_eth_driver_register(struct connman_mesh_eth_driver *driver)
{
	if (mesh_eth_driver && mesh_eth_driver != driver)
		return -EINVAL;

	mesh_eth_driver = driver;

	return 0;
}

void connman_mesh_eth_driver_unregister(struct connman_mesh_eth_driver *driver)
{
	if (mesh_eth_driver != driver)
		return;

	mesh_eth_driver = NULL;
}

int __connman_mesh_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	mesh_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, mesh_free);

	connected_peer_table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
							mesh_connected_peer_free);

	disconnected_peer_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, mesh_disconnected_peer_free);

	nl80211_global = __connman_mesh_nl80211_global_init();
	return 0;
}

void __connman_mesh_cleanup(void)
{
	DBG("");

	__connman_mesh_nl80211_global_deinit(nl80211_global);
	g_hash_table_destroy(mesh_table);
	g_hash_table_destroy(connected_peer_table);
	g_hash_table_destroy(disconnected_peer_table);
	dbus_connection_unref(connection);
}
