/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2009  Intel Corporation. All rights reserved.
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

#include <gdbus.h>
#include <string.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/network.h>
#include <connman/dbus.h>
#include <connman/inet.h>
#include <connman/log.h>

#define OFONO_SERVICE			"org.ofono"

#define OFONO_MANAGER_INTERFACE		OFONO_SERVICE ".Manager"
#define OFONO_MODEM_INTERFACE		OFONO_SERVICE ".Modem"
#define OFONO_GPRS_INTERFACE		OFONO_SERVICE ".DataConnectionManager"
#define OFONO_SIM_INTERFACE		OFONO_SERVICE ".SimManager"
#define OFONO_PRI_CONTEXT_INTERFACE	OFONO_SERVICE ".PrimaryDataContext"

#define PROPERTY_CHANGED		"PropertyChanged"
#define GET_PROPERTIES			"GetProperties"
#define SET_PROPERTY			"SetProperty"

#define TIMEOUT 5000

static DBusConnection *connection;

static GHashTable *modem_hash = NULL;

struct modem_data {
	char *path;
	struct connman_device *device;
	gboolean available;
};

static int modem_probe(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static void modem_remove(struct connman_device *device)
{
	DBG("device %p", device);
}

static void powered_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;

	DBG("");

	dbus_error_init(&error);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("%s", error.message);
		dbus_error_free(&error);
	}

	dbus_message_unref(reply);
}

static int gprs_change_powered(const char *path, dbus_bool_t powered)
{
	DBusMessage *message;
	DBusMessageIter iter;
	DBusPendingCall *call;

	DBG("path %s powered %d", path, powered);

	if (path == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(OFONO_SERVICE, path,
					OFONO_GPRS_INTERFACE, SET_PROPERTY);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	dbus_message_iter_init_append(message, &iter);
	connman_dbus_property_append_variant(&iter, "Powered",
						DBUS_TYPE_BOOLEAN, &powered);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to change powered property");
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, powered_reply, (void *)path, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static int modem_enable(struct connman_device *device)
{
	const char *path = connman_device_get_string(device, "Path");

	DBG("device %p, path, %s", device, path);

	return gprs_change_powered(path, TRUE);
}

static int modem_disable(struct connman_device *device)
{
	const char *path = connman_device_get_string(device, "Path");

	DBG("device %p, path %s", device, path);

	return gprs_change_powered(path, FALSE);
}

static struct connman_device_driver modem_driver = {
	.name		= "modem",
	.type		= CONNMAN_DEVICE_TYPE_CELLULAR,
	.probe		= modem_probe,
	.remove		= modem_remove,
	.enable		= modem_enable,
	.disable	= modem_disable,
};

static char *get_ident(const char *path)
{
	char *ident, *pos;

	if (*path != '/')
		return NULL;

	ident = g_strdup(path + 1);

	pos = ident;

	while ((pos = strchr(pos, '/')) != NULL)
		*pos = '_';

	return ident;
}

static void config_network_reply(DBusPendingCall *call, void *user_data)
{
	struct connman_network *network = user_data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	gboolean internet_type = FALSE;

	DBG("network %p", network);

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		goto done;

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Name") == TRUE) {
			const char *name;

			dbus_message_iter_get_basic(&value, &name);
			connman_network_set_name(network, name);
		} else if (g_str_equal(key, "Type") == TRUE) {
			const char *type;

			dbus_message_iter_get_basic(&value, &type);
			if (g_strcmp0(type, "internet") == 0) {
				internet_type = TRUE;

				connman_network_set_protocol(network,
						CONNMAN_NETWORK_PROTOCOL_IP);
			} else {
				internet_type = FALSE;

				connman_network_set_protocol(network,
					CONNMAN_NETWORK_PROTOCOL_UNKNOWN);
			}
		}

		dbus_message_iter_next(&dict);
	}

	if (internet_type == TRUE) {
		const char *path;
		char *group;

		path = connman_network_get_string(network, "Path");

		group = get_ident(path);

		connman_network_set_group(network, group);

		g_free(group);
	}

done:
	dbus_message_unref(reply);
}

static void config_network(struct connman_network *network, const char *path)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("path %s", path);

	message = dbus_message_new_method_call(OFONO_SERVICE, path,
				OFONO_PRI_CONTEXT_INTERFACE, GET_PROPERTIES);
	if (message == NULL)
		return;

	dbus_message_set_auto_start(message, FALSE);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get Primary Context");
		goto done;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		goto done;
	}

	dbus_pending_call_set_notify(call, config_network_reply,
						(void *)network, NULL);

done:
	dbus_message_unref(message);
}

static int network_probe(struct connman_network *network)
{
	const char *path;

	path = connman_network_get_string(network, "Path");

	DBG("network %p path %s", network, path);

	config_network(network, path);

	return 0;
}

static struct connman_network *pending_network;

static gboolean pending_network_is_available(
		struct connman_network *pending_network)
{
	struct connman_device *device;
	struct connman_network *network;
	const char *identifier;
	char *ident;

	/* Modem may be removed during waiting for active reply */
	device  = connman_network_get_device(pending_network);
	if (device == NULL)
		return FALSE;

	identifier = connman_network_get_identifier(pending_network);

	ident = g_strdup(identifier);

	connman_network_unref(pending_network);

	/* network may be removed during waiting for active reply */
	network = connman_device_get_network(device, ident);

	g_free(ident);

	if (network == NULL)
		return FALSE;

	return TRUE;
}

static void set_active_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	struct connman_network *network = user_data;

	DBG("network %p", network);

	if (pending_network_is_available(network) == FALSE)
		return;

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		return;

	dbus_error_init(&error);
	if (dbus_set_error_from_message(&error, reply)) {
		if (connman_network_get_index(network) < 0)
			connman_network_set_error(network,
				CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL);

		pending_network = NULL;

		connman_error("%s", error.message);

		dbus_error_free(&error);
	} else
		pending_network = network;

	dbus_message_unref(reply);
}

static int set_network_active(struct connman_network *network,
						dbus_bool_t active)
{
	DBusMessage *message;
	DBusPendingCall *call;
	DBusMessageIter iter;

	const char *path = connman_network_get_string(network, "Path");

	DBG("network %p, path %s, active %d", network, path, active);

	if (path == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(OFONO_SERVICE, path,
				OFONO_PRI_CONTEXT_INTERFACE, SET_PROPERTY);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	dbus_message_iter_init_append(message, &iter);
	connman_dbus_property_append_variant(&iter, "Active",
						DBUS_TYPE_BOOLEAN, &active);

	if (dbus_connection_send_with_reply(connection, message,
					&call, TIMEOUT * 10) == FALSE) {
		connman_error("Failed to connect service");
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	connman_network_ref(network);

	dbus_pending_call_set_notify(call, set_active_reply, network, NULL);

	dbus_message_unref(message);

	if (active == TRUE)
		return -EINPROGRESS;

	return 0;
}

static int network_connect(struct connman_network *network)
{
	if (connman_network_get_index(network) >= 0)
		return -EISCONN;

	return set_network_active(network, TRUE);
}

static int network_disconnect(struct connman_network *network)
{
	if (connman_network_get_index(network) < 0)
		return -ENOTCONN;

	return set_network_active(network, FALSE);
}

static void network_remove(struct connman_network *network)
{
	DBG("network %p", network);
}

static struct connman_network_driver network_driver = {
	.name		= "network",
	.type		= CONNMAN_NETWORK_TYPE_CELLULAR,
	.probe		= network_probe,
	.remove		= network_remove,
	.connect	= network_connect,
	.disconnect	= network_disconnect,
};

static void add_network(struct connman_device *device, const char *path)
{
	struct connman_network *network;
	char *ident;

	DBG("device %p path %s", device, path);

	network = connman_device_get_network(device, path);
	if (network != NULL)
		return;

	ident = get_ident(path);

	network = connman_network_create(ident,
					CONNMAN_NETWORK_TYPE_CELLULAR);
	if (network == NULL)
		return;

	g_free(ident);

	connman_network_set_string(network, "Path", path);
	connman_network_set_available(network, TRUE);
	connman_network_set_index(network, -1);
	connman_device_add_network(device, network);
}

static void add_networks(struct connman_device *device, DBusMessageIter *array)
{
	DBusMessageIter entry;

	DBG("");

	dbus_message_iter_recurse(array, &entry);

	while (dbus_message_iter_get_arg_type(&entry) ==
					DBUS_TYPE_OBJECT_PATH) {
		const char *path;

		dbus_message_iter_get_basic(&entry, &path);

		add_network(device, path);

		dbus_message_iter_next(&entry);
	}
}

static void check_networks_reply(DBusPendingCall *call, void *user_data)
{
	struct connman_device *device = user_data;
	DBusMessage *reply;
	DBusMessageIter array, dict, contexts;
	dbus_bool_t attached;

	DBG("device %p", device);

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		goto done;

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		DBG("key %s", key);

		if (g_str_equal(key, "Attached") == TRUE) {
			dbus_message_iter_get_basic(&value, &attached);
			DBG("Attached %d", attached);
		} else if (g_str_equal(key, "PrimaryContexts") == TRUE) {
			contexts = value;
		} else if (g_str_equal(key, "Status") == TRUE) {
			const char *status;

			dbus_message_iter_get_basic(&value, &status);
			/* FIXME: add roaming support */
		} else if (g_str_equal(key, "Powered") == TRUE) {
			dbus_bool_t powered;

			dbus_message_iter_get_basic(&value, &powered);

			connman_device_set_powered(device, powered);
		}

		dbus_message_iter_next(&dict);
	}

	if (attached == TRUE)
		add_networks(device, &contexts);

done:
	dbus_message_unref(reply);
}

static void check_networks(struct modem_data *modem)
{
	DBusMessage *message;
	DBusPendingCall *call;
	struct connman_device *device;

	DBG("modem %p", modem);

	if (modem == NULL)
		return;

	device = modem->device;
	if (device == NULL)
		return;

	message = dbus_message_new_method_call(OFONO_SERVICE, modem->path,
					OFONO_GPRS_INTERFACE, GET_PROPERTIES);
	if (message == NULL)
		return;

	dbus_message_set_auto_start(message, FALSE);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get ofono GPRS");
		goto done;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		goto done;
	}

	dbus_pending_call_set_notify(call, check_networks_reply,
						(void *)device, NULL);

done:
	dbus_message_unref(message);
}

static void add_device(const char *path, const char *imsi)
{
	struct modem_data *modem;
	struct connman_device *device;

	DBG("path %s imsi %s", path, imsi);

	if (path == NULL)
		return;

	if (imsi == NULL)
		return;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return;

	device = connman_device_create(imsi, CONNMAN_DEVICE_TYPE_CELLULAR);
	if (device == NULL)
		return;

	connman_device_set_ident(device, imsi);

	connman_device_set_mode(device, CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE);

	connman_device_set_string(device, "Path", path);

	if (connman_device_register(device) < 0) {
		connman_device_unref(device);
		return;
	}

	modem->device = device;

	check_networks(modem);
}

static void sim_properties_reply(DBusPendingCall *call, void *user_data)
{
	const char *path = user_data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("path %s", path);

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		return;

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key, *imsi;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "SubscriberIdentity") == TRUE) {
			dbus_message_iter_get_basic(&value, &imsi);

			add_device(path, imsi);
		}

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);
}

static void get_imsi(const char *path)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("path %s", path);

	message = dbus_message_new_method_call(OFONO_SERVICE, path,
				OFONO_SIM_INTERFACE, GET_PROPERTIES);
	if (message == NULL)
		return;

	dbus_message_set_auto_start(message, FALSE);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get ofono modem sim");
		goto done;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		goto done;
	}

	dbus_pending_call_set_notify(call, sim_properties_reply,
						(void *)path, NULL);

done:
	dbus_message_unref(message);
}

static int modem_change_powered(const char *path, dbus_bool_t powered)
{
	DBusMessage *message;
	DBusMessageIter iter;
	DBusPendingCall *call;

	DBG("path %s powered %d", path, powered);

	if (path == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(OFONO_SERVICE, path,
					OFONO_MODEM_INTERFACE, SET_PROPERTY);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	dbus_message_iter_init_append(message, &iter);
	connman_dbus_property_append_variant(&iter, "Powered",
						DBUS_TYPE_BOOLEAN, &powered);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to change powered property");
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, powered_reply, NULL, NULL);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static struct modem_data *add_modem(const char *path)
{
	struct modem_data *modem;

	if (path == NULL)
		return NULL;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem != NULL) {
		modem->available = TRUE;

		return modem;
	}

	modem = g_try_new0(struct modem_data, 1);
	if (modem == NULL)
		return NULL;

	modem->path = g_strdup(path);
	modem->device = NULL;
	modem->available = TRUE;

	g_hash_table_insert(modem_hash, g_strdup(path), modem);

	return modem;
}

static gboolean modem_has_gprs(DBusMessageIter *array)
{
	DBusMessageIter entry;

	dbus_message_iter_recurse(array, &entry);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
		const char *interface;

		dbus_message_iter_get_basic(&entry, &interface);

		if (g_strcmp0(OFONO_GPRS_INTERFACE, interface) == 0)
			return TRUE;

		dbus_message_iter_next(&entry);
	}

	return FALSE;
}

static void modem_properties_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusMessageIter array, dict;
	const char *path = user_data;

	DBG("path %s", path);

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		goto done;

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;
		dbus_bool_t powered;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Powered") == TRUE) {
			dbus_message_iter_get_basic(&value, &powered);

			if (powered == FALSE) {
				modem_change_powered(path, TRUE);
				break;
			}
		} else if (g_str_equal(key, "Interface") == TRUE) {
			if (modem_has_gprs(&value) == TRUE)
				get_imsi(path);
		}

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);
}

static void get_modem_properties(struct modem_data *modem)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("path %s", modem->path);

	if (modem->path == NULL)
		return;

	message = dbus_message_new_method_call(OFONO_SERVICE, modem->path,
				OFONO_MODEM_INTERFACE, GET_PROPERTIES);
	if (message == NULL)
		return;

	dbus_message_set_auto_start(message, FALSE);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get ofono modem");
		goto done;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		goto done;
	}

	dbus_pending_call_set_notify(call, modem_properties_reply,
						(void *)modem->path, NULL);

done:
	dbus_message_unref(message);
}

static void mask_unavailable(gpointer key, gpointer value, gpointer user_data)
{
	struct modem_data *modem = value;

	modem->available = FALSE;
}

static void modems_set_unavailable()
{
	g_hash_table_foreach(modem_hash, mask_unavailable, NULL);
}

static void cleanup_modem(gpointer key, gpointer value, gpointer user_data)
{
	struct modem_data *modem = value;

	if (modem->available == FALSE)
		g_hash_table_remove(modem_hash, key);
}

static void cleanup_modems()
{
	g_hash_table_foreach(modem_hash, cleanup_modem, NULL);
}

static void update_modems(DBusMessageIter *array)
{
	DBusMessageIter entry;

	dbus_message_iter_recurse(array, &entry);

	modems_set_unavailable();

	while (dbus_message_iter_get_arg_type(&entry) ==
					DBUS_TYPE_OBJECT_PATH) {
		const char *path;
		struct modem_data *modem;

		dbus_message_iter_get_basic(&entry, &path);

		modem = add_modem(path);
		if (modem != NULL)
			get_modem_properties(modem);

		dbus_message_iter_next(&entry);
	}

	cleanup_modems();
}

static void manager_properties_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		goto done;

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Modems") == TRUE) {
			update_modems(&value);
			break;
		}

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);
}

static void modem_remove_device(struct modem_data *modem)
{
	if (modem->device == NULL)
		return;

	connman_device_unregister(modem->device);
	connman_device_unref(modem->device);

	modem->device = NULL;
}

static void remove_modem(gpointer data)
{
	struct modem_data *modem = data;

	g_free(modem->path);

	modem_remove_device(modem);

	g_free(modem);
}

static void ofono_connect(DBusConnection *connection, void *user_data)
{
	DBusMessage *message;
	DBusPendingCall *call;

	DBG("connection %p", connection);

	modem_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, remove_modem);

	message = dbus_message_new_method_call(OFONO_SERVICE, "/",
				OFONO_MANAGER_INTERFACE, GET_PROPERTIES);
	if (message == NULL)
		return;

	dbus_message_set_auto_start(message, FALSE);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to get ofono modems");
		goto done;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		goto done;
	}

	dbus_pending_call_set_notify(call, manager_properties_reply,
								NULL, NULL);

done:
	dbus_message_unref(message);

}

static void ofono_disconnect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);

	if (modem_hash == NULL)
		return;

	g_hash_table_destroy(modem_hash);

	modem_hash = NULL;
}

static void modem_changed(DBusConnection *connection, DBusMessage *message)
{
	const char *path = dbus_message_get_path(message);
	struct modem_data *modem;
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Powered") == TRUE) {
		dbus_bool_t powered;

		dbus_message_iter_get_basic(&value, &powered);
		if (powered == TRUE)
			return;

		modem_remove_device(modem);
	} else if (g_str_equal(key, "Interfaces") == TRUE) {
		if (modem_has_gprs(&value) == TRUE) {
			if (modem->device == NULL)
				get_imsi(modem->path);
		} else if (modem->device != NULL)
			modem_remove_device(modem);
	}
}

static void gprs_changed(DBusConnection *connection, DBusMessage *message)
{
	const char *path = dbus_message_get_path(message);
	struct modem_data *modem;
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Attached") == TRUE) {
		dbus_bool_t attached;

		dbus_message_iter_get_basic(&value, &attached);

		DBG("Attached %d", attached);

		if (attached == TRUE)
			check_networks(modem);
		else if (modem->device != NULL)
			connman_device_remove_all_networks(modem->device);

	} else if (g_str_equal(key, "Status") == TRUE) {
		const char *status;
		dbus_message_iter_get_basic(&value, &status);

		DBG("status %s", status);

		/* FIXME: add roaming support */
	} else if (g_str_equal(key, "PrimaryContexts") == TRUE) {
		check_networks(modem);
	} else if (g_str_equal(key, "Powered") == TRUE) {
		dbus_bool_t powered;

		if (modem->device == NULL)
			return;

		dbus_message_iter_get_basic(&value, &powered);
		connman_device_set_powered(modem->device, powered);
	}
}

static void manager_changed(DBusConnection *connection, DBusMessage *message)
{
	const char *path = dbus_message_get_path(message);
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Modems") == TRUE)
		update_modems(&value);
}

static void update_settings(DBusMessageIter *array)
{
	DBusMessageIter dict;
	const char *interface = NULL;

	DBG("");

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Interface") == TRUE) {
			int index;

			dbus_message_iter_get_basic(&value, &interface);

			DBG("interface %s", interface);

			index = connman_inet_ifindex(interface);
			if (index >= 0) {
				connman_network_set_index(
					pending_network, index);
			} else {
				connman_error("Can not find interface %s",
								interface);
				break;
			}
		} else if (g_str_equal(key, "Method") == TRUE) {
			const char *method;

			dbus_message_iter_get_basic(&value, &method);
			if (g_strcmp0(method, "static") == 0) {
				DBG("static");
			} else if (g_strcmp0(method, "dhcp") == 0) {
				DBG("dhcp");
				break;
			}
		} else if (g_str_equal(key, "address") == TRUE) {
			const char *address;

			dbus_message_iter_get_basic(&value, &address);

			DBG("address %s", address);
		}
		/* FIXME: add static setting */
		dbus_message_iter_next(&dict);
	}

	/* deactive, oFono send NULL inteface before deactive signal */
	if (interface == NULL)
		connman_network_set_index(pending_network, -1);
}

static void pri_context_changed(DBusConnection *connection,
					DBusMessage *message)
{
	const char *path = dbus_message_get_path(message);
	const char *pending_path;
	DBusMessageIter iter, value;
	const char *key;

	DBG("pending_network %p, path %s", pending_network, path);

	if (pending_network == NULL)
		return;

	pending_path = connman_network_get_string(pending_network, "Path");
	if (g_strcmp0(pending_path, path) != 0)
		return;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Settings") == TRUE) {
		update_settings(&value);
	} else if (g_str_equal(key, "Active") == TRUE) {
		dbus_bool_t active;

		dbus_message_iter_get_basic(&value, &active);
		connman_network_set_connected(pending_network, active);

		pending_network = NULL;
	}
}

static DBusHandlerResult ofono_signal(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	if (dbus_message_is_signal(message, OFONO_MODEM_INTERFACE,
						PROPERTY_CHANGED) == TRUE) {
		modem_changed(connection, message);
	} else if (dbus_message_is_signal(message, OFONO_GPRS_INTERFACE,
						PROPERTY_CHANGED) == TRUE) {
		gprs_changed(connection, message);
	} else if (dbus_message_is_signal(message, OFONO_MANAGER_INTERFACE,
						PROPERTY_CHANGED) == TRUE) {
		manager_changed(connection, message);
	} else if (dbus_message_is_signal(message, OFONO_PRI_CONTEXT_INTERFACE,
						PROPERTY_CHANGED) == TRUE) {
		pri_context_changed(connection, message);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static const char *gprs_rule = "type=signal, member=" PROPERTY_CHANGED
					",interface=" OFONO_GPRS_INTERFACE;
static const char *modem_rule = "type=signal,member=" PROPERTY_CHANGED
					",interface=" OFONO_MODEM_INTERFACE;
static const char *manager_rule = "type=signal,member=" PROPERTY_CHANGED
					",interface=" OFONO_MANAGER_INTERFACE;
static const char *pri_context_rule = "type=signal,member=" PROPERTY_CHANGED
				", interface=" OFONO_PRI_CONTEXT_INTERFACE;

static guint watch;

static int ofono_init(void)
{
	int err;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	if (dbus_connection_add_filter(connection, ofono_signal,
						NULL, NULL) == FALSE) {
		err = -EIO;
		goto unref;
	}

	err = connman_network_driver_register(&network_driver);
	if (err < 0)
		goto remove;

	err = connman_device_driver_register(&modem_driver);
	if (err < 0) {
		connman_network_driver_unregister(&network_driver);
		goto remove;
	}

	watch = g_dbus_add_service_watch(connection, OFONO_SERVICE,
			ofono_connect, ofono_disconnect, NULL, NULL);
	if (watch == 0) {
		err = -EIO;
		goto remove;
	}

	dbus_bus_add_match(connection, modem_rule, NULL);
	dbus_bus_add_match(connection, gprs_rule, NULL);
	dbus_bus_add_match(connection, manager_rule, NULL);
	dbus_bus_add_match(connection, pri_context_rule, NULL);

	return 0;

remove:
	dbus_connection_remove_filter(connection, ofono_signal, NULL);

unref:
	dbus_connection_unref(connection);

	return err;
}

static void ofono_exit(void)
{
	dbus_bus_remove_match(connection, modem_rule, NULL);
	dbus_bus_remove_match(connection, gprs_rule, NULL);
	dbus_bus_remove_match(connection, manager_rule, NULL);
	dbus_bus_remove_match(connection, pri_context_rule, NULL);

	g_dbus_remove_watch(connection, watch);

	ofono_disconnect(connection, NULL);

	connman_device_driver_unregister(&modem_driver);
	connman_network_driver_unregister(&network_driver);

	dbus_connection_remove_filter(connection, ofono_signal, NULL);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(ofono, "oFono telephony plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, ofono_init, ofono_exit)
