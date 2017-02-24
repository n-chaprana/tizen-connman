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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <net/if.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/task.h>
#include <connman/dbus.h>
#include <connman/ipconfig.h>

#include "../vpn-provider.h"

#include "vpn.h"
#include "ipsec.h"
#include "vici-client.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

static DBusConnection *connection;

struct {
	const char *cm_opt;
	const char *vici_key;
	const char *section;
} ipsec_conn_options[] = {
	{"IPsec.Version", "version", NULL},
	{"IPsec.LocalAddrs", "local_addrs", NULL},
	{"IPsec.RemoteAddrs", "remote_addrs", NULL},
	{"IPsec.LocalAuth", "auth", "local"},
	{"IPsec.RemoteAuth", "auth", "remote"},
};

/*
 * IPsec.LocalID
 * IPsec.RemoteTS
 */
struct {
	const char *cm_opt;
	const char *vici_type;
} ipsec_shared_options[] = {
	{"IPsec.LocalXauthID", NULL},
	{"IPsec.XauthSecret", "XAUTH"},
	{"IPsec.IKESecret", "IKE"},
};

struct {
	const char *cm_opt;
	const char *vici_type;
	const char *vici_flag;
} ipsec_cert_options[] = {
	{"IPsec.LocalCert", "X509", NULL},
	{"IPsec.RemoteCert", "X509", NULL},
	{"IPsec.CACert", "X509", "CA"},
};


static int ipsec_notify(DBusMessage *msg, struct vpn_provider *provider)
{
	return 0;
}

static void vici_destroy_section(struct section* sect)
{
	g_hash_table_destroy(sect->elm);
	g_hash_table_destroy(sect->subsection);
	g_free(sect);
}

static void free_section(gpointer data)
{
	struct section* sect = (struct section*)data;
	vici_destroy_section(sect);
}

static struct section* vici_create_section(const char* name)
{
	struct section* sect;

	sect = g_try_new0(struct section, 1);
	if (!sect) {
		connman_error("Failed to create section");
		return NULL;
	}

	sect->name = g_strdup(name);
	sect->elm = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	sect->subsection = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_section);
	return sect;
}

static int vici_section_add_kv(struct section* sect, const char* key, const char* value)
{
	if (sect == NULL || key == NULL || value == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	g_hash_table_insert(sect->elm, g_strdup(key), g_strdup(value));
	return 0;
}

static int vici_section_add_subsection(struct section* sect, const char* name, struct section* child)
{
	if (sect == NULL || name == NULL || child == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	g_hash_table_insert(sect->subsection, g_strdup(name), child);
	return 0;
}


static struct section* vici_section_get_subsection(struct section* sect, const char* name)
{
	struct section* sub = g_hash_table_lookup(sect->subsection, name);
	if (sub == NULL) {
		sub = vici_create_section(name);
		vici_section_add_subsection(sect, name, sub);
	}
	return sub;
}

static int vici_section_add_element(struct section* sect, const char* key,
		const char* value, const char* subsection)
{
	struct section* target = sect;

	if (sect == NULL || key == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	if (subsection)
		target = vici_section_get_subsection(sect, subsection);

	vici_section_add_kv(target, key, value);
	return 0;
}

static int ipsec_is_same_auth(const char* req, const char* target)
{
	if (req == NULL || target == NULL)
		return 0;
	return (g_strcmp0(req, target) == 0);
}

static int vici_load_cert(const char* type, const char* flag, const char* data)
{
	struct section *sect;
	sect = vici_create_section("");
	vici_section_add_element(sect, "type", type, NULL);
	vici_section_add_element(sect, "flag", flag, NULL);
	vici_section_add_element(sect, "data", data, NULL);

	vici_client_send_request(VICI_REQUEST_LOAD_CERT, sect);

	vici_destroy_section(sect);

	return 0;
}

static int ipsec_load_conn(struct vpn_provider *provider)
{
	const char *key;
	const char *value;
	const char *subsection;
	struct section *sect;
	int i;

	value = vpn_provider_get_string(provider, "Name");
	sect = vici_create_section(value);

	for (i = 0; i < (int)ARRAY_SIZE(ipsec_conn_options); i++) {
		key = ipsec_conn_options[i].vici_key;
		value = vpn_provider_get_string(provider, ipsec_conn_options[i].cm_opt);
		subsection = ipsec_conn_options[i].section;
		vici_section_add_element(sect, key, value, subsection);
	}

	vici_client_send_request(VICI_REQUEST_LOAD_CONN, sect);

	vici_destroy_section(sect);

	return 0;
}

static int ipsec_load_shared(struct vpn_provider *provider)
{
	const char *type;
	const char *data;
	const char *owner;
	const char *auth_type;
	struct section *sect;

	sect = vici_create_section("");

	auth_type = vpn_provider_get_string(provider, "IPsec.LocalAuth");
	if (ipsec_is_same_auth(auth_type, IPSEC_AUTH_PSK)) {
		type = VICI_SHARED_TYPE_PSK;
		data = vpn_provider_get_string(provider, "IPsec.IKESecret");
	} else if (ipsec_is_same_auth(auth_type, IPSEC_AUTH_XAUTH)) {
		type = VICI_SHARED_TYPE_XAUTH;
		data = vpn_provider_get_string(provider, "IPsec.XauthSecret");
	} else {
		connman_error("invalid auth type: %s", auth_type);
		return -1;
	}

	owner = vpn_provider_get_string(provider, "IPsec.LocalXauthID");

	vici_section_add_element(sect, "type", type, NULL);
	vici_section_add_element(sect, "data", data, NULL);
	vici_section_add_element(sect, "owner", owner, NULL);

	vici_client_send_request(VICI_REQUEST_LOAD_SHARED, sect);

	vici_destroy_section(sect);

	return 0;
}

static int ipsec_load_cert(struct vpn_provider *provider)
{
	const char *type;
	const char *flag;
	const char *data;
	const char *auth_type;
	int i;

	auth_type = vpn_provider_get_string(provider, "IPsec.LocalAuth");
	if (!ipsec_is_same_auth(auth_type, IPSEC_AUTH_RSA)) {
		connman_error("invalid auth type: %s", auth_type);
		return -1;
	}

	for (i = 0; i < (int)ARRAY_SIZE(ipsec_cert_options); i++) {
		type = ipsec_cert_options[i].vici_type;;
		flag = ipsec_cert_options[i].vici_flag;
		data = vpn_provider_get_string(provider, ipsec_cert_options[i].cm_opt);
		vici_load_cert(type, flag, data);
	}

	return 0;
}

static int ipsec_connect(struct vpn_provider *provider,
			struct connman_task *task, const char *if_name,
			vpn_provider_connect_cb_t cb, const char *dbus_sender,
			void *user_data)
{
	int err = 0;

	/*
	 * Start charon daemon using ipsec script of strongSwan.
	 */
	connman_task_add_argument(task, "start", NULL);
	err = connman_task_run(task, vpn_died, provider, NULL, NULL, NULL);
	IPSEC_ERROR_CHECK_GOTO(err, done, "ipsec start failed");

	/*
	 * Initialize vici client
	 */
	err = vici_client_initialize();
	IPSEC_ERROR_CHECK_GOTO(err, done, "failed to initialize vici_client");

	/*
	 * Send the load-conn command
	 */
	err = ipsec_load_conn(provider);
	IPSEC_ERROR_CHECK_GOTO(err, done, "load-conn failed");

	/*
	 * Send the load-shared command for PSK or XAUTH
	 */
	err = ipsec_load_shared(provider);
	IPSEC_ERROR_CHECK_GOTO(err, done, "load-shared failed");

	/*
	 * Send the load-cert command
	 */
	err = ipsec_load_cert(provider);
	IPSEC_ERROR_CHECK_GOTO(err, done, "load-cert failed");

done:
	if (cb)
		cb(provider, user_data, err);

	return err;
}

static int ipsec_error_code(struct vpn_provider *provider, int exit_code)
{
	return 0;
}

static int ipsec_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	return 0;
}

static void ipsec_disconnect(struct vpn_provider *provider)
{
	int err = 0;

	err = vici_client_deinitialize();
	IPSEC_ERROR_CHECK_RETURN(err, "failed to deinitialize vici_client");
}

static struct vpn_driver vpn_driver = {
	.flags = VPN_FLAG_NO_TUN,
	.notify = ipsec_notify,
	.connect = ipsec_connect,
	.error_code = ipsec_error_code,
	.save = ipsec_save,
	.disconnect = ipsec_disconnect,
};

static int ipsec_init(void)
{
	connection = connman_dbus_get_connection();

	return vpn_register("ipsec", &vpn_driver, IPSEC);
}

static void ipsec_exit(void)
{
	vpn_unregister("ipsec");

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(ipsec, "IPSec plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, ipsec_init, ipsec_exit)
