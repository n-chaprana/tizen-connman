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
	const char *subsection;
	vici_section_add_element add_elem;
} ipsec_conn_options[] = {
	{"IPsec.Version", "version", NULL, vici_section_add_kv},
	{"IPsec.LeftAddrs", "local_addrs", NULL, vici_section_add_kvl},
	{"IPsec.RightAddrs", "remote_addrs", NULL, vici_section_add_kvl},

	{"IPsec.LocalAuth", "auth", "local", vici_section_add_kv},
	{"IPsec.LocalCerts", "certs", "local", vici_section_add_kv},
	{"IPsec.LocalID", "id", "local", vici_section_add_kv},
	{"IPsec.LocalXauthID", "xauth_id", "local", vici_section_add_kv},
	{"IPsec.LocalXauthAuth", "auth", "local-xauth", vici_section_add_kv},
	{"IPsec.LocalXauthXauthID", "xauth_id", "local-xauth", vici_section_add_kv},
	{"IPsec.RemoteAuth", "auth", "remote", vici_section_add_kv},
	{"IPsec.RemoteCerts", "certs", "remote", vici_section_add_kv},
	{"IPsec.RemoteID", "id", "remote", vici_section_add_kv},
	{"IPsec.RemoteXauthID", "xauth_id", "remote", vici_section_add_kv},
	{"IPsec.RemoteXauthAuth", "auth", "remote-xauth", vici_section_add_kv},
	{"IPsec.RemoteXauthXauthID", "xauth_id", "remote-xauth", vici_section_add_kv},
	{"IPsec.ChildrenLocalTs", "local_ts", "children", vici_section_add_kvl},
	{"IPsec.ChildrenRemoteTs", "remote_ts", "children", vici_section_add_kvl},
};

struct {
	const char *cm_opt;
	const char *vici_type;
} ipsec_shared_options[] = {
	{"IPsec.IkeData", "data"},
	{"IPsec.IkeOwners", "owners"},
	{"IPsec.XauthData", "data"},
	{"IPsec.XauthOwners", "owners"},
};

struct {
	const char *cm_opt;
	const char *vici_type;
	const char *vici_flag;
} ipsec_cert_options[] = {
	{"IPsec.CertType", "type", NULL},
	{"IPsec.CertFlag", "flag", NULL},
	{"IPsec.CertData", "data", NULL},
};


static int ipsec_notify(DBusMessage *msg, struct vpn_provider *provider)
{
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
	VICISection *sect;
	sect = vici_create_section(NULL);
	vici_section_add_kv(sect, "type", type, NULL);
	vici_section_add_kv(sect, "flag", flag, NULL);
	vici_section_add_kv(sect, "data", data, NULL);

	vici_client_send_request(VICI_REQUEST_LOAD_CERT, sect);

	vici_destroy_section(sect);

	return 0;
}

static int ipsec_load_conn(struct vpn_provider *provider)
{
	const char *key;
	const char *value;
	const char *subsection;
	VICISection *sect;
	int i;

	value = vpn_provider_get_string(provider, "Name");
	sect = vici_create_section(value);

	for (i = 0; i < (int)ARRAY_SIZE(ipsec_conn_options); i++) {
		key = ipsec_conn_options[i].vici_key;
		value = vpn_provider_get_string(provider, ipsec_conn_options[i].cm_opt);
		subsection = ipsec_conn_options[i].subsection;
		ipsec_conn_options[i].add_elem(sect, key, value, subsection);
	}

	vici_client_send_request(VICI_REQUEST_LOAD_CONN, sect);

	vici_destroy_section(sect);

	return 0;
}

static int ipsec_load_shared_psk(struct vpn_provider *provider)
{
	const char *data;
	const char *owner;
	VICISection *sect;

	data = vpn_provider_get_string(provider, "IPsec.IkeData");
	owner = vpn_provider_get_string(provider, "IPsec.IkeOwners");

	if (!data)
		return 0;

	sect = vici_create_section(NULL);

	vici_section_add_kv(sect, "type", VICI_SHARED_TYPE_PSK, NULL);
	vici_section_add_kv(sect, "data", data, NULL);
	vici_section_add_kvl(sect, "owners", owner, NULL);

	vici_client_send_request(VICI_REQUEST_LOAD_SHARED, sect);

	vici_destroy_section(sect);

	return 0;
}


static int ipsec_load_shared_xauth(struct vpn_provider *provider)
{
	const char *data;
	const char *owner;
	VICISection *sect;

	data = vpn_provider_get_string(provider, "IPsec.XauthData");
	owner = vpn_provider_get_string(provider, "IPsec.XauthOwners");

	if (!data)
		return 0;

	sect = vici_create_section(NULL);

	vici_section_add_kv(sect, "type", VICI_SHARED_TYPE_XAUTH, NULL);
	vici_section_add_kv(sect, "data", data, NULL);
	vici_section_add_kvl(sect, "owners", owner, NULL);

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
	 * Send the load-shared command for PSK
	 */
	err = ipsec_load_shared_psk(provider);
	IPSEC_ERROR_CHECK_GOTO(err, done, "load-shared failed");

	/*
	 * Send the load-shared command for XAUTH
	 */
	err = ipsec_load_shared_xauth(provider);
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
