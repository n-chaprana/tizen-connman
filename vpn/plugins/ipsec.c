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
#include <sys/stat.h>
#include <net/if.h>

#include <glib.h>
#include <gio/gio.h>

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

typedef enum {
	CERT_TYPE_NONE,
	CERT_TYPE_DER,
	CERT_TYPE_PEM,
	CERT_TYPE_PKCS12,
	CERT_TYPE_MAX,
} cert_type_e;

static DBusConnection *connection;
static VICIClient *vici_client;
static GFileMonitor* monitor;

struct ipsec_private_data {
	struct vpn_provider *provider;
	vpn_provider_connect_cb_t connect_cb;
	void *connect_user_data;
};

struct ipsec_event_data {
	vpn_event_callback event_cb;
	void *event_user_data;
};

struct {
	const char *cm_opt;
	const char *vici_key;
	const char *subsection;
	vici_add_element add_elem;
} ipsec_conn_options[] = {
	{"IPsec.Version", "version", NULL, vici_add_kv},
	{"IPsec.LeftAddrs", "local_addrs", NULL, vici_add_kvl},
	{"IPsec.RightAddrs", "remote_addrs", NULL, vici_add_kvl},

	{"IPsec.LocalAuth", "auth", "local", vici_add_kv},
	{"IPsec.LocalID", "id", "local", vici_add_kv},
	{"IPsec.LocalXauthID", "xauth_id", "local", vici_add_kv},
	{"IPsec.LocalXauthAuth", "auth", "local-xauth", vici_add_kv},
	{"IPsec.LocalXauthXauthID", "xauth_id", "local-xauth", vici_add_kv},
	{"IPsec.RemoteAuth", "auth", "remote", vici_add_kv},
	{"IPsec.RemoteID", "id", "remote", vici_add_kv},
	{"IPsec.RemoteXauthID", "xauth_id", "remote", vici_add_kv},
	{"IPsec.RemoteXauthAuth", "auth", "remote-xauth", vici_add_kv},
	{"IPsec.RemoteXauthXauthID", "xauth_id", "remote-xauth", vici_add_kv},
	{"IPsec.ChildrenLocalTS", "local_ts", "children", vici_add_kvl},
	{"IPsec.ChildrenRemoteTS", "remote_ts", "children", vici_add_kvl},
};

struct {
	const char *cm_opt;
	const char *vici_type;
} ipsec_shared_options[] = {
	{"IPsec.IKEData", "data"},
	{"IPsec.IKEOwners", "owners"},
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
	{"IPsec.CertPass", "data", NULL},
};

struct {
	const char *cm_opt;
	const char *vici_type;
} ipsec_pkey_options[] = {
	{"IPsec.PKeyType", "type"},
	{"IPsec.PKeyData", "data"},
};

static const char *ikev1_esp_proposals [] ={
		"aes256-sha256",
		"aes128-sha256",
		"aes256-sha1",
		"aes128-sha1",
		"aes256-md5",
		"aes128-md5",
		"3des-sha1",
		"3des-md5",
		NULL,
};

static const char *ikev1_proposals [] ={
		"aes256-sha256-modp1024",
		"aes128-sha256-modp1024",
		"aes256-sha1-modp1024",
		"aes128-sha1-modp1024",
		"aes256-md5-modp1024",
		"aes128-md5-modp1024",
		"3des-sha1-modp1024",
		"3des-md5-modp1024",
		NULL,
};

static const char *ikev2_esp_proposals = "aes256-aes128-sha256-sha1";

static const char *ikev2_proposals = "aes256-aes128-sha512-sha384-sha256-sha1-modp2048-modp1536-modp1024";

static struct ipsec_event_data event_data;

static void free_private_data(struct ipsec_private_data *data)
{
	g_free(data);
}

static int ipsec_notify(DBusMessage *msg, struct vpn_provider *provider)
{
	return 0;
}

static void ipsec_set_event_cb(vpn_event_callback event_cb, struct vpn_provider *provider)
{
	DBG("set event cb!");
	event_data.event_cb = event_cb;
	event_data.event_user_data = provider;
	return;
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
	int ret = 0;

	sect = vici_create_section(NULL);
	if (!sect)
		return -ENOMEM;

	vici_add_kv(sect, "type", type, NULL);
	vici_add_kv(sect, "flag", flag, NULL);
	vici_add_kv(sect, "data", data, NULL);

	ret = vici_send_request(vici_client, VICI_CMD_LOAD_CERT, sect);
	if (ret < 0)
		connman_error("vici_send_request failed");

	vici_destroy_section(sect);

	return ret;
}

static void ipsec_add_default_child_sa_data(struct vpn_provider *provider, VICISection *child)
{
	const char *version = vpn_provider_get_string(provider, "IPsec.Version");
	if (g_strcmp0(version, "1") == 0) {
		int i = 0;
		GSList *list;

		for (list = NULL; ikev1_esp_proposals[i] != NULL; i++)
			list = g_slist_append(list, g_strdup(ikev1_esp_proposals[i]));
		vici_add_list(child, "esp_proposals", list, "net");
		g_slist_free_full(list, g_free);
		list = NULL;
	} else {
		vici_add_kvl(child, "esp_proposals", ikev2_esp_proposals, "net");
	}
	return;
}

static void ipsec_add_default_conn_data(struct vpn_provider *provider, VICISection *conn)
{
	const char *version = vpn_provider_get_string(provider, "IPsec.Version");
	const char *remote_addr = vpn_provider_get_string(provider, "Host");

	vici_add_kvl(conn, "remote_addrs", remote_addr, NULL);
	if (g_strcmp0(version, "1") == 0) {
		int i = 0;
		GSList *list;

		for (list = NULL; ikev1_proposals[i] != NULL; i++)
			list = g_slist_append(list, g_strdup(ikev1_proposals[i]));
		vici_add_list(conn, "proposals", list, NULL);
		g_slist_free_full(list, g_free);
		list = NULL;

		if (g_strcmp0(vpn_provider_get_string(provider, "IPsec.LocalAuth"), "psk") == 0)
			vici_add_kv(conn, "aggressive", "yes", NULL);
	} else {
		vici_add_kvl(conn, "proposals", ikev2_proposals, NULL);
	}

	vici_add_kvl(conn, "vips", "0.0.0.0", NULL);
	return;
}

static char *load_file_from_path(const char *path)
{
	struct stat st;
	FILE *fp = NULL;
	int fd = 0;
	size_t  file_size = 0;
	char *file_buff = NULL;

	if (!path) {
		connman_error("File path is NULL\n");
		return NULL;
	}

	fp = fopen(path, "rb");
	if (!fp) {
		connman_error("fopen %s is failed\n", path);
		return NULL;
	}

	fd = fileno(fp);
	if (fd == -1) {
		connman_error("fp is not a valid stream");
		fclose(fp);
		return NULL;
	}

	if (fstat(fd, &st) != 0) {
		connman_error("fstat failed");
		fclose(fp);
		return NULL;
	}

	file_size = st.st_size;
	file_buff = g_try_malloc0(sizeof(char)*st.st_size);
	if (file_buff == NULL) {
		connman_error("g_try_malloc0 failed\n");
		fclose(fp);
		return NULL;
	}

	if (fread(file_buff, 1, file_size, fp) != file_size) {
		connman_error("file size not matched\n");
		g_free(file_buff);
		file_buff = NULL;
	}

	fclose(fp);
	return file_buff;
}

static char * get_local_cert_str(struct vpn_provider *provider)
{
	const char *path;

	if (!provider)
		return NULL;

	path = vpn_provider_get_string(provider, "IPsec.LocalCerts");

	return load_file_from_path(path);
}

static int ipsec_load_conn(struct vpn_provider *provider, struct ipsec_private_data *data)
{
	const char *key;
	const char *value;
	const char *subsection;
	char *local_cert_str;
	VICISection *conn;
	VICISection *children;
	int i;
	int ret = 0;

	if (!provider || !data) {
		connman_error("invalid provider or data");
		return -EINVAL;
	}

	value = vpn_provider_get_string(provider, "Name");
	DBG("Name: %s", value);
	conn = vici_create_section(value);
	children = vici_create_section("children");
	add_subsection("children", children, conn);

	for (i = 0; i < (int)ARRAY_SIZE(ipsec_conn_options); i++) {
		value = vpn_provider_get_string(provider, ipsec_conn_options[i].cm_opt);
		if (!value)
			continue;

		key = ipsec_conn_options[i].vici_key;
		subsection = ipsec_conn_options[i].subsection;
		ipsec_conn_options[i].add_elem(conn, key, value, subsection);
	}

	local_cert_str = get_local_cert_str(provider);
	if (local_cert_str) {
		/* TODO :remove this after debug */
		DBG("There's local certification to add local section");
		vici_add_kvl(conn, "certs", local_cert_str, "local");
		g_free(local_cert_str);
	}

	ipsec_add_default_conn_data(provider, conn);
	ipsec_add_default_child_sa_data(provider, children);

	ret = vici_send_request(vici_client, VICI_CMD_LOAD_CONN, conn);
	if (ret < 0)
		connman_error("vici_send_request failed");

	vici_destroy_section(conn);

	return ret;
}

static int ipsec_load_shared_psk(struct vpn_provider *provider)
{
	const char *data;
	const char *owner;
	VICISection *sect;
	int ret = 0;

	if (!provider) {
		connman_error("invalid provider");
		return -EINVAL;
	}

	data = vpn_provider_get_string(provider, "IPsec.IKEData");
	owner = vpn_provider_get_string(provider, "IPsec.IKEOwners");
	DBG("IKEData: %s, IKEOwners: %s", data, owner);

	if (!data)
		return 0;

	sect = vici_create_section(NULL);
	if (!sect) {
		return -ENOMEM;
	}

	vici_add_kv(sect, "type", VICI_SHARED_TYPE_PSK, NULL);
	vici_add_kv(sect, "data", data, NULL);
	vici_add_kvl(sect, "owners", owner, NULL);

	ret = vici_send_request(vici_client, VICI_CMD_LOAD_SHARED, sect);
	if (ret < 0)
		connman_error("vici_send_request failed");

	vici_destroy_section(sect);

	return ret;
}

static int ipsec_load_shared_xauth(struct vpn_provider *provider)
{
	const char *data;
	const char *owner;
	VICISection *sect;
	int ret = 0;

	if (!provider) {
		connman_error("invalid provider");
		return -EINVAL;
	}

	data = vpn_provider_get_string(provider, "IPsec.XauthData");
	owner = vpn_provider_get_string(provider, "IPsec.XauthOwners");
	DBG("XauthData: %s, XauthOwners: %s", data, owner);

	if (!data)
		return 0;

	sect = vici_create_section(NULL);

	vici_add_kv(sect, "type", VICI_SHARED_TYPE_XAUTH, NULL);
	vici_add_kv(sect, "data", data, NULL);
	vici_add_kvl(sect, "owners", owner, NULL);

	ret = vici_send_request(vici_client, VICI_CMD_LOAD_SHARED, sect);
	if (ret < 0)
		connman_error("vici_send_request failed");

	vici_destroy_section(sect);

	return ret;
}

static int ipsec_load_key(struct vpn_provider *provider)
{
	const char *type;
	const char *path;
	char *data;
	VICISection *sect;
	int ret = 0;

	if (!provider) {
		connman_error("invalid provider");
		return -EINVAL;
	}

	type = vpn_provider_get_string(provider, "IPsec.PKeyType");
	path = vpn_provider_get_string(provider, "IPsec.PKeyData");
	DBG("PKeyType: %s, PKeyData: %s", type, path);

	if (!type || !path)
		return 0;

	data = load_file_from_path(path);
	if (!data)
		return 0;

	sect = vici_create_section(NULL);
	if (!sect) {
		g_free(data);
		return -ENOMEM;
	}

	vici_add_kv(sect, "type", type, NULL);
	vici_add_kv(sect, "data", data, NULL);

	ret = vici_send_request(vici_client, VICI_CMD_LOAD_KEY, sect);
	if (ret < 0)
		connman_error("vici_send_request failed");

	vici_destroy_section(sect);
	g_free(data);

	return ret;
}

static int ipsec_initiate(struct vpn_provider *provider)
{
	VICISection *sect;
	int ret = 0;

	sect = vici_create_section(NULL);
	if (!sect)
		return -ENOMEM;

	vici_add_kv(sect, "child", "net", NULL);
	ret = vici_send_request(vici_client, VICI_CMD_INITIATE, sect);
	if (ret < 0)
		connman_error("vici_send_request failed");

	vici_destroy_section(sect);

	return ret;
}

static int ipsec_load_cert(struct vpn_provider *provider)
{
	const char *type;
	const char *flag;
	char *data;
	const char *local_auth_type;
	const char *remote_auth_type;
	int ret = 0;

	if (!provider) {
		connman_error("invalid provider");
		return -EINVAL;
	}

	local_auth_type = vpn_provider_get_string(provider, "IPsec.LocalAuth");
	remote_auth_type = vpn_provider_get_string(provider, "IPsec.RemoteAuth");
	if (!ipsec_is_same_auth(local_auth_type, "pubkey") &&
			!ipsec_is_same_auth(remote_auth_type, "pubkey")) {
		DBG("invalid auth type");
		return 0;
	}

	type = vpn_provider_get_string(provider, "IPsec.CertType");
	flag = vpn_provider_get_string(provider, "IPsec.CertFlag");
	data = load_file_from_path(vpn_provider_get_string(provider, "IPsec.CertData"));
	DBG("CertType: %s, CertFalg: %s,CertData: %s", type, flag, data);
	if (!type || ! flag || !data) {
		connman_error("invalid certification information");
		g_free(data);
		return -EINVAL;
	}

	ret = vici_load_cert(type, flag, data);
	if (ret < 0)
		connman_error("failed to load cert");

	g_free(data);

	return ret;
}

static int ipsec_terminate(struct vpn_provider *provider)
{
	VICISection *sect;
	int ret = 0;

	sect = vici_create_section(NULL);
	if (!sect)
		return -ENOMEM;

	vici_add_kv(sect, "child", "net", NULL);
	vici_add_kv(sect, "ike", vpn_provider_get_string(provider, "Name"), NULL);
	vici_add_kv(sect, "timeout", "-1", NULL);
	ret = vici_send_request(vici_client, VICI_CMD_TERMINATE, sect);
	if (ret < 0)
		connman_error("vici_send_request failed");

	vici_destroy_section(sect);

	return ret;
}

static void request_reply_cb(int err, void *user_data)
{
	struct ipsec_private_data *data;

	data = (struct ipsec_private_data *)user_data;
	DBG("request reply cb");

	if(err != 0) {
		if (event_data.event_cb)
			event_data.event_cb(event_data.event_user_data, VPN_STATE_FAILURE);
		/* TODO: Does close socket needed? */
	} else {
		DBG("Series of requests are succeeded");
		/* TODO: Not sure about below */
		if (event_data.event_cb)
			event_data.event_cb(event_data.event_user_data, VPN_STATE_CONNECT);
	}

	free_private_data(data);
}

static void ipsec_vici_event_cb(VICIClientEvent event, void *user_data)
{
	struct vpn_provider *provider;

	provider = (struct vpn_provider *)user_data;
	if (!provider) {
		DBG("Invalid user data");
		return;
	}

	if(event == VICI_EVENT_CHILD_UP) {
		if (event_data.event_cb)
			event_data.event_cb(event_data.event_user_data, VPN_STATE_READY);
	} else if (event == VICI_EVENT_CHILD_DOWN) {
		if (event_data.event_cb)
			event_data.event_cb(event_data.event_user_data, VPN_STATE_DISCONNECT);
	} else {
		DBG("Unknown event");
	}

	return;
}

static struct ipsec_private_data* create_ipsec_private_data(struct vpn_provider *provider,
		vpn_provider_connect_cb_t cb, void* user_data)
{
	struct ipsec_private_data *data;
	data = g_try_new0(struct ipsec_private_data, 1);
	if (!data) {
		connman_error("out of memory");
		return NULL;
	}

	data->provider = provider;
	data->connect_cb = cb;
	data->connect_user_data = user_data;
	return data;
}

static void vici_connect(struct ipsec_private_data *data)
{
	struct vpn_provider *provider = NULL;
	vpn_provider_connect_cb_t cb = NULL;
	int err = 0;

	if (!data)
		IPSEC_ERROR_CHECK_GOTO(-1, done, "Invalid data parameter");

	provider = data->provider;
	cb = data->connect_cb;
	if (!provider || !cb)
		IPSEC_ERROR_CHECK_GOTO(-1, done, "Invalid provider or callback");

	DBG("data %p, provider %p", data, provider);

	/*
	 * Initialize vici client
	 */
	err = vici_initialize(&vici_client);
	IPSEC_ERROR_CHECK_GOTO(err, done, "failed to initialize vici_client");

	/* TODO :remove this after debug */
	DBG("success to initialize vici socket");

	vici_set_request_reply_cb(vici_client, (vici_request_reply_cb)request_reply_cb, data);
	/*
	 * Sets child-updown event
	 */
	err = vici_set_event_cb(vici_client, (vici_event_cb)ipsec_vici_event_cb, provider);
	IPSEC_ERROR_CHECK_GOTO(err, done, "register event failed");

	/* TODO :remove this after debug */
	DBG("success to vici_set_event_cb");
	/*
	 * Send the load-conn command
	 */
	err = ipsec_load_conn(provider, data);
	IPSEC_ERROR_CHECK_GOTO(err, done, "load-conn failed");

	/* TODO :remove this after debug */
	DBG("success to ipsec_load_conn");

	/*
	 * Send the load-shared command for PSK
	 */
	err = ipsec_load_shared_psk(provider);
	IPSEC_ERROR_CHECK_GOTO(err, done, "load-shared failed");

	/* TODO :remove this after debug */
	DBG("success to ipsec_load_shared_psk");

	/*
	 * Send the load-shared command for XAUTH
	 */
	err = ipsec_load_shared_xauth(provider);
	IPSEC_ERROR_CHECK_GOTO(err, done, "load-shared failed");

	/* TODO :remove this after debug */
	DBG("success to ipsec_load_shared_xauth");
	/*
	 * Send the load-cert command
	 */
	err = ipsec_load_cert(provider);
	IPSEC_ERROR_CHECK_GOTO(err, done, "load-cert failed");

	/* TODO :remove this after debug */
	DBG("success to ipsec_load_cert");

	/*
	 * Send the load-key command
	 */
	err = ipsec_load_key(provider);
	IPSEC_ERROR_CHECK_GOTO(err, done, "load-key failed");

	/* TODO :remove this after debug */
	DBG("success to ipsec_load_cert");
	/*
	 * Send the initiate command
	 */
	err = ipsec_initiate(provider);
	IPSEC_ERROR_CHECK_GOTO(err, done, "initiate failed");

	/* TODO :remove this after debug */
	DBG("success to ipsec_initiate");

done:
	/* refer to connect_cb on vpn-provider.c for cb */
	if(cb)
		cb(provider, data->connect_user_data, -err);
	/* TODO: Does close socket needed? when err is not zero */

	return;
}

static void monitor_changed(GFileMonitor *monitor, GFile *file, GFile *other_file,
		GFileMonitorEvent  event_type, gpointer user_data)
{
	DBG("file %s", g_file_get_path(file));
	if (event_type == G_FILE_MONITOR_EVENT_CREATED) {
		if (g_file_test(VICI_DEFAULT_URI, G_FILE_TEST_EXISTS)) {
			DBG("file created: %s", VICI_DEFAULT_URI);
			struct ipsec_private_data *data = user_data;
			vici_connect(data);
			g_object_unref(monitor);
		}
	}
}

static void monitor_vici_socket(struct ipsec_private_data *data)
{
	GError *error = NULL;
	GFile* file;

	file = g_file_new_for_path(VICI_DEFAULT_URI);
	monitor = g_file_monitor_file(file, G_FILE_MONITOR_SEND_MOVED, NULL, &error);
	if (error) {
		connman_error("g_file_monitor_directory failed: %s / %d", error->message, error->code);
		g_error_free(error);
		if(event_data.event_cb)
			event_data.event_cb(event_data.event_user_data, VPN_STATE_FAILURE);
		return;
	}
	/* TODO :remove this after debug */
	DBG("starting to monitor vici socket");
	g_signal_connect(monitor, "changed", G_CALLBACK(monitor_changed), data);
	g_object_unref(file);
}

static void check_vici_socket(struct ipsec_private_data *data)
{
	DBG("data %p", data);
	if (g_file_test(VICI_DEFAULT_URI, G_FILE_TEST_EXISTS)) {
		DBG("file exists: %s", VICI_DEFAULT_URI);
		vici_connect(data);
	} else {
		monitor_vici_socket(data);
	}
}

static void ipsec_died(struct connman_task *task, int exit_code, void *user_data)
{
       DBG("task %p exit_code %d", task, exit_code);
       unlink(VICI_DEFAULT_URI);
       vpn_died(task, exit_code, user_data);
}

static int ipsec_connect(struct vpn_provider *provider,
			struct connman_task *task, const char *if_name,
			vpn_provider_connect_cb_t cb, const char *dbus_sender,
			void *user_data)
{
	struct ipsec_private_data *data;
	int err = 0;

	data = create_ipsec_private_data(provider, cb, user_data);
	if (!data) {
		connman_error("create ipsec private data failed");
		return -ENOMEM;
	}
	/*
	 * Start charon daemon using ipsec script of strongSwan.
	 */
	err = connman_task_run(task, ipsec_died, provider, NULL, NULL, NULL);
	if (err < 0) {
		connman_error("charon start failed");
		if (cb)
			cb(provider, user_data, err);

		g_free(data);
		return err;
	}

	check_vici_socket(data);
//	g_usleep(G_USEC_PER_SEC);

	return err;
}

static int ipsec_error_code(struct vpn_provider *provider, int exit_code)
{
	return 0;
}

static int ipsec_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	int i;
	const char *option;

	DBG("");
	/*
	 * Save IKE connection configurations
	 */
	for (i = 0; i < (int)ARRAY_SIZE(ipsec_conn_options); i++) {
		option = vpn_provider_get_string(provider, ipsec_conn_options[i].cm_opt);
		if (option)
			g_key_file_set_string(keyfile,
					vpn_provider_get_save_group(provider),
					ipsec_conn_options[i].cm_opt,
					option);
	}

	/*
	 * Save shared IKE PSK, EAP or XAUTH secret
	 */
	for (i = 0; i < (int)ARRAY_SIZE(ipsec_shared_options); i++) {
		option = vpn_provider_get_string(provider, ipsec_shared_options[i].cm_opt);
		if (option)
			g_key_file_set_string(keyfile,
					vpn_provider_get_save_group(provider),
					ipsec_shared_options[i].cm_opt,
					option);
	}

	/*
	 * Save certification
	 */
	for (i = 0; i < (int)ARRAY_SIZE(ipsec_cert_options); i++) {
		option = vpn_provider_get_string(provider, ipsec_cert_options[i].cm_opt);
		if (option)
			g_key_file_set_string(keyfile,
					vpn_provider_get_save_group(provider),
					ipsec_cert_options[i].cm_opt,
					option);
	}

	/*
	 * Save private key
	 */
	for (i = 0; i < (int)ARRAY_SIZE(ipsec_pkey_options); i++) {
		option = vpn_provider_get_string(provider, ipsec_pkey_options[i].cm_opt);
		if (option)
			g_key_file_set_string(keyfile,
					vpn_provider_get_save_group(provider),
					ipsec_pkey_options[i].cm_opt,
					option);
	}

	/*
	 * Save local certification
	 */
	option = vpn_provider_get_string(provider, "IPsec.LocalCerts");
	if (option)
		g_key_file_set_string(keyfile,
				vpn_provider_get_save_group(provider),
				"IPsec.LocalCerts",
				option);
	option = vpn_provider_get_string(provider, "IPsec.LocalCertPass");
	if (option)
		g_key_file_set_string(keyfile,
				vpn_provider_get_save_group(provider),
				"IPsec.LocalCertPass",
				option);
	/*
	 * Save CA certification directory
	 */
	option = vpn_provider_get_string(provider, "IPsec.CACertsDir");
	if (option)
		g_key_file_set_string(keyfile,
				vpn_provider_get_save_group(provider),
				"IPsec.CACertsDir",
				option);

	return 0;
}

static void ipsec_disconnect(struct vpn_provider *provider)
{
	int err = 0;
	/*
	 * Send the terminate command
	 */
	err = ipsec_terminate(provider);
	IPSEC_ERROR_CHECK_RETURN(err, "terminate failed");

	err = vici_deinitialize(vici_client);
	IPSEC_ERROR_CHECK_RETURN(err, "failed to deinitialize vici_client");

	return;
}

static struct vpn_driver vpn_driver = {
	.flags = VPN_FLAG_NO_TUN,
	.notify = ipsec_notify,
	.set_event_cb = ipsec_set_event_cb,
	.connect = ipsec_connect,
	.error_code = ipsec_error_code,
	.save = ipsec_save,
	.disconnect = ipsec_disconnect,
};

static int ipsec_init(void)
{
	connection = connman_dbus_get_connection();

	event_data.event_cb = NULL;
	event_data.event_user_data = NULL;

	return vpn_register("ipsec", &vpn_driver, IPSEC);
}

static void ipsec_exit(void)
{
	vpn_unregister("ipsec");

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(ipsec, "IPSec plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, ipsec_init, ipsec_exit)
