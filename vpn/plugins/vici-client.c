#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include <glib.h>

#include <connman/log.h>
#include "ipsec.h"
#include "vici-client.h"

#define VICI_DEFAULT_URI "/var/run/charon.vici"

#define SOCK_FD_MIN 3
#define VICI_REQUEST_TIMEOUT 5000

enum vici_element {
	VICI_END = 0,
	VICI_SECTION_START = 1,
	VICI_SECTION_END = 2,
	VICI_KEY_VALUE = 3,
	VICI_LIST_START = 4,
	VICI_LIST_ITEM = 5,
	VICI_LIST_END = 6,
};

enum vici_packet_type {
	VICI_CMD_REQUEST = 0,
	VICI_CMD_RESPONSE = 1,
	VICI_CMD_UNKNOWN = 2,
	VICI_EVENT_REGISTER = 3,
	VICI_EVENT_UNREGISTER = 4,
	VICI_EVENT_CONFIRM = 5,
	VICI_EVENT_UNKNOWN = 6,
	VICI_EVENT = 7,
};

typedef void (*process_return)(unsigned char *buf, unsigned int size);

struct request {
	unsigned int allocated;
	unsigned int used;
	unsigned int hdr_len;
	char *buf;
	int err;
	int client_source_idle_id;
	int client_source_timeout_id;
	/* process reply */
	unsigned int rcv_pkt_size;
	process_return handler;
	/* davici_cb cb; */
	void *user;
};

struct _VICIClient {
	/* io data */
	int client_sock;
	int client_watch;
	GList *request_list;
};

struct _VICISection {
	char *name;
	GHashTable *kvs;
	GHashTable *kvls;
	GHashTable *subsection;
};

static void _remove_list(gpointer data)
{
	if (data == NULL)
		return;

	g_slist_free_full((GSList *)data, g_free);
}

void vici_destroy_section(VICISection* section)
{
	g_free(section->name);
	g_hash_table_destroy(section->kvs);
	g_hash_table_destroy(section->kvls);
	g_hash_table_destroy(section->subsection);
	g_free(section);
}

static void _free_section(gpointer data)
{
	VICISection* section = (VICISection*)data;
	vici_destroy_section(section);
}

VICISection* vici_create_section(const char* name)
{
	VICISection* section;

	section = g_try_new0(VICISection, 1);
	if (!section) {
		connman_error("Failed to create section");
		return NULL;
	}

	if (name)
		section->name = g_strdup(name);
	section->kvs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	section->kvls = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, _remove_list);
	section->subsection = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, _free_section);
	return section;
}

static int _vici_section_add_kvl(VICISection* section, const char* key, const char* value)
{
	GSList *list = NULL;
	if (section == NULL || key == NULL || value == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	list = g_hash_table_lookup(section->kvls, key);
	if (list == NULL) {
		list = g_slist_alloc();
		g_hash_table_insert(section->kvls, g_strdup(key), list);
	}
	
	list = g_slist_prepend(list, g_strdup(value));

	return 0;
}

static int _vici_section_add_kv(VICISection* section, const char* key, const char* value)
{
	if (section == NULL || key == NULL || value == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	g_hash_table_insert(section->kvs, g_strdup(key), g_strdup(value));
	return 0;
}

static int vici_section_add_subsection(VICISection* section, const char* name, VICISection* child)
{
	if (section == NULL || name == NULL || child == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	g_hash_table_insert(section->subsection, g_strdup(name), child);
	return 0;
}

static VICISection* _vici_section_get_subsection(VICISection* section, const char* name)
{
	VICISection* sub = g_hash_table_lookup(section->subsection, name);
	if (sub == NULL) {
		sub = vici_create_section(name);
		vici_section_add_subsection(section, name, sub);
	}
	return sub;
}

int vici_section_add_kv(VICISection* section, const char* key,
		const char* value, const char* subsection)
{
	VICISection* target = section;

	if (section == NULL || key == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	if (subsection)
		target = _vici_section_get_subsection(section, subsection);

	_vici_section_add_kv(target, key, value);
	return 0;
}

int vici_section_add_kvl(VICISection* section, const char* key,
		const char* value, const char* subsection)
{
	VICISection* target = section;

	if (section == NULL || key == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	if (subsection)
		target = _vici_section_get_subsection(section, subsection);

	_vici_section_add_kvl(target, key, value);
	return 0;
}

static void* _add_element(struct request *r, enum vici_element type,
						 unsigned int size)
{
	unsigned int newlen;
	void *ret, *new;

	if (r->used + size + 1 > r->allocated)
	{
		newlen = r->allocated;
		while (newlen < r->used + size + 1)
		{
			newlen *= 2;
		}
		new = realloc(r->buf, newlen);
		if (!new)
		{
			r->err = -errno;
			return NULL;
		}
		r->buf = new;
		r->allocated = newlen;
	}
	r->buf[r->used++] = type;
	ret = r->buf + r->used;
	r->used += size;
	return ret;
}

static void vici_section_start(struct request *r, const char *name)
{
	uint8_t nlen;
	char *pos;

	nlen = strlen(name);
	pos = _add_element(r, VICI_SECTION_START, 1 + nlen);
	if (pos)
	{
		pos[0] = nlen;
		memcpy(pos + 1, name, nlen);
	}
}

static void vici_section_end(struct request *r)
{
	_add_element(r, VICI_SECTION_END, 0);
}

static void vici_kv(struct request *r, const char *name,
			   const void *buf, unsigned int buflen)
{
	uint8_t nlen;
	uint16_t vlen;
	char *pos;

	nlen = strlen(name);
	pos = _add_element(r, VICI_KEY_VALUE, 1 + nlen + sizeof(vlen) + buflen);
	if (pos)
	{
		pos[0] = nlen;
		memcpy(pos + 1, name, nlen);
		vlen = htons(buflen);
		memcpy(pos + 1 + nlen, &vlen, sizeof(vlen));
		memcpy(pos + 1 + nlen + sizeof(vlen), buf, buflen);
	}
}


static void vici_list_start(struct request *r, const char *name)
{
	uint8_t nlen;
	char *pos;

	nlen = strlen(name);
	pos = _add_element(r, VICI_LIST_START, 1 + nlen);
	if (pos)
	{
		pos[0] = nlen;
		memcpy(pos + 1, name, nlen);
	}
}

static void vici_list_item(struct request *r, const void *buf,
					  unsigned int buflen)
{
	uint16_t vlen;
	char *pos;

	pos = _add_element(r, VICI_LIST_ITEM, sizeof(vlen) + buflen);
	if (pos)
	{
		vlen = htons(buflen);
		memcpy(pos, &vlen, sizeof(vlen));
		memcpy(pos + sizeof(vlen), buf, buflen);
	}
}

static void vici_list_end(struct request *r)
{
	_add_element(r, VICI_LIST_END, 0);
}


static int create_vici_request(enum vici_packet_type type, const char *name,
						  struct request **rp)
{
	struct request *req = NULL;

	if (!name || !rp)
		return -1;

	req = g_try_new0(struct request, 1);
	if (!req)
		return -1;

	req->used = 2;
	req->used += strlen(name);
	req->allocated = MIN(32, req->used);
	req->buf = g_try_new0(char, req->allocated);
	if (!req->buf) {
		g_free(req);
		return -1;
	}

	req->buf[0] = type;
	req->buf[1] = req->used - 2; /* except for type and name length */
	memcpy(req->buf + 2, name, req->used - 2);
	req->hdr_len = req->used;

	*rp = req;

	return 0;
}

static void write_section_kvs(VICISection *section, struct request *req)
{
	GHashTableIter iter;
	gpointer key, value;

	if (section == NULL || req == NULL)
		return;

	g_hash_table_iter_init (&iter, section->kvs);
	while (g_hash_table_iter_next (&iter, &key, &value))
	{
		if (!key || !value)
			continue;
		vici_kv(req, (const char*)key, (const void *)value, strlen((char *)value));
	}

	return;
}

static void _write_vl(gpointer data, gpointer user_data)
{
	struct request *req = NULL;
	char *value = NULL;

	if (!data || !user_data)
		return;

	value = (char *)data;
	req = (struct request *)user_data;
	vici_list_item(req, value, strlen(value));

	return;
}

static void write_section_kvls(VICISection *section, struct request *req)
{
	GHashTableIter iter;
	gpointer key, value;

	if (section == NULL || req == NULL)
		return;

	g_hash_table_iter_init (&iter, section->kvls);
	while (g_hash_table_iter_next (&iter, &key, &value))
	{
		if (!key || !value)
			continue;

		vici_list_start(req, key);
		g_slist_foreach((GSList *)value, (GFunc)_write_vl, (gpointer)req);
		vici_list_end(req);
	}

	return;
}

static void _write_section(struct request *req, VICISection *section)
{
	GHashTableIter iter;
	gpointer key, value;
	VICISection *subsection;

	if (req == NULL || section == NULL)
		return;

	if (section->name)
		vici_section_start(req, section->name);

	write_section_kvs(section, req);
	write_section_kvls(section, req);

	g_hash_table_iter_init(&iter, section->subsection);
	while (g_hash_table_iter_next (&iter, &key, &value))
	{
		if (!key || !value)
			continue;
		subsection = value;
		_write_section(req, subsection);
	}

	if (section->name)
		vici_section_end(req);
	return;
}

static int vici_client_send_command(struct request *req)
{
	return 0;
}

static int destroy_vici_request(struct request *req)
{
	return 0;
}

int vici_client_send_request(const char *cmd, VICISection *root)
{
	struct request* req = NULL;
	int ret;

	ret = create_vici_request(VICI_CMD_REQUEST, cmd, &req);
	if (ret < 0) {
		connman_error("error on create_request\n");
		return -1;
	}

	_write_section(req, root);

	ret = vici_client_send_command(req);
	if (ret < 0) {
		connman_error("error on send_command\n");
		return -1;
	}

	ret = destroy_vici_request(req);
	if (ret < 0) {
		connman_error("error on destroy_request \n");
		return -1;
	}

	return 0;
}

static int str_to_sock_addr(const char *uri, struct sockaddr_un *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	strncpy(addr->sun_path, uri, sizeof(addr->sun_path));

	addr->sun_path[sizeof(addr->sun_path)-1] = '\0';

	return offsetof(struct sockaddr_un, sun_path) + strlen(addr->sun_path);
}

static int connect_sock(const char *uri)
{
	struct sockaddr_un addr;
	int len, fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -errno;

	len = str_to_sock_addr(uri, &addr);
	if (len == -1)
	{
		close(fd);
		return -1;
	}

	if (connect(fd, (struct sockaddr*)&addr, len) < 0) {
		close(fd);
		return -errno;
	}

	return fd;
}

static gboolean process_reply(GIOChannel *source, GIOChannel condtion, gpointer user_data)
{
	return TRUE;
}
int vici_client_initialize()
{
	GIOChannel *vici_channel;
	VICIClient *vici_client = NULL;

	vici_client = g_try_new0(VICIClient, 1);
	if (!vici_client) {
		return VICI_CLIENT_ERROR_NOMEM;
	}

	vici_client->client_sock = connect_sock(VICI_DEFAULT_URI);
	if (vici_client->client_sock < 0) {
		g_free(vici_client);
		return -EIO;
	}

	vici_channel = g_io_channel_unix_new(vici_client->client_sock);
	if (!vici_channel) {
		close(vici_client->client_sock);
		g_free(vici_client);
	}

	vici_client->client_watch = g_io_add_watch_full(vici_channel,
						 G_PRIORITY_LOW,
						 G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
						 (GIOFunc)process_reply,
						 (gpointer)vici_client,
						 NULL);
	g_io_channel_unref(vici_channel);

	return 0;
}

int vici_client_deinitialize()
{
	VICIClient *vici_client = NULL;

	if (vici_client->client_watch > 0) {
		g_source_remove(vici_client->client_watch);
		vici_client->client_watch = 0;
	}

	close(vici_client->client_sock);
	g_free(vici_client);

	return 0;
}
