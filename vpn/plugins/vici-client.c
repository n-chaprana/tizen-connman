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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <glib.h>

#include <connman/log.h>
#include "ipsec.h"
#include "vici-client.h"

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

static const char *vici_cmd_str[] = {
	"load-conn",
	"load-shared",
	"load-cert",
	"load-authority",
	"unload-authority",
	"load-key",
	"initiate",
	NULL,
};

struct request {
	unsigned int allocated;
	unsigned int used;
	unsigned int hdr_len;
	char *sndbuf;
	int cmd;
	int err;
	/* process reply */
	unsigned int rcv_pkt_size;
	char *rcvbuf;
	/* davici_cb cb; */
	void *user;
};

struct _VICIClient {
	/* io data */
	int client_sock_fd;
	int client_watch;
	GSList *request_list;
	vici_connect_reply_cb reply;
	void *ipsec_user_data;
};

struct _VICISection {
	char *name;
	GHashTable *kvs;
	GHashTable *kvls;
	GHashTable *subsection;
};

static void remove_list(gpointer data)
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

static void free_section(gpointer data)
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
	section->kvls = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, remove_list);
	section->subsection = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_section);
	return section;
}

int add_subsection(const char* name, VICISection* child, VICISection* section)
{
	if (section == NULL || name == NULL || child == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	g_hash_table_insert(section->subsection, g_strdup(name), child);
	return 0;
}

static int add_kvl_to_section(const char* key, const char* value, VICISection* section)
{
	GSList *list = NULL;
	if (section == NULL || key == NULL || value == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	list = g_hash_table_lookup(section->kvls, key);
	if (list == NULL)
		list = g_slist_alloc();

	list = g_slist_prepend(list, g_strdup(value));
	g_hash_table_replace(section->kvls, g_strdup(key), list);
	return 0;
}

static int add_kv_to_section(const char* key, const char* value, VICISection* section)
{
	if (section == NULL || key == NULL || value == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	g_hash_table_insert(section->kvs, g_strdup(key), g_strdup(value));
	return 0;
}

static VICISection* get_subsection(VICISection* section, const char* name)
{
	VICISection* sub = g_hash_table_lookup(section->subsection, name);
	if (sub == NULL) {
		sub = vici_create_section(name);
		add_subsection(name, sub, section);
	}
	return sub;
}

int vici_add_kv(VICISection* section, const char* key,
		const char* value, const char* subsection)
{
	VICISection* target = section;
	DBG("key: %s, value: %s, subsection: %s", key, value, subsection);

	if (section == NULL || key == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	if (subsection)
		target = get_subsection(section, subsection);

	add_kv_to_section(key, value, target);
	return 0;
}

int vici_add_kvl(VICISection* section, const char* key,
		const char* value, const char* subsection)
{
	VICISection* target = section;

	DBG("key: %s, value: %s, subsection: %s", key, value, subsection);
	if (section == NULL || key == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	if (subsection)
		target = get_subsection(section, subsection);

	if (g_strcmp0(subsection, "children") == 0)
		target = get_subsection(target, "net");

	add_kvl_to_section(key, value, target);
	return 0;
}

static void add_list_to_section(char *key, GSList *list, VICISection *section)
{
	if (section == NULL || key == NULL || list == NULL)
		return;

	g_hash_table_insert(section->kvls, g_strdup(key), g_slist_copy(list));
	return;
}

int vici_add_list(VICISection* section, char *key, GSList *list, const char* subsection)
{
	VICISection* target = section;

	DBG("key: %s, subsection: %s", key, subsection);
	if (section == NULL || key == NULL) {
		connman_error("invalid parameter");
		return -1;
	}

	if (subsection)
		target = get_subsection(section, subsection);

	if (g_strcmp0(subsection, "children") == 0)
		target = get_subsection(target, "net");

	add_list_to_section(key, list, target);
	return 0;
}

static char *load_cert_from_path(const char *path)
{
	struct stat st;
	FILE *fp = NULL;
	int fd = 0;
	size_t file_size = 0;
	char *file_buff = NULL;

	fp = fopen(path, "rb");
	if (fp == NULL) {
		connman_error("fopen failed");
		return NULL;
	}

	fd = fileno(fp);
	fstat(fd, &st);
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

int vici_add_cert_kv(VICISection *section, const char *key,
		const char *value, const char *subsection)
{
	char *cert = NULL;
	int ret = 0;

	if (value == NULL) {
		DBG("value is null");
		return 0;
	}

	cert = load_cert_from_path(value);
	if (!cert)
		return -1;

	ret = vici_add_kv(section, key, (const char *)cert, subsection);
	g_free(cert);
	return ret;
}

int vici_add_cert_kvl(VICISection *section, const char *key,
		const char *value, const char *subsection)
{
	char *cert = NULL;
	int ret = 0;

	cert = load_cert_from_path(value);
	if (!cert)
		return -1;

	ret = vici_add_kvl(section, key, (const char *)cert, subsection);
	g_free(cert);
	return ret;
}

static void *add_element(struct request *r, enum vici_element type,
						 unsigned int size)
{
	unsigned int newlen;
	void *ret, *new;

	if (r->used + size + 1 > r->allocated) {
		newlen = r->allocated;
		while (newlen < r->used + size + 1) {
			newlen *= 2;
		}
		new = realloc(r->sndbuf, newlen);
		if (!new) {
			r->err = -errno;
			return NULL;
		}
		r->sndbuf = new;
		r->allocated = newlen;
	}
	r->sndbuf[r->used++] = type;
	ret = r->sndbuf + r->used;
	r->used += size;
	return ret;
}

static void section_start(struct request *r, const char *name)
{
	uint8_t nlen;
	char *pos;

	nlen = strlen(name);
	pos = add_element(r, VICI_SECTION_START, 1 + nlen);
	if (pos) {
		pos[0] = nlen;
		memcpy(pos + 1, name, nlen);
	}
}

static void section_end(struct request *r)
{
	add_element(r, VICI_SECTION_END, 0);
}

static void key_value(struct request *r, const char *name,
			   const void *buf, unsigned int buflen)
{
	uint8_t nlen;
	uint16_t vlen;
	char *pos;

	nlen = strlen(name);
	pos = add_element(r, VICI_KEY_VALUE, 1 + nlen + sizeof(vlen) + buflen);
	if (pos) {
		pos[0] = nlen;
		memcpy(pos + 1, name, nlen);
		vlen = htons(buflen);
		memcpy(pos + 1 + nlen, &vlen, sizeof(vlen));
		memcpy(pos + 1 + nlen + sizeof(vlen), buf, buflen);
	}
}


static void list_start(struct request *r, const char *name)
{
	uint8_t nlen;
	char *pos;

	nlen = strlen(name);
	pos = add_element(r, VICI_LIST_START, 1 + nlen);
	if (pos) {
		pos[0] = nlen;
		memcpy(pos + 1, name, nlen);
	}
}

static void list_item(struct request *r, const void *buf,
					  unsigned int buflen)
{
	uint16_t vlen;
	char *pos;

	pos = add_element(r, VICI_LIST_ITEM, sizeof(vlen) + buflen);
	if (pos) {
		vlen = htons(buflen);
		memcpy(pos, &vlen, sizeof(vlen));
		memcpy(pos + sizeof(vlen), buf, buflen);
	}
}

static void list_end(struct request *r)
{
	add_element(r, VICI_LIST_END, 0);
}

static void destroy_vici_request(gpointer data)
{
	struct request *req = (struct request *)data;
	if(!req)
		return;

	g_free(req->sndbuf);
	g_free(req->rcvbuf);
	g_free(req);
}

static int create_vici_request(enum vici_packet_type type, VICIClientCmd cmd,
						  struct request **rp)
{
	struct request *req = NULL;

	if (cmd >= VICI_CMD_MAX || !rp)
		return -EINVAL;

	req = g_try_new0(struct request, 1);
	if (!req) {
		connman_error("g_try_new0 failed");
		return -ENOMEM;
	}

	req->used = 2;
	req->used += strlen(vici_cmd_str[cmd]);
	req->allocated = MIN(32, req->used);
	req->sndbuf = g_try_new0(char, req->allocated);
	if (!req->sndbuf) {
		connman_error("g_try_new0 failed");
		g_free(req);
		return -ENOMEM;
	}

	req->sndbuf[0] = type;
	req->sndbuf[1] = req->used - 2; /* except for type and name length */
	memcpy(req->sndbuf + 2, vici_cmd_str[cmd], req->used - 2);
	req->hdr_len = req->used;
	req->cmd = cmd;

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
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		if (!key || !value)
			continue;
		key_value(req, (const char*)key, (const void *)value, strlen((char *)value));
	}

	return;
}

static void write_list_item(gpointer data, gpointer user_data)
{
	struct request *req = NULL;
	char *value = NULL;

	if (!data || !user_data)
		return;

	value = (char *)data;
	req = (struct request *)user_data;
	list_item(req, value, strlen(value));

	return;
}

static void write_section_kvls(VICISection *section, struct request *req)
{
	GHashTableIter iter;
	gpointer key, value;

	if (section == NULL || req == NULL)
		return;

	g_hash_table_iter_init (&iter, section->kvls);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		if (!key || !value)
			continue;

		list_start(req, key);
		g_slist_foreach((GSList *)value, (GFunc)write_list_item, (gpointer)req);
		list_end(req);
	}

	return;
}

static void write_section(struct request *req, VICISection *section)
{
	GHashTableIter iter;
	gpointer key, value;

	if (req == NULL || section == NULL)
		return;

	if (section->name)
		section_start(req, section->name);

	write_section_kvs(section, req);
	write_section_kvls(section, req);

	g_hash_table_iter_init(&iter, section->subsection);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		if (!key || !value)
			continue;
		write_section(req, (VICISection *)value);
	}

	if (section->name)
		section_end(req);
	return;
}

static int check_socket(int sock)
{
	struct pollfd p_fd;
	int res = 0;

	p_fd.fd = sock;
	p_fd.events = POLLIN | POLLOUT | POLLERR | POLLHUP | POLLNVAL;
	res = poll((struct pollfd *) &p_fd, 1, 1);

	if (res < 0) {
		connman_error("Polling error from socket\n");
		return -1;
	} else if (res == 0) {
		connman_error( "poll timeout. socket is busy\n");
		return 1;
	} else {

		if (p_fd.revents & POLLERR) {
			connman_error("Error! POLLERR from socket[%d]\n", sock);
			return -1;
		} else if (p_fd.revents & POLLHUP) {
			connman_error("Error! POLLHUP from socket[%d]\n", sock);
			return -1;
		} else if (p_fd.revents & POLLNVAL) {
			connman_error("Error! POLLNVAL from socket[%d]\n", sock);
			return -1;
		} else if (p_fd.revents & POLLIN) {
			return 0;
		} else if (p_fd.revents & POLLOUT) {
			return 0;
		}
	}

	connman_error("Unknown poll event [%d]\n", p_fd.revents);
	return -1;
}

static int write_socket(int sock, char *data, int data_len)
{
	int wbytes = 0;
	int left_len = data_len;
	char *ptr = data;
	int res = 0;

	if (sock < SOCK_FD_MIN || !data || data_len < 0)
		return -1;

	res = check_socket(sock);
	if (res < 0)
		return -1;
	else if (res > 0)
		return -2;

	errno = 0;
	while (left_len) {
		wbytes = write(sock, ptr, left_len);
		if (wbytes <= 0) {
			connman_error("Failed to write data into socket[%d].\n", sock);
			break;
		}else if (wbytes < left_len) {
			left_len -= wbytes;
			ptr += wbytes;
		} else if (wbytes == left_len) {
			left_len = 0;
		} else {
			connman_error("Unknown error occurred.\n");
			break;
		}
	}

	if (left_len)
		return -1;
	else
		return 0;
}

int send_vici_command(struct request *req, VICIClient *vici_client)
{
	unsigned int size = 0;
	int res = 0;

	if (req == NULL) {
		connman_error("request is NULL\n");
		return -EINVAL;
	}

	size = htonl(req->used);
	res = write_socket(vici_client->client_sock_fd, (char *)&size, sizeof(size));
	if (res != 0) {
		connman_error("failed to send size with network byte order\n");
		return -EIO;
	}

	res = write_socket(vici_client->client_sock_fd, req->sndbuf, req->used);
	if (res != 0) {
		connman_error("failed to send pkt\n");
		return -EIO;
	}

	vici_client->request_list = g_slist_append(vici_client->request_list, req);
	return res;
}

static void print_vici_element(int elem_type, char *value, int sections)
{
	int i = 0;


	switch (elem_type) {
	case VICI_SECTION_START:
		for (i = 0; i < sections - 1; i++)
			DBG("\t");
		DBG("%s = {\n", value);
		break;
	case VICI_SECTION_END:
		for (i = 0; i < sections; i++)
			DBG("\t");
		DBG("}\n");
		break;
	case VICI_KEY_VALUE:
		for (i = 0; i < sections; i++)
			DBG("\t");
		DBG("%s\n", value);
		break;
	case VICI_LIST_START:
		for (i = 0; i < sections; i++)
			DBG("\t");
		DBG("%s = [", value);
		break;
	case VICI_LIST_ITEM:
		DBG("%s, ", value);
		break;
	case VICI_LIST_END:
		DBG("]\n");
		break;
	default:
		break;
	}
	return;
}

static void debug_vici_message(char *buf, unsigned int size)
{
	char temp[255];
	unsigned int pos = 0;
	int len = 0;
	int sections = 0;
	int type = -1;

	if (buf == NULL || size == 0)
		return;

	pos = 1;
	while (pos < size) {

		type = buf[pos];
		pos++;
		switch (type) {
		case VICI_SECTION_START:
		{
			len = buf[pos];
			pos++;
			g_strlcpy(temp, (const gchar *)&buf[pos], len + 1);
			pos += len;
			sections++;
		}
			break;
		case VICI_SECTION_END:
		{
			sections--;
		}
			break;
		case VICI_KEY_VALUE:
		{
			int key_len = 0;
			int value_len = 0;

			key_len = buf[pos];
			pos++;
			g_strlcpy(temp, (const gchar *)&buf[pos], key_len + 1);
			temp[key_len] = '=';
			pos += (key_len + 1);
			value_len = buf[pos];
			pos++;
			g_strlcpy(temp + key_len + 1, (const gchar *)&buf[pos], value_len + 1);
			pos += value_len;
			len = key_len + 1 + value_len;
		}
			break;
		case VICI_LIST_START:
		{
			len = buf[pos];
			pos++;
			g_strlcpy(temp, (const gchar *)&buf[pos], len + 1);
			pos += len;
		}
			break;
		case VICI_LIST_ITEM:
		{
			pos++;
			len = buf[pos];
			pos++;
			g_strlcpy(temp, (const gchar *)&buf[pos], len + 1);
			pos += len;
		}
			break;
		case VICI_LIST_END:
			break;
		default:
			break;
		}
		print_vici_element(type, temp, sections);
	}
	return;
}

static unsigned int extract_key_value(char *buf, unsigned int pos, char **key, char **value)
{
	int key_len = 0;
	int value_len = 0;

	key_len = buf[pos];
	pos++;
	*key = g_strndup((const gchar *)&buf[pos], key_len);
	pos+=(key_len + 1);
	value_len = buf[pos];
	pos++;
	*value = g_strndup((const gchar *)&buf[pos], value_len);
	pos+=value_len;
	return pos;
}

static gboolean extract_request_result(char *buf, unsigned int size, char **err)
{
	gboolean success = FALSE;
	unsigned int pos = 0;
	int type = -1;

	pos = 1;
	while (pos < size) {

		type = buf[pos];//3
		pos++;
		if (type == VICI_KEY_VALUE) {
			char *key = NULL;
			char *value = NULL;
			pos = extract_key_value(buf, pos, &key, &value);
			DBG("pos : %d size : %d\n", pos, size);

			/* TODO :remove this after debug */
			DBG("key : %s value : %s\n", key, value);
			if (g_strcmp0(key, "success") == 0)
				(g_strcmp0(value, "yes") == 0)?(success = TRUE):(success = FALSE);

			if (g_strcmp0(key, "errmsg"))
				*err = g_strdup(value);
			g_free(key);
			g_free(value);
		}
	}
	return success;
}

static int handle_vici_result(gboolean success, int cmd, char * err)
{
	int ret = 0;
	if (success)
		return 0;

	g_free(err);

	switch (cmd) {
	case 	VICI_CMD_LOAD_CONN:
		ret = EINVAL;
		break;
	case 	VICI_CMD_LOAD_SHARED:
		ret = EINVAL;
		break;
	case 	VICI_CMD_LOAD_CERT:
		ret = EINVAL;
		break;
	case 	VICI_CMD_LOAD_AUTH:
		ret = 0;
		break;
	case 	VICI_CMD_LOAD_KEY:
		ret = EINVAL;
		break;
	case 	VICI_CMD_INITIATE:
		ret = ECONNABORTED;
		break;
	default:
		break;
	}

	DBG(" %s failed with %d!\n", vici_cmd_str[cmd], ret);
	return ret;
}

static int process_vici_response(struct request * req)
{
	char *err = NULL;
	gboolean success = FALSE;
	int ret = 0;

	if (!req)
		return -1;

	if (!req->rcvbuf || req->rcvbuf[0] != VICI_CMD_RESPONSE)
		return -1;

	//TODO: remove below when there's no further problem.
	debug_vici_message(req->rcvbuf, req->rcv_pkt_size);

	success = extract_request_result(req->rcvbuf, req->rcv_pkt_size, &err);
	ret = handle_vici_result(success, req->cmd, err);

	return ret;
}

int vici_send_request(VICIClient *vici_client, VICIClientCmd cmd, VICISection *root)
{
	struct request *req = NULL;
	int ret;

	DBG("%s", vici_cmd_str[cmd]);
	ret = create_vici_request(VICI_CMD_REQUEST, cmd, &req);
	if (ret < 0) {
		connman_error("error on create_request\n");
		return ret;
	}

	write_section(req, root);
	//TODO: remove below when there's no further problem.
	debug_vici_message(req->sndbuf + req->hdr_len - 1, req->used - req->hdr_len + 1);

	ret = send_vici_command(req, vici_client);
	if (ret < 0) {
		destroy_vici_request(req);
		connman_error("error on send_command\n");
	}

	return ret;
}

static int get_socket_from_source(GIOChannel *source, GIOCondition condition)
{
	int sock = -1;
	/* check socket */
	sock = g_io_channel_unix_get_fd(source);
	if (sock < SOCK_FD_MIN)
		return -1;

	if ((condition & G_IO_ERR) || (condition & G_IO_HUP) || (condition & G_IO_NVAL)) {
		connman_error("G_IO_ERR/G_IO_HUP/G_IO_NVAL received sock [%d] condition [%d]\n", sock, condition);
		//TODO: handle the breaking socket
		return -1;
	}
	return sock;
}

static int read_socket(int sock, char *data, unsigned int data_len)
{
	int rbytes = 0;
	int total_rbytes = 0;

	if (sock < SOCK_FD_MIN || !data || data_len <= 0)
		return -1;

	while (data_len > 0) {
		errno = 0;
		rbytes = read(sock, data, data_len);
		if (rbytes <= 0)
			return -1;

		total_rbytes += rbytes;
		data += rbytes;
		data_len -= rbytes;
	}

	return total_rbytes;
}

static int recv_vici_pkt(int sock, struct request *req)
{
	if(!req)
		return -1;

	if (req->rcv_pkt_size == 0) {
		unsigned int pkt_size = 0;
		if (read_socket(sock, (char *)&pkt_size, sizeof(pkt_size)) < 0)
			return -1;

		req->rcv_pkt_size = ntohl(pkt_size);
		/* TODO :REMOVE THIS AFTER DEBUG */
		DBG("rcv_pkt_size [%d] will be recved\n", req->rcv_pkt_size);
	} else {

		char *buf = NULL;
		buf = g_try_malloc0(req->rcv_pkt_size);
		if (buf == NULL)
			return -1;

		if (read_socket(sock, buf, req->rcv_pkt_size) < 0) {
			g_free(buf);
			return -1;
		}
		req->rcvbuf = buf;
	}

	return 0;
}

static struct request *pop_vici_request(VICIClient *vici_client)
{
	GSList *list = NULL;

	if (!vici_client)
		return NULL;

	list = vici_client->request_list;
	if(!list)
		return NULL;

	return list->data;
}

static gboolean process_reply(GIOChannel *source,
					   GIOCondition condition,
					   gpointer user_data)
{
	VICIClient *vici_client = NULL;
	struct request * req = NULL;
	int sock = 0;
	int ret = 0;

	vici_client = (VICIClient *)user_data;
	if (!vici_client)
		return FALSE;

	sock = get_socket_from_source(source, condition);
	if (sock < 0)
		return FALSE;

	/* get first request */
	req = pop_vici_request((VICIClient *)user_data);
	if (!req)
		return FALSE;

	if(recv_vici_pkt(sock, req) < 0)
		return FALSE;

	if (!req->rcvbuf) {
		return TRUE;
	}

	ret = process_vici_response(req);
	vici_client->request_list = g_slist_remove(vici_client->request_list, req);
	destroy_vici_request(req);

	/* TODO :remove this after debug */
	DBG("left request reply : %d", g_slist_length(vici_client->request_list));

	if (ret!= 0 || g_slist_length(vici_client->request_list) == 0)
		vici_client->reply(ret, vici_client->ipsec_user_data);

	return TRUE;
}

static int str_to_socket_addr(const char *uri, struct sockaddr_un *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	strncpy(addr->sun_path, uri, sizeof(addr->sun_path));

	addr->sun_path[sizeof(addr->sun_path)-1] = '\0';

	return offsetof(struct sockaddr_un, sun_path) + strlen(addr->sun_path);
}

static int connect_socket(const char *uri)
{
	struct sockaddr_un addr;
	int len, fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		connman_error("socket() failed");
		return -errno;
	}

	len = str_to_socket_addr(uri, &addr);
	if (len == -1) {
		connman_error("str_to_socket_addr failed");
		close(fd);
		return -1;
	}

	if (connect(fd, (struct sockaddr*)&addr, len) < 0) {
		connman_error("connect failed. errno %d/%s", errno, strerror(errno));
		close(fd);
		return -errno;
	}

	return fd;
}

int vici_initialize(VICIClient **vici_client)
{
	GIOChannel *vici_channel;

	*vici_client = g_try_new0(VICIClient, 1);
	if (!*vici_client) {
		connman_error("out of memory");
		return -ENOMEM;
	}

	(*vici_client)->client_sock_fd = connect_socket(VICI_DEFAULT_URI);
	if ((*vici_client)->client_sock_fd < 0) {
		connman_error("connect_socket failed");
		g_free(*vici_client);
		return -EIO;
	}

	vici_channel = g_io_channel_unix_new((*vici_client)->client_sock_fd);
	if (!vici_channel) {
		connman_error("g_io_channel_unix_new failed");
		close((*vici_client)->client_sock_fd);
		g_free(*vici_client);
		return -ENOMEM;
	}

	(*vici_client)->client_watch = g_io_add_watch_full(vici_channel,
						 G_PRIORITY_LOW,
						 G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
						 (GIOFunc)process_reply,
						 (gpointer)*vici_client,
						 NULL);
	g_io_channel_unref(vici_channel);

	DBG("connected");
	return 0;
}

void vici_set_connect_reply_cb(VICIClient *vici_client, vici_connect_reply_cb reply_cb, gpointer user_data)
{
	vici_client->reply = reply_cb;
	vici_client->ipsec_user_data = user_data;
}

int vici_deinitialize(VICIClient *vici_client)
{
	if (vici_client->client_watch > 0) {
		g_source_remove(vici_client->client_watch);
		vici_client->client_watch = 0;
	}

	close(vici_client->client_sock_fd);
	g_slist_free_full(vici_client->request_list, destroy_vici_request);
	g_free(vici_client);

	return 0;
}
