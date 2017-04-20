#ifndef __VICI_CLIENT_H
#define __VICI_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* strongswan VICI plugin client part*/
struct _VICIClient;
typedef struct _VICIClient VICIClient;

struct _VICISection;
typedef struct _VICISection VICISection;

typedef enum {
	VICI_CMD_LOAD_CONN,
	VICI_CMD_LOAD_SHARED,
	VICI_CMD_LOAD_CERT,
	VICI_CMD_LOAD_AUTH,
	VICI_CMD_UNLOAD_AUTH,
	VICI_CMD_LOAD_KEY,
	VICI_CMD_INITIATE,
	VICI_CMD_MAX,
} VICIClientCmd;

#define VICI_DEFAULT_URI "/var/run/charon.vici"

typedef int (*vici_add_element)(VICISection *sect, const char *key,
		const char *value, const char *subsection);

typedef void (*vici_connect_reply_cb)(int err, void *user_data);

VICISection* vici_create_section(const char *name);
int add_subsection(const char* name, VICISection* child, VICISection* section);
void vici_destroy_section(VICISection *sect);
int vici_add_kv(VICISection *sect, const char *key,
		const char *value, const char *subsection);
int vici_add_kvl(VICISection *sect, const char *key,
		const char *value, const char *subsection);
int vici_add_list(VICISection* section, char *key,
		GSList *list, const char* subsection);
int vici_add_cert_kv(VICISection *section, const char *key,
		const char *value, const char *subsection);
int vici_add_cert_kvl(VICISection *section, const char *key,
		const char *value, const char *subsection);

int vici_initialize(VICIClient **vici_client);
int vici_deinitialize(VICIClient *vici_client);
void vici_set_connect_reply_cb(VICIClient *vici_client, vici_connect_reply_cb reply_cb, gpointer user_data);
int vici_send_request(VICIClient *vici_client, VICIClientCmd cmd, VICISection *root);

#ifdef __cplusplus
}
#endif

#endif /* __VICI_CLIENT_H */
