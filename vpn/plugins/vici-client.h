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
	VICI_CLIENT_ERROR_NONE,
	VICI_CLIENT_ERROR_NOMEM,
} VICIClientError;

typedef enum {
	VICI_CLIENT_EVENT,
} VICIClientEvent;

#define VICI_REQUEST_LOAD_CONN		"load-conn"
#define VICI_REQUEST_LOAD_SHARED	"load-shared"
#define VICI_REQUEST_LOAD_CERT		"load-cert"
#define VICI_REQUEST_LOAD_INITIATE "initiate"

typedef int (*vici_section_add_element)(VICISection *sect, const char *key,
		const char *value, const char *subsection);

VICISection* vici_create_section(const char *name);
int vici_section_add_kv(VICISection *sect, const char *key,
		const char *value, const char *subsection);
int vici_section_add_kvl(VICISection *sect, const char *key,
		const char *value, const char *subsection);
void vici_destroy_section(VICISection *sect);

int vici_client_initialize();
int vici_client_deinitialize();
int vici_client_send_request(const char *cmd, VICISection *root);

#ifdef __cplusplus
}
#endif

#endif /* __VICI_CLIENT_H */
