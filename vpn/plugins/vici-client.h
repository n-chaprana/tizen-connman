#ifndef __VICI_CLIENT_H
#define __VICI_CLIENT_H

#define VICI_DEFAULT_URI "/var/run/charon.vici"

#define VICI_REQUEST_LOAD_CONN		"load-conn"
#define VICI_REQUEST_LOAD_SHARED	"load-shared"
#define VICI_REQUEST_LOAD_CERT		"load-cert"

int vici_client_initialize();
int vici_client_deinitialize();
int vici_client_send_request(const char* cmd, struct section* root);

#endif /* __VICI_CLIENT_H */
