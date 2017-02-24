#include <glib.h>

#include <connman/log.h>
#include "ipsec.h"
#include "vici-client.h"

struct request {
};

static struct request* vici_client_create_request(struct section* root)
{
	struct request* req;

	req = g_try_new0(struct req, 1);
	if (!req) {
		comman_error("Failed to create request");
		return NULL;
	}

	return req;
}

static int vici_client_send_command(struct request* req)
{
	return 0;
}

int vici_client_initialize()
{
	/*
	 * Open socket to connect vici plugin
	 */
	return 0;
}

int vici_client_deinitialize()
{
	return 0;
}

int vici_client_send_request(const char* cmd, struct section* root)
{
	struct request* req = vici_client_send_request(root);
	vici_client_send_command(req);
	return 0;
}
