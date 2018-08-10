/*
 *
 *  Connection Manager
 *
 *
 *  Copyright (C) 2017 Samsung Electronics Co., Ltd.
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
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 *  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "connman.h"
#include <connman/mesh-netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/netlink.h>

static int seq_check_cb(struct nl_msg *msg, void *arg)
{
	DBG("");

	return NL_OK;
}

static int finish_cb(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	DBG("");

	*ret = 0;

	return NL_SKIP;
}

static int ack_cb(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	DBG("");

	*ret = 0;

	return NL_STOP;
}

static int valid_cb(struct nl_msg *msg, void *arg)
{
	DBG("");

	return NL_SKIP;
}

static int error_cb(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *ret = arg;

	*ret = err->error;

	DBG("error %d", *ret);

	return NL_STOP;
}

int __connman_mesh_netlink_set_gate_announce(mesh_nl80211_global *global,
					int mesh_if_index, bool gate_announce, int hwmp_rootmode)
{
	struct nl_msg *msg;
	struct nlattr *container;
	struct nl_cb *cb;
	int err = -1;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	cb = nl_cb_clone(global->cb);
	if (!cb)
		goto out;

	genlmsg_put(msg, 0, 0, global->id, 0, 0, NL80211_CMD_SET_MESH_CONFIG, 0);
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, mesh_if_index);

	container = nla_nest_start(msg, NL80211_ATTR_MESH_CONFIG);

	nla_put_u8(msg, NL80211_MESHCONF_HWMP_ROOTMODE, hwmp_rootmode);

	nla_put_u8(msg, NL80211_MESHCONF_GATE_ANNOUNCEMENTS, gate_announce);

	nla_nest_end(msg, container);

	err = nl_send_auto_complete(global->nl_socket, msg);
	if (err < 0) {
		DBG("Failed to send msg");
		goto out;
	}

	err = 1;

	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_cb, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_cb, &err);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_cb, &err);
	nl_cb_err(cb, NL_CB_CUSTOM, error_cb, &err);

	while (err > 0) {
		int res = nl_recvmsgs(global->nl_socket, cb);
		if (res < 0)
			DBG("nl_recvmsgs failed: %d", res);
	}

out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	return err;
}

mesh_nl80211_global *__connman_mesh_nl80211_global_init(void)
{
	mesh_nl80211_global *global;

	DBG("");

	global = g_malloc0(sizeof(mesh_nl80211_global));

	global->nl_socket = nl_socket_alloc();
	if (!global->nl_socket) {
		DBG("Failed to allocate netlink socket");
		g_free(global);
		return NULL;
	}

	if (genl_connect(global->nl_socket)) {
		DBG("Failed to connect to generic netlink");
		nl_socket_free(global->nl_socket);
		g_free(global);
		return NULL;
	}

	nl_socket_set_buffer_size(global->nl_socket, 8192, 8192);

	global->id = genl_ctrl_resolve(global->nl_socket, "nl80211");
	if (global->id < 0) {
		DBG("nl80211 generic netlink not found");
		nl_socket_free(global->nl_socket);
		g_free(global);
		return NULL;
	}

	global->cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!global->cb) {
		DBG("Failed to allocate netwlink callbacks");
		nl_socket_free(global->nl_socket);
		g_free(global);
		return NULL;
	}

	nl_cb_set(global->cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, seq_check_cb, NULL);

	return global;
}

void __connman_mesh_nl80211_global_deinit(mesh_nl80211_global *global)
{
	DBG("");

	nl_cb_put(global->cb);
	nl_socket_free(global->nl_socket);
	g_free(global);
}
