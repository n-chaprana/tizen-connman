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

#ifndef __CONNMAN_MESH_NETLINK_H
#define __CONNMAN_MESH_NETLINK_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int id;
	struct nl_sock *nl_socket;
	struct nl_cb *cb;
} mesh_nl80211_global;

#define MESH_HWMP_ROOTMODE_NO_ROOT						0
#define MESH_HWMP_ROOTMODE_PROACTIVE_PREQ_NO_PREP		2
#define MESH_HWMP_ROOTMODE_PROACTIVE_PREQ_WITH_PREP		3
#define MESH_HWMP_ROOTMODE_RANN							4

#define NL80211_ATTR_IFINDEX							3
#define NL80211_CMD_SET_MESH_CONFIG						29
#define NL80211_ATTR_MESH_CONFIG						35

#define NL80211_MESHCONF_HWMP_ROOTMODE					14
#define NL80211_MESHCONF_GATE_ANNOUNCEMENTS				17

int __connman_mesh_netlink_set_gate_announce(mesh_nl80211_global *global,
					int mesh_if_index, bool gate_announce, int hwmp_rootmode);

mesh_nl80211_global *__connman_mesh_nl80211_global_init(void);
void __connman_mesh_nl80211_global_deinit(mesh_nl80211_global *global);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_MESH_NETLINK_H */
