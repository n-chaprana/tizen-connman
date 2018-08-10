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

#ifndef __CONNMAN_MESH_H
#define __CONNMAN_MESH_H

#include <gdbus.h>

#ifdef __cplusplus
extern "C" {
#endif

struct connman_mesh;

enum connman_mesh_security {
	CONNMAN_MESH_SECURITY_UNKNOWN = 0,
	CONNMAN_MESH_SECURITY_NONE    = 1,
	CONNMAN_MESH_SECURITY_SAE     = 2,
};

enum connman_mesh_state {
	CONNMAN_MESH_STATE_UNKNOWN       = 0,
	CONNMAN_MESH_STATE_IDLE          = 1,
	CONNMAN_MESH_STATE_ASSOCIATION   = 2,
	CONNMAN_MESH_STATE_CONFIGURATION = 3,
	CONNMAN_MESH_STATE_READY         = 4,
	CONNMAN_MESH_STATE_DISCONNECT    = 5,
	CONNMAN_MESH_STATE_FAILURE       = 6,
};

enum connman_mesh_peer_type {
	CONNMAN_MESH_PEER_TYPE_CREATED    = 0,
	CONNMAN_MESH_PEER_TYPE_DISCOVERED = 1,
};

enum connman_mesh_peer_disconnect_reason {
	CONNMAN_MESH_REASON_UNKNOWN          = 0,
	CONNMAN_MESH_DEAUTH_LEAVING          = 1,
	CONNMAN_MESH_PEERING_CANCELLED       = 2,
	CONNMAN_MESH_MAX_PEERS               = 3,
	CONNMAN_MESH_CONFIG_POLICY_VIOLATION = 4,
	CONNMAN_MESH_CLOSE_RCVD              = 5,
	CONNMAN_MESH_MAX_RETRIES             = 6,
	CONNMAN_MESH_CONFIRM_TIMEOUT         = 7,
	CONNMAN_MESH_INVALID_GTK             = 8,
	CONNMAN_MESH_INCONSISTENT_PARAMS     = 9,
	CONNMAN_MESH_INVALID_SECURITY_CAP    = 10,
};

enum connman_mesh_peer_status {
	CONNMAN_MESH_PEER_ADD    = 0,
	CONNMAN_MESH_PEER_REMOVE = 1,
};

struct connman_mesh *connman_mesh_create(const char *interface_addr,
									const char *identifier);

void connman_mesh_set_name(struct connman_mesh *mesh, const char *name);
const char *connman_mesh_get_name(struct connman_mesh *mesh);
void connman_mesh_set_passphrase(struct connman_mesh *mesh,
								 const char *passphrase);
const char *connman_mesh_get_passphrase(struct connman_mesh *mesh);
void connman_mesh_set_address(struct connman_mesh *mesh, const char *address);
void connman_mesh_set_security(struct connman_mesh *mesh, const char *security);
const char *connman_mesh_get_security(struct connman_mesh *mesh);
void connman_mesh_set_frequency(struct connman_mesh *mesh, uint16_t frequency);
uint16_t connman_mesh_get_frequency(struct connman_mesh *mesh);
void connman_mesh_set_ieee80211w(struct connman_mesh *mesh, uint16_t ieee80211w);
uint16_t connman_mesh_get_ieee80211w(struct connman_mesh *mesh);
int connman_mesh_peer_set_state(struct connman_mesh *mesh,
								enum connman_mesh_state new_state);
void connman_mesh_set_peer_type(struct connman_mesh *mesh,
								enum connman_mesh_peer_type type);
bool connman_mesh_peer_is_connected_state(struct connman_mesh *mesh);
struct connman_mesh *connman_get_connected_mesh_from_name(char *name);
struct connman_mesh *connman_get_connecting_mesh_from_name(char *name);
void connman_mesh_set_index(struct connman_mesh *mesh, int index);
void connman_mesh_set_strength(struct connman_mesh *mesh, uint8_t strength);
void connman_mesh_peer_set_disconnect_reason(struct connman_mesh *mesh,
						int disconnect_reason);
void __connman_mesh_add_ethernet_to_bridge(void);
void __connman_mesh_remove_ethernet_from_bridge(void);
int __connman_mesh_change_peer_status(DBusMessage *msg,
				       const char *peer_address,
				       enum connman_mesh_peer_status status);

int connman_mesh_register(struct connman_mesh *mesh);
void connman_mesh_unregister(struct connman_mesh *mesh);

int __connman_mesh_add_virtual_interface(const char *ifname,
					  const char *parent_ifname, const char *bridge_ifname);

int __connman_mesh_remove_virtual_interface(const char *ifname);
int __connman_mesh_set_stp_gate_announce(bool gate_announce, int hwmp_rootmode,
					  int stp);

const char *connman_mesh_get_interface_name(void);
bool connman_mesh_is_interface_created(void);

struct connman_mesh *connman_mesh_get(const char *interface_addr,
				       const char *identifier);

int connman_mesh_notify_interface_create(bool success);
int connman_mesh_notify_interface_remove(bool success);

int connman_mesh_add_connected_peer(const char *peer_address);
int connman_mesh_remove_connected_peer(const char *peer_address, int reason);

typedef void (*mesh_change_peer_status_cb_t) (int result, void *user_data);

struct connman_mesh_driver {
	int (*add_interface) (const char *ifname, const char *parent_ifname);
	int (*remove_interface) (const char *ifname);
	int (*connect) (struct connman_mesh *mesh);
	int (*disconnect) (struct connman_mesh *mesh);
	int (*change_peer_status) (const char *peer_address,
						enum connman_mesh_peer_status status,
						mesh_change_peer_status_cb_t callback, void *user_data);
};

int connman_mesh_driver_register(struct connman_mesh_driver *driver);
void connman_mesh_driver_unregister(struct connman_mesh_driver *driver);

struct connman_mesh_eth_driver {
	int (*add_to_bridge) (const char *bridge);
	int (*remove_from_bridge) (const char *bridge);
};

int connman_mesh_eth_driver_register(struct connman_mesh_eth_driver *driver);
void connman_mesh_eth_driver_unregister(struct connman_mesh_eth_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_MESH_H */
