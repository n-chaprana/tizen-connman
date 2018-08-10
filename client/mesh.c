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

#include <stdio.h>
#include <string.h>

#include "mesh.h"
#include "dbus_helpers.h"

static void print_mesh_peer(char *path, DBusMessageIter *iter)
{
	char *name = "";
	char state = ' ';
	char *str, *property;
	DBusMessageIter entry, val;
	int count = 0, favorite = 0;

	while (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INVALID) {
		dbus_message_iter_recurse(iter, &entry);
		dbus_message_iter_get_basic(&entry, &property);

		if (strcmp(property, "Name") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &name);
		} else if (strcmp(property, "State") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &str);

			if (str) {
				if (strcmp(str, "online") == 0)
					state = 'O';
				else if (strcmp(str, "ready") == 0)
					state = 'R';
				else if (!strcmp(str, "association"))
					state = 'a';
				else if (!strcmp(str, "configuration"))
					state = 'c';
				else if (!strcmp(str, "disconnect"))
					state = 'd';
			}
		} else if (strcmp(property, "Favorite") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &favorite);
		}

		dbus_message_iter_next(iter);
		count++;
	}

	str = strrchr(path, '/');
	if (str)
		str++;
	else
		str = path;

	if (count > 0)
		fprintf(stdout, "%c%c %-20s %s", favorite != 0 ? 'A' : ' ',
				state, name, str);
	else
		fprintf(stdout, "%s %s", "unchanged", str);
}

static void list_mesh_peer_array(DBusMessageIter *iter)
{
	DBusMessageIter array, dict;
	char *path = NULL;

	while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_STRUCT) {
		dbus_message_iter_recurse(iter, &array);
		if (dbus_message_iter_get_arg_type(&array)
				!= DBUS_TYPE_OBJECT_PATH)
			return;

		dbus_message_iter_get_basic(&array, &path);

		dbus_message_iter_next(&array);
		if (dbus_message_iter_get_arg_type(&array)
						== DBUS_TYPE_ARRAY) {
			dbus_message_iter_recurse(&array, &dict);
			print_mesh_peer(path, &dict);
		}

		if (dbus_message_iter_has_next(iter))
			fprintf(stdout, "\n");

		dbus_message_iter_next(iter);
	}
}

void __connmanctl_mesh_peers_list(DBusMessageIter *iter)
{
	DBusMessageIter array;
	char *path;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(iter, &array);
	list_mesh_peer_array(&array);

	dbus_message_iter_next(iter);
	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	fprintf(stdout, "\n}, {");

	dbus_message_iter_recurse(iter, &array);
	while (dbus_message_iter_get_arg_type(&array)
					== DBUS_TYPE_OBJECT_PATH) {
		dbus_message_iter_get_basic(&array, &path);
		fprintf(stdout, "\n%s %s", "removed", path);

		dbus_message_iter_next(&array);
	}

}

void __connmanctl_mesh_connected_peers_list(DBusMessageIter *iter)
{
	DBusMessageIter array;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(iter, &array);
	__connmanctl_dbus_print(&array, "  ", " = ", "\n");
	fprintf(stdout, "\n");
}

void __connmanctl_mesh_disconnected_peers_list(DBusMessageIter *iter)
{
	DBusMessageIter array;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(iter, &array);
	__connmanctl_dbus_print(&array, "  ", " = ", "\n");
	fprintf(stdout, "\n");
}
