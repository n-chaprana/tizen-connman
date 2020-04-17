/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>

#include "ins.h"

struct bssid_info_s {
	char *bssid;
	unsigned int strength;
	unsigned int frequency;
	int score_ins;
	int score_last_connected;
	int score_assoc_reject;
	int score_frequency;
	int score_strength;
};

static void print_bssid_info(gpointer value, gpointer user_data)
{
	struct bssid_info_s *bssid_info = value;
	int *bssid_rank = user_data;

	fprintf(stdout, "     %2d) %-20s total[%2d] last_conn[%2d] "
			"assoc_reject[%2d] freq[%2d(%4d)] strength[%2d(%2d)]\n",
			*bssid_rank, bssid_info->bssid, bssid_info->score_ins,
			bssid_info->score_last_connected, bssid_info->score_assoc_reject,
			bssid_info->score_frequency, bssid_info->frequency,
			bssid_info->score_strength, bssid_info->strength);

	(*bssid_rank)++;
}

static GSList *get_bssid_list(DBusMessageIter *iter)
{
	char *property;
	DBusMessageIter entry, val;
	GSList *bssid_list = NULL;
	struct bssid_info_s *bssid_info = NULL;

	while (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INVALID) {
		dbus_message_iter_recurse(iter, &entry);
		dbus_message_iter_get_basic(&entry, &property);

		if (strcmp(property, "BSSID") == 0) {
			bssid_info = g_try_new0(struct bssid_info_s, 1);
			if (!bssid_info)
				continue;

			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &(bssid_info->bssid));

		} else if (strcmp(property, "ScoreINS") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &(bssid_info->score_ins));

		} else if (strcmp(property, "ScoreLastConnected") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &(bssid_info->score_last_connected));

		} else if (strcmp(property, "ScoreAssocReject") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &(bssid_info->score_assoc_reject));

		} else if (strcmp(property, "Frequency") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &(bssid_info->frequency));

		} else if (strcmp(property, "ScoreFrequency") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &(bssid_info->score_frequency));

		} else if (strcmp(property, "Strength") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &(bssid_info->strength));

		} else if (strcmp(property, "ScoreStrength") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &(bssid_info->score_strength));

			bssid_list = g_slist_append(bssid_list, bssid_info);
		}

		dbus_message_iter_next(iter);
	}

	return bssid_list;
}

static void print_ins_info(int *rank, char *path, char *filter, DBusMessageIter *iter)
{
	char *name = "";
	char *security;
	char *str = NULL;
	int count = 0;
	char *property;
	unsigned char strength;
	unsigned int frequency;
	int score_INS;
	int score_last_user_selection;
	int score_last_connected;
	int score_frequency;
	int score_security_priority;
	int score_internet_connection;
	int score_strength;
	GSList *bssid_list = NULL;
	DBusMessageIter entry, val, dict;

	while (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INVALID) {
		dbus_message_iter_recurse(iter, &entry);
		dbus_message_iter_get_basic(&entry, &property);

		if (strcmp(property, "Name") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &name);

		} else if (strcmp(property, "ScoreINS") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &score_INS);

		} else if (strcmp(property, "ScoreLastUserSelection") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &score_last_user_selection);

		} else if (strcmp(property, "ScoreLastConnected") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &score_last_connected);

		} else if (strcmp(property, "Security") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &security);

		} else if (strcmp(property, "ScoreSecurityPriority") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &score_security_priority);

		} else if (strcmp(property, "Strength") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &strength);

		} else if (strcmp(property, "ScoreStrength") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &score_strength);

		} else if (strcmp(property, "ScoreInternetConnection") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &score_internet_connection);

		} else if (strcmp(property, "Frequency") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &frequency);

		} else if (strcmp(property, "ScoreFrequency") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			dbus_message_iter_get_basic(&val, &score_frequency);

		} else if (strcmp(property, "BSSID.List") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &val);
			if (dbus_message_iter_get_arg_type(&val)
				== DBUS_TYPE_ARRAY) {
				dbus_message_iter_recurse(&val, &dict);
				bssid_list = get_bssid_list(&dict);
			}

		}

		count++;
		dbus_message_iter_next(iter);
	}

	str = strrchr(path, '/');
	if (str)
		str++;
	else
		str = path;

	if (count > 0) {
		if (!filter || strcmp(filter, name) == 0 || strcmp(filter, "ssid") == 0) {
			fprintf(stdout, "  [%2d] %-20s total[%2d] last_usr[%2d] last_conn[%2d] "
				"internet[%2d] sec[%2d(%9s)] freq[%2d(%4d)] strength[%2d(%2d)]\n  %s\n",
				*rank, name, score_INS, score_last_user_selection, score_last_connected,
				score_internet_connection, score_security_priority, security,
				score_frequency, frequency, score_strength, strength, str);

			if (!filter || strcmp(filter, "ssid") != 0) {
				int bssid_rank = 1;
				g_slist_foreach(bssid_list, print_bssid_info, &bssid_rank);
			}

			(*rank)++;
		}

	} else {
		fprintf(stdout, "%-24s %s", "unchanged\n", str);
	}

}

static void list_ins_array(DBusMessageIter *iter, char *filter)
{
	DBusMessageIter array, dict;
	char *path = NULL;
	int rank = 1;

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
			print_ins_info(&rank, path, filter, &dict);
		}

		dbus_message_iter_next(iter);
	}
}

void __connmanctl_ins_list(DBusMessageIter *iter, char *filter)
{
	DBusMessageIter array;
	char *path;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(iter, &array);
	list_ins_array(&array, filter);

	dbus_message_iter_next(iter);
	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	fprintf(stdout, "\n}, {");

	dbus_message_iter_recurse(iter, &array);
	while (dbus_message_iter_get_arg_type(&array)
			== DBUS_TYPE_OBJECT_PATH) {
		dbus_message_iter_get_basic(&array, &path);
		fprintf(stdout, "\n%-24s %s", "removed", path);

		dbus_message_iter_next(&array);
	}

}
