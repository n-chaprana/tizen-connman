/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <gdbus.h>

#include "connman.h"

#define CONF_ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]) - 1)

#define DEFAULT_INPUT_REQUEST_TIMEOUT (120 * 1000)
#define DEFAULT_BROWSER_LAUNCH_TIMEOUT (300 * 1000)

#define MAINFILE "main.conf"
#define CONFIGMAINFILE CONFIGDIR "/" MAINFILE

static char *default_auto_connect[] = {
	"wifi",
	"ethernet",
	"cellular",
	NULL
};

static char *default_favorite_techs[] = {
	"ethernet",
	NULL
};

static char *default_blacklist[] = {
	"vmnet",
	"vboxnet",
	"virbr",
	"ifb",
	"ve-",
	"vb-",
	NULL
};

static struct {
	bool bg_scan;
	char **pref_timeservers;
	unsigned int *auto_connect;
	unsigned int *favorite_techs;
	unsigned int *preferred_techs;
	unsigned int *always_connected_techs;
	char **fallback_nameservers;
	unsigned int timeout_inputreq;
	unsigned int timeout_browserlaunch;
	char **blacklisted_interfaces;
	bool allow_hostname_updates;
	bool allow_domainname_updates;
	bool single_tech;
	char **tethering_technologies;
	bool persistent_tethering_mode;
	bool enable_6to4;
	char *vendor_class_id;
	bool enable_online_check;
	bool auto_connect_roaming_services;
	bool acd;
	bool use_gateways_as_timeservers;
#if defined TIZEN_EXT
	char **cellular_interfaces;
	bool tizen_tv_extension;
	bool auto_ip;
	char *global_nameserver;
	bool supplicant_debug;
#endif
} connman_settings  = {
	.bg_scan = true,
	.pref_timeservers = NULL,
	.auto_connect = NULL,
	.favorite_techs = NULL,
	.preferred_techs = NULL,
	.always_connected_techs = NULL,
	.fallback_nameservers = NULL,
	.timeout_inputreq = DEFAULT_INPUT_REQUEST_TIMEOUT,
	.timeout_browserlaunch = DEFAULT_BROWSER_LAUNCH_TIMEOUT,
	.blacklisted_interfaces = NULL,
	.allow_hostname_updates = true,
	.allow_domainname_updates = true,
	.single_tech = false,
	.tethering_technologies = NULL,
	.persistent_tethering_mode = false,
	.enable_6to4 = false,
	.vendor_class_id = NULL,
	.enable_online_check = true,
	.auto_connect_roaming_services = false,
	.acd = false,
	.use_gateways_as_timeservers = false,
#if defined TIZEN_EXT
	.cellular_interfaces = NULL,
	.tizen_tv_extension = false,
	.auto_ip = true,
	.global_nameserver = NULL,
	.supplicant_debug = false,
#endif
};

#if defined TIZEN_EXT
static struct {
	/* BSSID */
	char *ins_preferred_freq_bssid;
	bool ins_last_connected_bssid;
	bool ins_assoc_reject;
	bool ins_signal_bssid;
	unsigned int ins_preferred_freq_bssid_score;
	unsigned int ins_last_connected_bssid_score;
	unsigned int ins_assoc_reject_score;
	/* SSID */
	bool ins_last_user_selection;
	unsigned int ins_last_user_selection_time;
	bool ins_last_connected;
	char *ins_preferred_freq;
	char **ins_security_priority;
	unsigned int ins_security_priority_count;
	bool ins_signal;
	bool ins_internet;
	unsigned int ins_last_user_selection_score;
	unsigned int ins_last_connected_score;
	unsigned int ins_preferred_freq_score;
	unsigned int ins_security_priority_score;
	unsigned int ins_internet_score;
	/* Common */
	int ins_signal_level3_5ghz;
	int ins_signal_level3_24ghz;
} connman_ins_settings = {
	/* BSSID */
	.ins_preferred_freq_bssid = NULL,
	.ins_last_connected_bssid = true,
	.ins_assoc_reject = true,
	.ins_signal_bssid = true,
	.ins_preferred_freq_bssid_score = 20,
	.ins_last_connected_bssid_score = 20,
	.ins_assoc_reject_score = 10,
	/* SSID */
	.ins_last_user_selection = true,
	.ins_last_user_selection_time = 480,
	.ins_last_connected = true,
	.ins_preferred_freq = NULL,
	.ins_security_priority = NULL,
	.ins_security_priority_count = 0,
	.ins_signal = true,
	.ins_internet = true,
	.ins_last_user_selection_score = 30,
	.ins_last_connected_score = 30,
	.ins_preferred_freq_score = 60,
	.ins_security_priority_score = 5,
	.ins_internet_score = 30,
	/* Common */
	.ins_signal_level3_5ghz = -76,
	.ins_signal_level3_24ghz = -74,
};
#endif

#define CONF_BG_SCAN                    "BackgroundScanning"
#define CONF_PREF_TIMESERVERS           "FallbackTimeservers"
#define CONF_AUTO_CONNECT_TECHS         "DefaultAutoConnectTechnologies"
#define CONF_FAVORITE_TECHS             "DefaultFavoriteTechnologies"
#define CONF_ALWAYS_CONNECTED_TECHS     "AlwaysConnectedTechnologies"
#define CONF_PREFERRED_TECHS            "PreferredTechnologies"
#define CONF_FALLBACK_NAMESERVERS       "FallbackNameservers"
#define CONF_TIMEOUT_INPUTREQ           "InputRequestTimeout"
#define CONF_TIMEOUT_BROWSERLAUNCH      "BrowserLaunchTimeout"
#define CONF_BLACKLISTED_INTERFACES     "NetworkInterfaceBlacklist"
#define CONF_ALLOW_HOSTNAME_UPDATES     "AllowHostnameUpdates"
#define CONF_ALLOW_DOMAINNAME_UPDATES   "AllowDomainnameUpdates"
#define CONF_SINGLE_TECH                "SingleConnectedTechnology"
#define CONF_TETHERING_TECHNOLOGIES      "TetheringTechnologies"
#define CONF_PERSISTENT_TETHERING_MODE  "PersistentTetheringMode"
#define CONF_ENABLE_6TO4                "Enable6to4"
#define CONF_VENDOR_CLASS_ID            "VendorClassID"
#define CONF_ENABLE_ONLINE_CHECK        "EnableOnlineCheck"
#define CONF_AUTO_CONNECT_ROAMING_SERVICES "AutoConnectRoamingServices"
#define CONF_ACD                        "AddressConflictDetection"
#define CONF_USE_GATEWAYS_AS_TIMESERVERS "UseGatewaysAsTimeservers"
#if defined TIZEN_EXT
#define CONF_CELLULAR_INTERFACE         "NetworkCellularInterfaceList"
#define CONF_TIZEN_TV_EXT		        "TizenTVExtension"
#define CONF_ENABLE_AUTO_IP		        "EnableAutoIp"
#define CONF_GLOBAL_NAMESERVER          "GlobalNameserver"
#define CONF_CONNMAN_SUPPLICANT_DEBUG   "ConnmanSupplicantDebug"
#endif

#if defined TIZEN_EXT
/* BSSID */
#define CONF_INS_PREFERRED_FREQ_BSSID        "INSPreferredFreqBSSID"
#define CONF_INS_PREFERRED_FREQ_BSSID_SCORE  "INSPreferredFreqBSSIDScore"
#define CONF_INS_LAST_CONNECTED_BSSID        "INSLastConnectedBSSID"
#define CONF_INS_LAST_CONNECTED_BSSID_SCORE  "INSLastConnectedBSSIDScore"
#define CONF_INS_ASSOC_REJECT                "INSAssocReject"
#define CONF_INS_ASSOC_REJECT_SCORE          "INSAssocRejectScore"
#define CONF_INS_SIGNAL_BSSID                "INSSignalBSSID"
/* SSID */
#define CONF_INS_LAST_USER_SELECTION         "INSLastUserSelection"
#define CONF_INS_LAST_USER_SELECTION_TIME    "INSLastUserSelectionTime"
#define CONF_INS_LAST_USER_SELECTION_SCORE   "INSLastUserSelectionScore"
#define CONF_INS_LAST_CONNECTED              "INSLastConnected"
#define CONF_INS_LAST_CONNECTED_SCORE        "INSLastConnectedScore"
#define CONF_INS_PREFERRED_FREQ              "INSPreferredFreq"
#define CONF_INS_PREFERRED_FREQ_SCORE        "INSPreferredFreqScore"
#define CONF_INS_SECURITY_PRIORITY           "INSSecurityPriority"
#define CONF_INS_SECURITY_PRIORITY_COUNT     "INSSecurityPriorityCount"
#define CONF_INS_SECURITY_PRIORITY_SCORE     "INSSecurityPriorityScore"
#define CONF_INS_SIGNAL                      "INSSignal"
#define CONF_INS_INTERNET                    "INSInternet"
#define CONF_INS_INTERNET_SCORE              "INSInternetScore"
/* Common */
#define CONF_INS_SIGNAL_LEVEL3_5GHZ          "INSSignalLevel3_5GHz"
#define CONF_INS_SIGNAL_LEVEL3_24GHZ         "INSSignalLevel3_24GHz"
#endif

static const char *supported_options[] = {
	CONF_BG_SCAN,
	CONF_PREF_TIMESERVERS,
	CONF_AUTO_CONNECT_TECHS,
	CONF_ALWAYS_CONNECTED_TECHS,
	CONF_PREFERRED_TECHS,
	CONF_FALLBACK_NAMESERVERS,
	CONF_TIMEOUT_INPUTREQ,
	CONF_TIMEOUT_BROWSERLAUNCH,
	CONF_BLACKLISTED_INTERFACES,
	CONF_ALLOW_HOSTNAME_UPDATES,
	CONF_ALLOW_DOMAINNAME_UPDATES,
	CONF_SINGLE_TECH,
	CONF_TETHERING_TECHNOLOGIES,
	CONF_PERSISTENT_TETHERING_MODE,
	CONF_ENABLE_6TO4,
	CONF_VENDOR_CLASS_ID,
	CONF_ENABLE_ONLINE_CHECK,
	CONF_AUTO_CONNECT_ROAMING_SERVICES,
	CONF_ACD,
	CONF_USE_GATEWAYS_AS_TIMESERVERS,
#if defined TIZEN_EXT
	CONF_CELLULAR_INTERFACE,
	CONF_TIZEN_TV_EXT,
	CONF_ENABLE_AUTO_IP,
	CONF_GLOBAL_NAMESERVER,
	CONF_CONNMAN_SUPPLICANT_DEBUG,
#endif
	NULL
};

#if defined TIZEN_EXT
static const char *supported_ins_options[] = {
	/* BSSID */
	CONF_INS_PREFERRED_FREQ_BSSID,
	CONF_INS_PREFERRED_FREQ_BSSID_SCORE,
	CONF_INS_LAST_CONNECTED_BSSID,
	CONF_INS_LAST_CONNECTED_BSSID_SCORE,
	CONF_INS_ASSOC_REJECT,
	CONF_INS_ASSOC_REJECT_SCORE,
	CONF_INS_SIGNAL_BSSID,
	/* SSID */
	CONF_INS_LAST_USER_SELECTION,
	CONF_INS_LAST_USER_SELECTION_TIME,
	CONF_INS_LAST_USER_SELECTION_SCORE,
	CONF_INS_LAST_CONNECTED,
	CONF_INS_LAST_CONNECTED_SCORE,
	CONF_INS_PREFERRED_FREQ,
	CONF_INS_PREFERRED_FREQ_SCORE,
	CONF_INS_SECURITY_PRIORITY,
	CONF_INS_SECURITY_PRIORITY_COUNT,
	CONF_INS_SECURITY_PRIORITY_SCORE,
	CONF_INS_SIGNAL,
	CONF_INS_INTERNET,
	CONF_INS_INTERNET_SCORE,
	/* Common */
	CONF_INS_SIGNAL_LEVEL3_5GHZ,
	CONF_INS_SIGNAL_LEVEL3_24GHZ,
	NULL
};
#endif

static GKeyFile *load_config(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		if (err->code != G_FILE_ERROR_NOENT) {
			connman_error("Parsing %s failed: %s", file,
								err->message);
		}

		g_error_free(err);
		g_key_file_free(keyfile);
		return NULL;
	}

	return keyfile;
}

static uint *parse_service_types(char **str_list, gsize len)
{
	unsigned int *type_list;
	int i, j;
	enum connman_service_type type;

	type_list = g_try_new0(unsigned int, len + 1);
	if (!type_list)
		return NULL;

	i = 0;
	j = 0;
	while (str_list[i]) {
		type = __connman_service_string2type(str_list[i]);

		if (type != CONNMAN_SERVICE_TYPE_UNKNOWN) {
			type_list[j] = type;
			j += 1;
		}
		i += 1;
	}

	type_list[j] = CONNMAN_SERVICE_TYPE_UNKNOWN;

	return type_list;
}

static char **parse_fallback_nameservers(char **nameservers, gsize len)
{
	char **servers;
	int i, j;

	servers = g_try_new0(char *, len + 1);
	if (!servers)
		return NULL;

	i = 0;
	j = 0;
	while (nameservers[i]) {
		if (connman_inet_check_ipaddress(nameservers[i]) > 0) {
			servers[j] = g_strdup(nameservers[i]);
			j += 1;
		}
		i += 1;
	}

	return servers;
}

static void check_config(GKeyFile *config)
{
	char **keys;
	int j;

	if (!config)
		return;

	keys = g_key_file_get_groups(config, NULL);

	for (j = 0; keys && keys[j]; j++) {
#if defined TIZEN_EXT
		if (g_strcmp0(keys[j], "General") != 0 &&
			g_strcmp0(keys[j], "INS") != 0)
#else
		if (g_strcmp0(keys[j], "General") != 0)
#endif
			connman_warn("Unknown group %s in %s",
						keys[j], MAINFILE);
	}

	g_strfreev(keys);

	keys = g_key_file_get_keys(config, "General", NULL, NULL);

	for (j = 0; keys && keys[j]; j++) {
		bool found;
		int i;

		found = false;
		for (i = 0; supported_options[i]; i++) {
			if (g_strcmp0(keys[j], supported_options[i]) == 0) {
				found = true;
				break;
			}
		}
		if (!found && !supported_options[i])
			connman_warn("Unknown option %s in %s",
						keys[j], MAINFILE);
	}

	g_strfreev(keys);

#if defined TIZEN_EXT
	keys = g_key_file_get_keys(config, "INS", NULL, NULL);

	for (j = 0; keys && keys[j]; j++) {
		bool found;
		int i;

		found = false;
		for (i = 0; supported_ins_options[i]; i++) {
			if (g_strcmp0(keys[j], supported_ins_options[i]) == 0) {
				found = true;
				break;
			}
		}
		if (!found && !supported_ins_options[i])
			connman_warn("Unknown option %s in %s",
						keys[j], MAINFILE);
	}

	g_strfreev(keys);
#endif
}

#if defined TIZEN_EXT
static void check_Tizen_INS_configuration(GKeyFile *config)
{
	GError *error = NULL;
	char *ins_preferred_freq_bssid;
	char *ins_preferred_freq;
	char **ins_security_priority;
	bool boolean;
	int integer;
	gsize len;

	ins_preferred_freq_bssid = __connman_config_get_string(config, "INS",
					CONF_INS_PREFERRED_FREQ_BSSID, &error);
	if (!error)
		connman_ins_settings.ins_preferred_freq_bssid = ins_preferred_freq_bssid;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "INS",
			CONF_INS_PREFERRED_FREQ_BSSID_SCORE, &error);
	if (!error && integer >= 0)
		connman_ins_settings.ins_preferred_freq_bssid_score = integer;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "INS",
			CONF_INS_LAST_CONNECTED_BSSID, &error);
	if (!error)
		connman_ins_settings.ins_last_connected_bssid = boolean;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "INS",
			CONF_INS_LAST_CONNECTED_BSSID_SCORE, &error);
	if (!error && integer >= 0)
		connman_ins_settings.ins_last_connected_bssid_score = integer;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "INS",
			CONF_INS_ASSOC_REJECT, &error);
	if (!error)
		connman_ins_settings.ins_assoc_reject = boolean;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "INS",
			CONF_INS_ASSOC_REJECT_SCORE, &error);
	if (!error && integer >= 0)
		connman_ins_settings.ins_assoc_reject_score = integer;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "INS",
			CONF_INS_SIGNAL_BSSID, &error);
	if (!error)
		connman_ins_settings.ins_signal_bssid = boolean;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "INS",
			CONF_INS_LAST_USER_SELECTION, &error);
	if (!error)
		connman_ins_settings.ins_last_user_selection = boolean;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "INS",
			CONF_INS_LAST_USER_SELECTION_TIME, &error);
	if (!error && integer >= 0)
		connman_ins_settings.ins_last_user_selection_time = integer;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "INS",
			CONF_INS_LAST_USER_SELECTION_SCORE, &error);
	if (!error && integer >= 0)
		connman_ins_settings.ins_last_user_selection_score = integer;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "INS",
			CONF_INS_LAST_CONNECTED, &error);
	if (!error)
		connman_ins_settings.ins_last_connected = boolean;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "INS",
			CONF_INS_LAST_CONNECTED_SCORE, &error);
	if (!error && integer >= 0)
		connman_ins_settings.ins_last_connected_score = integer;

	g_clear_error(&error);

	ins_preferred_freq = __connman_config_get_string(config, "INS",
					CONF_INS_PREFERRED_FREQ, &error);
	if (!error)
		connman_ins_settings.ins_preferred_freq = ins_preferred_freq;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "INS",
			CONF_INS_PREFERRED_FREQ_SCORE, &error);
	if (!error && integer >= 0)
		connman_ins_settings.ins_preferred_freq_score = integer;

	g_clear_error(&error);

	ins_security_priority = g_key_file_get_string_list(config, "INS",
			CONF_INS_SECURITY_PRIORITY, &len, &error);

	if (error == NULL) {
		connman_ins_settings.ins_security_priority = ins_security_priority;
		connman_ins_settings.ins_security_priority_count = len;
	}

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "INS",
			CONF_INS_SECURITY_PRIORITY_SCORE, &error);
	if (!error && integer >= 0)
		connman_ins_settings.ins_security_priority_score = integer;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "INS",
			CONF_INS_SIGNAL, &error);
	if (!error)
		connman_ins_settings.ins_signal = boolean;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "INS",
			CONF_INS_INTERNET, &error);
	if (!error)
		connman_ins_settings.ins_internet = boolean;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "INS",
			CONF_INS_INTERNET_SCORE, &error);
	if (!error && integer >= 0)
		connman_ins_settings.ins_internet_score = integer;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "INS",
			CONF_INS_SIGNAL_LEVEL3_5GHZ, &error);
	if (!error)
		connman_ins_settings.ins_signal_level3_5ghz = integer;

	g_clear_error(&error);

	integer = g_key_file_get_integer(config, "INS",
			CONF_INS_SIGNAL_LEVEL3_24GHZ, &error);
	if (!error)
		connman_ins_settings.ins_signal_level3_24ghz = integer;

	g_clear_error(&error);
}

static void check_Tizen_configuration(GKeyFile *config)
{
	GError *error = NULL;
	char **cellular_interfaces;
	char *global_nameserver;
	bool boolean;
	gsize len;

	cellular_interfaces = g_key_file_get_string_list(config, "General",
			CONF_CELLULAR_INTERFACE, &len, &error);

	if (error == NULL)
		connman_settings.cellular_interfaces = cellular_interfaces;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
			CONF_TIZEN_TV_EXT, &error);
	if (!error)
		connman_settings.tizen_tv_extension = boolean;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
			CONF_ENABLE_AUTO_IP, &error);
	if (!error)
		connman_settings.auto_ip = boolean;

	g_clear_error(&error);

	global_nameserver = __connman_config_get_string(config, "General",
					CONF_GLOBAL_NAMESERVER, &error);
	if (!error)
		connman_settings.global_nameserver = global_nameserver;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
			CONF_CONNMAN_SUPPLICANT_DEBUG, &error);
	if (!error)
		connman_settings.supplicant_debug = boolean;

	g_clear_error(&error);

	check_Tizen_INS_configuration(config);
}

static void set_nofile_inc(void)
{
	int err;
	struct rlimit rlim;

	rlim.rlim_cur = 8192;
	rlim.rlim_max = 8192;

	err = setrlimit(RLIMIT_NOFILE, &rlim);
	if (err)
		DBG("fail to increase FILENO err(%d)", err);

	return;
}
#endif

static void parse_config(GKeyFile *config)
{
	GError *error = NULL;
	bool boolean;
	char **timeservers;
	char **interfaces;
	char **str_list;
	char **tethering;
        char *vendor_class_id;
	gsize len;
	int timeout;

	if (!config) {
		connman_settings.auto_connect =
			parse_service_types(default_auto_connect, CONF_ARRAY_SIZE(default_auto_connect));
		connman_settings.favorite_techs =
			parse_service_types(default_favorite_techs, CONF_ARRAY_SIZE(default_favorite_techs));
		connman_settings.blacklisted_interfaces =
			g_strdupv(default_blacklist);
		return;
	}

	DBG("parsing %s", MAINFILE);

	boolean = g_key_file_get_boolean(config, "General",
						CONF_BG_SCAN, &error);
	if (!error)
		connman_settings.bg_scan = boolean;

	g_clear_error(&error);

	timeservers = __connman_config_get_string_list(config, "General",
					CONF_PREF_TIMESERVERS, NULL, &error);
	if (!error)
		connman_settings.pref_timeservers = timeservers;

	g_clear_error(&error);

	str_list = __connman_config_get_string_list(config, "General",
			CONF_AUTO_CONNECT_TECHS, &len, &error);

	if (!error)
		connman_settings.auto_connect =
			parse_service_types(str_list, len);
	else
		connman_settings.auto_connect =
			parse_service_types(default_auto_connect, CONF_ARRAY_SIZE(default_auto_connect));

	g_clear_error(&error);

	str_list = __connman_config_get_string_list(config, "General",
			CONF_FAVORITE_TECHS, &len, &error);

	if (!error)
		connman_settings.favorite_techs =
			parse_service_types(str_list, len);
	else
		connman_settings.favorite_techs =
			parse_service_types(default_favorite_techs, CONF_ARRAY_SIZE(default_favorite_techs));

	g_strfreev(str_list);

	g_clear_error(&error);

	str_list = __connman_config_get_string_list(config, "General",
			CONF_PREFERRED_TECHS, &len, &error);

	if (!error)
		connman_settings.preferred_techs =
			parse_service_types(str_list, len);

	g_strfreev(str_list);

	g_clear_error(&error);

	str_list = __connman_config_get_string_list(config, "General",
			CONF_ALWAYS_CONNECTED_TECHS, &len, &error);

	if (!error)
		connman_settings.always_connected_techs =
			parse_service_types(str_list, len);

	g_strfreev(str_list);

	g_clear_error(&error);

	str_list = __connman_config_get_string_list(config, "General",
			CONF_FALLBACK_NAMESERVERS, &len, &error);

	if (!error)
		connman_settings.fallback_nameservers =
			parse_fallback_nameservers(str_list, len);

	g_strfreev(str_list);

	g_clear_error(&error);

	timeout = g_key_file_get_integer(config, "General",
			CONF_TIMEOUT_INPUTREQ, &error);
	if (!error && timeout >= 0)
		connman_settings.timeout_inputreq = timeout * 1000;

	g_clear_error(&error);

	timeout = g_key_file_get_integer(config, "General",
			CONF_TIMEOUT_BROWSERLAUNCH, &error);
	if (!error && timeout >= 0)
		connman_settings.timeout_browserlaunch = timeout * 1000;

	g_clear_error(&error);

	interfaces = __connman_config_get_string_list(config, "General",
			CONF_BLACKLISTED_INTERFACES, &len, &error);

	if (!error)
		connman_settings.blacklisted_interfaces = interfaces;
	else
		connman_settings.blacklisted_interfaces =
			g_strdupv(default_blacklist);

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
					CONF_ALLOW_HOSTNAME_UPDATES,
					&error);
	if (!error)
		connman_settings.allow_hostname_updates = boolean;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
					CONF_ALLOW_DOMAINNAME_UPDATES,
					&error);
	if (!error)
		connman_settings.allow_domainname_updates = boolean;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
			CONF_SINGLE_TECH, &error);
	if (!error)
		connman_settings.single_tech = boolean;

	g_clear_error(&error);

	tethering = __connman_config_get_string_list(config, "General",
			CONF_TETHERING_TECHNOLOGIES, &len, &error);

	if (!error)
		connman_settings.tethering_technologies = tethering;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
					CONF_PERSISTENT_TETHERING_MODE,
					&error);
	if (!error)
		connman_settings.persistent_tethering_mode = boolean;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
					CONF_ENABLE_6TO4, &error);
	if (!error)
		connman_settings.enable_6to4 = boolean;

	g_clear_error(&error);

	vendor_class_id = __connman_config_get_string(config, "General",
					CONF_VENDOR_CLASS_ID, &error);
	if (!error)
		connman_settings.vendor_class_id = vendor_class_id;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
					CONF_ENABLE_ONLINE_CHECK, &error);
	if (!error) {
		connman_settings.enable_online_check = boolean;
		if (!boolean)
			connman_info("Online check disabled by main config.");
	}

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
				CONF_AUTO_CONNECT_ROAMING_SERVICES, &error);
	if (!error)
		connman_settings.auto_connect_roaming_services = boolean;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General", CONF_ACD, &error);
	if (!error)
		connman_settings.acd = boolean;

	g_clear_error(&error);

	boolean = __connman_config_get_bool(config, "General",
				CONF_USE_GATEWAYS_AS_TIMESERVERS, &error);
	if (!error)
		connman_settings.use_gateways_as_timeservers = boolean;

	g_clear_error(&error);

#if defined TIZEN_EXT
	check_Tizen_configuration(config);
#endif
}

static int config_init(const char *file)
{
	GKeyFile *config;

#if defined TIZEN_EXT
	set_nofile_inc();
#endif
	config = load_config(file);
	check_config(config);
	parse_config(config);
	if (config)
		g_key_file_free(config);

	return 0;
}

static GMainLoop *main_loop = NULL;

static unsigned int __terminated = 0;

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		if (__terminated == 0) {
			connman_info("Terminating");
			g_main_loop_quit(main_loop);
		}

		__terminated = 1;
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static void disconnect_callback(DBusConnection *conn, void *user_data)
{
	connman_error("D-Bus disconnect");

	g_main_loop_quit(main_loop);
}

static gchar *option_config = NULL;
static gchar *option_debug = NULL;
static gchar *option_device = NULL;
static gchar *option_plugin = NULL;
static gchar *option_nodevice = NULL;
static gchar *option_noplugin = NULL;
static gchar *option_wifi = NULL;
static gboolean option_detach = TRUE;
static gboolean option_dnsproxy = TRUE;
static gboolean option_backtrace = TRUE;
static gboolean option_version = FALSE;

static bool parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value) {
		if (option_debug) {
			char *prev = option_debug;

			option_debug = g_strconcat(prev, ",", value, NULL);
			g_free(prev);
		} else {
			option_debug = g_strdup(value);
		}
	} else {
		g_free(option_debug);
		option_debug = g_strdup("*");
	}

	return true;
}

static bool parse_noplugin(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (option_noplugin) {
		char *prev = option_noplugin;

		option_noplugin = g_strconcat(prev, ",", value, NULL);
		g_free(prev);
	} else {
		option_noplugin = g_strdup(value);
	}

	return true;
}

static GOptionEntry options[] = {
	{ "config", 'c', 0, G_OPTION_ARG_STRING, &option_config,
				"Load the specified configuration file "
				"instead of " CONFIGMAINFILE, "FILE" },
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ "device", 'i', 0, G_OPTION_ARG_STRING, &option_device,
			"Specify networking devices or interfaces", "DEV,..." },
	{ "nodevice", 'I', 0, G_OPTION_ARG_STRING, &option_nodevice,
			"Specify networking interfaces to ignore", "DEV,..." },
	{ "plugin", 'p', 0, G_OPTION_ARG_STRING, &option_plugin,
				"Specify plugins to load", "NAME,..." },
	{ "noplugin", 'P', 0, G_OPTION_ARG_CALLBACK, &parse_noplugin,
				"Specify plugins not to load", "NAME,..." },
	{ "wifi", 'W', 0, G_OPTION_ARG_STRING, &option_wifi,
				"Specify driver for WiFi/Supplicant", "NAME" },
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't fork daemon to background" },
	{ "nodnsproxy", 'r', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_dnsproxy,
				"Don't support DNS resolving" },
	{ "nobacktrace", 0, G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_backtrace,
				"Don't print out backtrace information" },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ NULL },
};

const char *connman_option_get_string(const char *key)
{
	if (g_str_equal(key, CONF_VENDOR_CLASS_ID))
		return connman_settings.vendor_class_id;

	if (g_strcmp0(key, "wifi") == 0) {
		if (!option_wifi)
			return "nl80211,wext";
		else
			return option_wifi;
	}

#if defined TIZEN_EXT
	if (g_str_equal(key, CONF_GLOBAL_NAMESERVER))
		return connman_settings.global_nameserver;
#endif

#if defined TIZEN_EXT
	if (g_str_equal(key, CONF_INS_PREFERRED_FREQ_BSSID))
		return connman_ins_settings.ins_preferred_freq_bssid;

	if (g_str_equal(key, CONF_INS_PREFERRED_FREQ))
		return connman_ins_settings.ins_preferred_freq;
#endif
	return NULL;
}

bool connman_setting_get_bool(const char *key)
{
	if (g_str_equal(key, CONF_BG_SCAN))
		return connman_settings.bg_scan;

	if (g_str_equal(key, CONF_ALLOW_HOSTNAME_UPDATES))
		return connman_settings.allow_hostname_updates;

	if (g_str_equal(key, CONF_ALLOW_DOMAINNAME_UPDATES))
		return connman_settings.allow_domainname_updates;

	if (g_str_equal(key, CONF_SINGLE_TECH))
		return connman_settings.single_tech;

	if (g_str_equal(key, CONF_PERSISTENT_TETHERING_MODE))
		return connman_settings.persistent_tethering_mode;

	if (g_str_equal(key, CONF_ENABLE_6TO4))
		return connman_settings.enable_6to4;

	if (g_str_equal(key, CONF_ENABLE_ONLINE_CHECK))
		return connman_settings.enable_online_check;

	if (g_str_equal(key, CONF_AUTO_CONNECT_ROAMING_SERVICES))
		return connman_settings.auto_connect_roaming_services;

	if (g_str_equal(key, CONF_ACD))
		return connman_settings.acd;

	if (g_str_equal(key, CONF_USE_GATEWAYS_AS_TIMESERVERS))
		return connman_settings.use_gateways_as_timeservers;

#if defined TIZEN_EXT
	if (g_str_equal(key, CONF_ENABLE_AUTO_IP))
		return connman_settings.auto_ip;

	if (g_str_equal(key, CONF_CONNMAN_SUPPLICANT_DEBUG))
		return connman_settings.supplicant_debug;
#endif

#if defined TIZEN_EXT
	if (g_str_equal(key, CONF_INS_LAST_CONNECTED_BSSID))
		return connman_ins_settings.ins_last_connected_bssid;

	if (g_str_equal(key, CONF_INS_ASSOC_REJECT))
		return connman_ins_settings.ins_assoc_reject;

	if (g_str_equal(key, CONF_INS_SIGNAL_BSSID))
		return connman_ins_settings.ins_signal_bssid;

	if (g_str_equal(key, CONF_INS_LAST_USER_SELECTION))
		return connman_ins_settings.ins_last_user_selection;

	if (g_str_equal(key, CONF_INS_LAST_CONNECTED))
		return connman_ins_settings.ins_last_connected;

	if (g_str_equal(key, CONF_INS_SIGNAL))
		return connman_ins_settings.ins_signal;

	if (g_str_equal(key, CONF_INS_INTERNET))
		return connman_ins_settings.ins_internet;
#endif

	return false;
}

#if defined TIZEN_EXT
unsigned int connman_setting_get_uint(const char *key)
{
	if (g_str_equal(key, CONF_INS_PREFERRED_FREQ_BSSID_SCORE))
		return connman_ins_settings.ins_preferred_freq_bssid_score;

	if (g_str_equal(key, CONF_INS_LAST_CONNECTED_BSSID_SCORE))
		return connman_ins_settings.ins_last_connected_bssid_score;

	if (g_str_equal(key, CONF_INS_ASSOC_REJECT_SCORE))
		return connman_ins_settings.ins_assoc_reject_score;

	if (g_str_equal(key, CONF_INS_LAST_USER_SELECTION_TIME))
		return connman_ins_settings.ins_last_user_selection_time;

	if (g_str_equal(key, CONF_INS_SECURITY_PRIORITY_COUNT))
		return connman_ins_settings.ins_security_priority_count;

	if (g_str_equal(key, CONF_INS_LAST_USER_SELECTION_SCORE))
		return connman_ins_settings.ins_last_user_selection_score;

	if (g_str_equal(key, CONF_INS_LAST_CONNECTED_SCORE))
		return connman_ins_settings.ins_last_connected_score;

	if (g_str_equal(key, CONF_INS_PREFERRED_FREQ_SCORE))
		return connman_ins_settings.ins_preferred_freq_score;

	if (g_str_equal(key, CONF_INS_SECURITY_PRIORITY_SCORE))
		return connman_ins_settings.ins_security_priority_score;

	if (g_str_equal(key, CONF_INS_INTERNET_SCORE))
		return connman_ins_settings.ins_internet_score;

	return 0;
}

int connman_setting_get_int(const char *key)
{
	if (g_str_equal(key, CONF_INS_SIGNAL_LEVEL3_5GHZ))
		return connman_ins_settings.ins_signal_level3_5ghz;

	if (g_str_equal(key, CONF_INS_SIGNAL_LEVEL3_24GHZ))
		return connman_ins_settings.ins_signal_level3_24ghz;

	return 0;
}
#endif

char **connman_setting_get_string_list(const char *key)
{
	if (g_str_equal(key, CONF_PREF_TIMESERVERS))
		return connman_settings.pref_timeservers;

	if (g_str_equal(key, CONF_FALLBACK_NAMESERVERS))
		return connman_settings.fallback_nameservers;

	if (g_str_equal(key, CONF_BLACKLISTED_INTERFACES))
		return connman_settings.blacklisted_interfaces;

	if (g_str_equal(key, CONF_TETHERING_TECHNOLOGIES))
		return connman_settings.tethering_technologies;

#if defined TIZEN_EXT
	if (g_str_equal(key, CONF_CELLULAR_INTERFACE))
		return connman_settings.cellular_interfaces;
#endif

#if defined TIZEN_EXT
	if (g_str_equal(key, CONF_INS_SECURITY_PRIORITY))
		return connman_ins_settings.ins_security_priority;
#endif

	return NULL;
}

unsigned int *connman_setting_get_uint_list(const char *key)
{
	if (g_str_equal(key, CONF_AUTO_CONNECT_TECHS))
		return connman_settings.auto_connect;

	if (g_str_equal(key, CONF_FAVORITE_TECHS))
		return connman_settings.favorite_techs;

	if (g_str_equal(key, CONF_PREFERRED_TECHS))
		return connman_settings.preferred_techs;

	if (g_str_equal(key, CONF_ALWAYS_CONNECTED_TECHS))
		return connman_settings.always_connected_techs;

	return NULL;
}

unsigned int connman_timeout_input_request(void)
{
	return connman_settings.timeout_inputreq;
}

unsigned int connman_timeout_browser_launch(void)
{
	return connman_settings.timeout_browserlaunch;
}

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	DBusConnection *conn;
	DBusError err;
	guint signal;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_version) {
		printf("%s\n", VERSION);
		exit(0);
	}

	if (option_detach) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	if (mkdir(STORAGEDIR, S_IRUSR | S_IWUSR | S_IXUSR |
				S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
		if (errno != EEXIST)
			perror("Failed to create storage directory");
	}

	umask(0077);

	main_loop = g_main_loop_new(NULL, FALSE);

	signal = setup_signalfd();

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, CONNMAN_SERVICE, &err);
	if (!conn) {
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with system bus\n");
		exit(1);
	}

	g_dbus_set_disconnect_function(conn, disconnect_callback, NULL, NULL);

	__connman_log_init(argv[0], option_debug, option_detach,
			option_backtrace, "Connection Manager", VERSION);

	__connman_dbus_init(conn);

	if (!option_config)
		config_init(CONFIGMAINFILE);
	else
		config_init(option_config);

	__connman_util_init();
	__connman_inotify_init();
	__connman_technology_init();
	__connman_notifier_init();
	__connman_agent_init();
	__connman_service_init();
	__connman_peer_service_init();
	__connman_peer_init();
#if defined TIZEN_EXT_WIFI_MESH
	__connman_mesh_init();
#endif /* TIZEN_EXT_WIFI_MESH */
	__connman_provider_init();
	__connman_network_init();
	__connman_config_init();
	__connman_device_init(option_device, option_nodevice);

	__connman_ippool_init();
	__connman_firewall_init();
	__connman_nat_init();
	__connman_tethering_init();
	__connman_counter_init();
	__connman_manager_init();
	__connman_stats_init();
	__connman_clock_init();

	__connman_ipconfig_init();
	__connman_rtnl_init();
	__connman_task_init();
	__connman_proxy_init();
	__connman_detect_init();
	__connman_session_init();
	__connman_timeserver_init();
	__connman_connection_init();

	__connman_plugin_init(option_plugin, option_noplugin);

	__connman_resolver_init(option_dnsproxy);
	__connman_rtnl_start();
	__connman_dhcp_init();
	__connman_dhcpv6_init();
	__connman_wpad_init();
	__connman_wispr_init();
#if !defined TIZEN_EXT
	__connman_rfkill_init();
	__connman_machine_init();
#endif

	g_free(option_config);
	g_free(option_device);
	g_free(option_plugin);
	g_free(option_nodevice);
	g_free(option_noplugin);

	g_main_loop_run(main_loop);

	g_source_remove(signal);

#if !defined TIZEN_EXT
	__connman_machine_cleanup();
	__connman_rfkill_cleanup();
#endif
	__connman_wispr_cleanup();
	__connman_wpad_cleanup();
	__connman_dhcpv6_cleanup();
	__connman_session_cleanup();
	__connman_plugin_cleanup();
	__connman_provider_cleanup();
	__connman_connection_cleanup();
	__connman_timeserver_cleanup();
	__connman_detect_cleanup();
	__connman_proxy_cleanup();
	__connman_task_cleanup();
	__connman_rtnl_cleanup();
	__connman_resolver_cleanup();

	__connman_clock_cleanup();
	__connman_stats_cleanup();
	__connman_config_cleanup();
	__connman_manager_cleanup();
	__connman_counter_cleanup();
	__connman_tethering_cleanup();
	__connman_nat_cleanup();
	__connman_firewall_cleanup();
	__connman_peer_service_cleanup();
	__connman_peer_cleanup();
#if defined TIZEN_EXT_WIFI_MESH
	__connman_mesh_cleanup();
#endif /* TIZEN_EXT_WIFI_MESH */
	__connman_ippool_cleanup();
	__connman_device_cleanup();
	__connman_network_cleanup();
	__connman_dhcp_cleanup();
	__connman_service_cleanup();
	__connman_agent_cleanup();
	__connman_ipconfig_cleanup();
	__connman_notifier_cleanup();
	__connman_technology_cleanup();
	__connman_inotify_cleanup();

	__connman_util_cleanup();
	__connman_dbus_cleanup();

	__connman_log_cleanup(option_backtrace);

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	if (connman_settings.pref_timeservers)
		g_strfreev(connman_settings.pref_timeservers);

	g_free(connman_settings.auto_connect);
	g_free(connman_settings.favorite_techs);
	g_free(connman_settings.preferred_techs);
	g_strfreev(connman_settings.fallback_nameservers);
	g_strfreev(connman_settings.blacklisted_interfaces);
	g_strfreev(connman_settings.tethering_technologies);

#if defined TIZEN_EXT
	g_free(connman_ins_settings.ins_preferred_freq_bssid);
	g_free(connman_ins_settings.ins_preferred_freq);
	if (connman_ins_settings.ins_security_priority)
		g_strfreev(connman_ins_settings.ins_security_priority);
#endif

	g_free(option_debug);
	g_free(option_wifi);

	return 0;
}
