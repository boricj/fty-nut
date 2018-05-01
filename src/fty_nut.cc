/*  =========================================================================
    fty_nut - NUT (Network UPS Tools) daemon wrapper/proxy

    Copyright (C) 2014 - 2017 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
 */

/*
@header
    fty_nut - fty-nut main
@discuss
@end
 */

#include "fty_nut_server.h"
#include "sensor_actor.h"
#include "alert_actor.h"
#include "ftyproto.h"
#include "nut_mlm.h"
#include "logger.h"

#include <getopt.h>
#include <stdio.h>
#include <czmq.h>
#include <string>

#define str(x) #x

#define DEFAULT_LOG_LEVEL LOG_WARNING

void usage() {
    puts("fty-nut [options] ...\n"
            "  --log-level / -l       bios log level\n"
            "                         overrides setting in env. variable BIOS_LOG_LEVEL\n"
            "  --config / -c          path to config file\n"
            "  --mapping-file / -m    NUT-to-BIOS mapping file\n"
            "  --state-file / -s      state file\n"
            "  --polling / -p         polling interval in seconds [30]\n"
            "  --verbose / -v         verbose test output\n"
            "  --help / -h            this information\n"
            );
}

int get_log_level(const char *level) {
    if (streq(level, str(LOG_DEBUG))) {
        return LOG_DEBUG;
    } else
        if (streq(level, str(LOG_INFO))) {
        return LOG_INFO;
    } else
        if (streq(level, str(LOG_WARNING))) {
        return LOG_WARNING;
    } else
        if (streq(level, str(LOG_ERR))) {
        return LOG_ERR;
    } else
        if (streq(level, str(LOG_CRIT))) {
        return LOG_CRIT;
    }
    return -1;
}

int main(int argc, char *argv []) {
    int help = 0;
    bool verbose = false;
    int log_level = -1;
    std::string mapping_file;
    std::string state_file;
    const char* polling = NULL;
    const char *config_file = "/etc/fty-nut/fty-nut.cfg";
    zconfig_t *config = NULL;

    // Some systems define struct option with non-"const" "char *"
#if defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wwrite-strings"
#endif
    static const char *short_options = "hvl:m:p:s:c:";
    static struct option long_options[] = {
        {"help", no_argument, 0, 1},
        {"verbose", no_argument, 0, 1},
        {"log-level", required_argument, 0, 'l'},
        {"config", required_argument, 0, 'c'},
        {"mapping-file", required_argument, 0, 'm'},
        {"state-file", required_argument, 0, 's'},
        {"polling", required_argument, 0, 'p'},
        {NULL, 0, 0, 0}
    };
#if defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostic pop
#endif

    while (true) {
        int option_index = 0;
        int c = getopt_long(argc, argv, short_options, long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
            case 'l':
            {
                log_level = get_log_level(optarg);
                break;
            }
            case 'c':
            {
                config_file = optarg;
                break;
            }
            case 'm':
            {
                mapping_file.assign(optarg);
                break;
            }
            case 's':
            {
                state_file.assign(optarg);
                break;
            }
            case 'v':
            {
                verbose = true;
                log_level = LOG_DEBUG;
                break;
            }
            case 'p':
            {
                if (!optarg) {
                    printf("invalid polling interval '%s'\n", optarg);
                    return EXIT_FAILURE;
                }
                polling = optarg;
                break;
            }
            case 'h':
            default:
            {
                help = 1;
                break;
            }
        }
    }
    if (help) {
        usage();
        return EXIT_FAILURE;
    }

    // Process configuration file
    config = zconfig_load(config_file);
    if (!config) {
        zsys_error("Failed to load config file %s", config_file);
        exit(EXIT_FAILURE);
    }
    // VERBOSE
    if (streq(zconfig_get(config, "server/verbose", "false"), "true")) {
        verbose = true;
    }
    // POLLING
    polling = zconfig_get(config, CONFIG_POLLING, "30");

    // log_level cascade (priority ascending)
    //  1. default value
    //  2. env. variable
    //  3. command line argument
    //  4. actor message - NOT IMPLEMENTED SO FAR
    if (log_level == -1) {
        char *env_log_level = getenv("BIOS_LOG_LEVEL");
        if (env_log_level) {
            log_level = get_log_level(env_log_level);
            if (log_level == -1)
                log_level = DEFAULT_LOG_LEVEL;
        } else {
            log_level = DEFAULT_LOG_LEVEL;
        }
    }
    log_set_level(log_level);

    log_info("fty_nut - NUT (Network UPS Tools) wrapper/daemon");

    zactor_t *nut_server = zactor_new(fty_nut_server, MLM_ENDPOINT_VOID);
    if (!nut_server) {
        log_critical("zactor_new (task = 'fty_nut_server', args = 'NULL') failed");
        return -1;
    }

    zactor_t *nut_device_alert = zactor_new(alert_actor, MLM_ENDPOINT_VOID);
    if (!nut_device_alert) {
        log_critical("zactor_new (task = 'nut_device_server', args = 'NULL') failed");
        return -1;
    }

    zactor_t *nut_sensor = zactor_new(sensor_actor, MLM_ENDPOINT_VOID);
    if (!nut_sensor) {
        log_critical("zactor_new (task = 'nut_sensor', args = 'NULL') failed");
        return -1;
    }

    if (verbose) {
        zstr_sendx(nut_server, "VERBOSE", NULL);
        zstr_sendx(nut_device_alert, "VERBOSE", NULL);
        zstr_sendx(nut_sensor, "VERBOSE", NULL);
    }
    zstr_sendx(nut_server, ACTION_CONFIGURE, mapping_file.c_str(), state_file.c_str(), NULL);
    zstr_sendx(nut_server, ACTION_POLLING, polling, NULL);

    zstr_sendx(nut_device_alert, ACTION_POLLING, polling, NULL);

    zstr_sendx(nut_sensor, ACTION_POLLING, polling, NULL);

    zpoller_t *poller = zpoller_new(nut_server, nut_device_alert, nut_sensor, NULL);
    assert(poller);

    while (!zsys_interrupted) {
        void *which = zpoller_wait(poller, 10000);
        if (which) {
            char *message = zstr_recv(which);
            if (message) {
                puts(message);
                zstr_free(&message);
            }
        } else {
            if (zpoller_terminated(poller)) {
                break;
            }
        }

        if (zconfig_has_changed(config)) {
            log_debug("Config file has changed, reload config and propagate polling value");
            zconfig_destroy(&config);
            config = zconfig_load(config_file);
            if (config) {
                polling = zconfig_get(config, CONFIG_POLLING, "30");
                zstr_sendx(nut_server, ACTION_POLLING, polling, NULL);
                zstr_sendx(nut_device_alert, ACTION_POLLING, polling, NULL);
                zstr_sendx(nut_sensor, ACTION_POLLING, polling, NULL);
            } else {
                zsys_error("Failed to load config file %s", config_file);
                break;
            }
        }
    }

    zpoller_destroy(&poller);
    zactor_destroy(&nut_server);
    zactor_destroy(&nut_device_alert);
    zactor_destroy(&nut_sensor);
    if (config) {
        zconfig_destroy(&config);
    }
    return 0;
}
