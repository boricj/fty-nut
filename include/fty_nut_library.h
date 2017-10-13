/*  =========================================================================
    fty-nut - generated layer of public API

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

################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
    =========================================================================
*/

#ifndef FTY_NUT_LIBRARY_H_INCLUDED
#define FTY_NUT_LIBRARY_H_INCLUDED

//  Set up environment for the application

//  External dependencies
#include <czmq.h>
#include <malamute.h>
#include <ftyproto.h>
#include <libcidr.h>
#include <cxxtools/allocator.h>
#include <nutclient.h>

//  FTY_NUT version macros for compile-time API detection
#define FTY_NUT_VERSION_MAJOR 1
#define FTY_NUT_VERSION_MINOR 0
#define FTY_NUT_VERSION_PATCH 0

#define FTY_NUT_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))
#define FTY_NUT_VERSION \
    FTY_NUT_MAKE_VERSION(FTY_NUT_VERSION_MAJOR, FTY_NUT_VERSION_MINOR, FTY_NUT_VERSION_PATCH)

#if defined (__WINDOWS__)
#   if defined FTY_NUT_STATIC
#       define FTY_NUT_EXPORT
#   elif defined FTY_NUT_INTERNAL_BUILD
#       if defined DLL_EXPORT
#           define FTY_NUT_EXPORT __declspec(dllexport)
#       else
#           define FTY_NUT_EXPORT
#       endif
#   elif defined FTY_NUT_EXPORTS
#       define FTY_NUT_EXPORT __declspec(dllexport)
#   else
#       define FTY_NUT_EXPORT __declspec(dllimport)
#   endif
#   define FTY_NUT_PRIVATE
#else
#   define FTY_NUT_EXPORT
#   if (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
#       define FTY_NUT_PRIVATE __attribute__ ((visibility ("hidden")))
#   else
#       define FTY_NUT_PRIVATE
#   endif
#endif

//  Opaque class structures to allow forward references
//  These classes are stable or legacy and built in all releases
typedef struct _fty_nut_server_t fty_nut_server_t;
#define FTY_NUT_SERVER_T_DEFINED
typedef struct _fty_nut_configurator_server_t fty_nut_configurator_server_t;
#define FTY_NUT_CONFIGURATOR_SERVER_T_DEFINED
typedef struct _alert_actor_t alert_actor_t;
#define ALERT_ACTOR_T_DEFINED
typedef struct _sensor_actor_t sensor_actor_t;
#define SENSOR_ACTOR_T_DEFINED


//  Public classes, each with its own header file
#include "fty_nut_server.h"
#include "fty_nut_configurator_server.h"
#include "alert_actor.h"
#include "sensor_actor.h"

#ifdef FTY_NUT_BUILD_DRAFT_API
//  Self test for private classes
FTY_NUT_EXPORT void
    fty_nut_private_selftest (bool verbose);
#endif // FTY_NUT_BUILD_DRAFT_API

#endif
/*
################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
*/
