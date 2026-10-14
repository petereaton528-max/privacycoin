#!/bin/sh
# Experimental public-admission development client. No network/mining at launch.
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 petereaton528-max
set -eu
umask 077
APP=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
unset PYTHONPATH PYTHONSTARTUP PYTHONINSPECT PYTHONSAFEPATH PYTHONPLATLIBDIR PYTHONUSERBASE PYTHONEXECUTABLE PYTHONOPTIMIZE PYTHONVERBOSE PYTHONWARNINGS PYTHONPYCACHEPREFIX PYTHONHOME
export PC_DEVELOPMENT_NETWORK=open-dev02
export PYTHONHOME="$APP/runtime/python"
export PYTHONNOUSERSITE=1
export LD_LIBRARY_PATH="$APP/runtime/lib"
export TCL_LIBRARY="$APP/runtime/tcltk/tcl8.6"
export TK_LIBRARY="$APP/runtime/tcltk/tk8.6"
export PATH="$APP/runtime/bin:/usr/bin:/bin"
cd -- "$APP"
exec "$APP/runtime/python/bin/python3" -B -m apps.network_v1.desktop "$@"
