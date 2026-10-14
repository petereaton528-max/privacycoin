#!/bin/sh
# Private-pipe backend for the explicitly labeled Windows/WSL2 compatibility UI.
set -eu
umask 077
APP=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
unset PYTHONPATH PYTHONSTARTUP PYTHONINSPECT PYTHONSAFEPATH PYTHONPLATLIBDIR PYTHONUSERBASE PYTHONEXECUTABLE PYTHONOPTIMIZE PYTHONVERBOSE PYTHONWARNINGS PYTHONPYCACHEPREFIX PYTHONHOME
export PYTHONHOME="$APP/runtime/python"
export PYTHONNOUSERSITE=1
export LD_LIBRARY_PATH="$APP/runtime/lib"
export TCL_LIBRARY="$APP/runtime/tcltk/tcl8.6"
export TK_LIBRARY="$APP/runtime/tcltk/tk8.6"
export PATH="$APP/runtime/bin:/usr/bin:/bin"
cd -- "$APP"
if [ ! -x "$APP/runtime/python/bin/python3" ]; then
    printf '%s\n' 'Verified bundled backend missing; install the current dependency-inclusive WSL2/Linux package.' >&2
    exit 1
fi
exec "$APP/runtime/python/bin/python3" -B -m apps.network_v1.desktop_backend "$@"
