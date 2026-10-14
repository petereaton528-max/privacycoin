#!/bin/sh
set -eu
umask 077
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONHOME="$HERE/runtime/python"
export PYTHONNOUSERSITE=1
export LD_LIBRARY_PATH="$HERE/runtime/lib"
export TCL_LIBRARY="$HERE/runtime/tcltk/tcl8.6"
export TK_LIBRARY="$HERE/runtime/tcltk/tk8.6"
cd "$HERE"
exec "$HERE/runtime/python/bin/python3" -B -m apps.network_v1.production_gui "$@"
