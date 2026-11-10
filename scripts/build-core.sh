#!/usr/bin/env bash
# This file keeps its declarations with the functions they describe.
# dyshellint disable=BSG033
# @file build-core.sh
# @brief Build the dybw-core WASM module the plugin embeds
# @description Builds dybw-core's WASM module into `vendor/dybw-core`, where esbuild and the tests read it. The core
#              comes from `DYBW_CORE_DIR` (a local checkout, used as it is) or from a clone of `DYBW_CORE_URL` at the
#              commit pinned in `core.rev`. The core's own `scripts/build-wasm.sh` does the build, so it needs what that
#              script needs: Rust 1.99.1 with the wasm32 target, wasm-bindgen 0.2.129, binaryen version_133
#              (`WASM_OPT`), node and npm, and dybatpho at `DYBATPHO_DIR`.
SCRIPT_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
ROOT="$(dirname "${SCRIPT_DIR}")"
: "${DYBATPHO_DIR:=${HOME}/Working/personal/tools/dybatpho}"
export DYBATPHO_DIR
# shellcheck source=/dev/null
. "${DYBATPHO_DIR}/init.sh" --modules cli || exit 1

dybatpho::register_common_handlers

: "${DYBW_CORE_DIR:=}"
: "${DYBW_CORE_URL:=https://gitlab.com/dynamo-tools/dybw-core.git}"
OUT="${ROOT}/vendor/dybw-core"
# The core checkout, set by _main or _clone.
SRC=""

# @description Points `SRC` at a clone of the core in `vendor/` at the pinned commit, cloning it when needed.
# @arg $1 string The pinned commit
function _clone {
  local rev
  dybatpho::expect_args rev -- "$@"
  SRC="${ROOT}/vendor/dybw-core-src"
  if [[ ! -d "${SRC}/.git" ]]; then
    dybatpho::info "Cloning ${DYBW_CORE_URL}"
    git clone --quiet --no-checkout "${DYBW_CORE_URL}" "${SRC}" || dybatpho::die "Cannot clone ${DYBW_CORE_URL}"
  fi
  if ! git -C "${SRC}" cat-file -e "${rev}^{commit}" 2> /dev/null; then
    git -C "${SRC}" fetch --quiet origin || dybatpho::die "Cannot fetch ${DYBW_CORE_URL}"
  fi
  git -C "${SRC}" checkout --quiet --detach "${rev}" || dybatpho::die "The core has no commit ${rev}"
}

# @description Finds the core, installs the harness packages its size report needs, and builds the module.
# @noargs
function _main {
  dybatpho::require git
  dybatpho::require npm
  local _rev _head
  _rev="$(< "${ROOT}/core.rev")" || dybatpho::die "Cannot read core.rev"
  if [[ -n "${DYBW_CORE_DIR}" ]]; then
    SRC="$(realpath "${DYBW_CORE_DIR}")" || dybatpho::die "No core at ${DYBW_CORE_DIR}"
    _head="$(git -C "${SRC}" rev-parse HEAD)" || dybatpho::die "Not a git checkout: ${SRC}"
    [[ "${_head}" == "${_rev}" ]] || dybatpho::warn "${SRC} is at ${_head}, core.rev pins ${_rev}"
  else
    _clone "${_rev}"
  fi

  local _js="${SRC}/crates/dybw-core-wasm/js"
  if [[ ! -d "${_js}/node_modules" ]]; then
    dybatpho::info "Installing the core harness packages (esbuild for the size report)"
    npm ci --ignore-scripts --prefix "${_js}" || dybatpho::die "npm ci failed in ${_js}"
  fi
  "${SRC}/scripts/build-wasm.sh" --out "${OUT}"
  dybatpho::success "Built the core at ${_rev} into ${OUT}"
}

# @description The option spec of the build.
# @noargs
function _spec {
  dybatpho::opts::setup "Build the dybw-core WASM module into vendor/dybw-core" ARGS action:"_main"
  dybatpho::opts::disp "Show help" --help -h action:"dybatpho::generate_help _spec"
}

dybatpho::generate_from_spec _spec "$@"
