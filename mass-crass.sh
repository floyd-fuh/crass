#!/bin/bash -i
CRASS_DIR="$(pwd -L)"

goto_fail () {

  if [[ $# -lt 2 ]]; then
    printf "usage:\t$0 CRASS_OUT_BASEDIR SOURCE...\n"
    printf "\t\tCRASS_OUT_BASEDIR\tParent of the set of well-directories containing CRASS grep results\n"
    printf "\t\tSOURCE...\tDirectories to grep using CRASS\n"
  fi

  local CRASS_OUT_BASEDIR="${1%/}"

  while :; do
    shift
    if [[ $# -le 0 ]]; then
      exit 0
    fi
    local SOURCE="${1%/}"
    local SOURCENAME="$(basename $SOURCE)"
    local CRASS_OUT="${CRASS_OUT_BASEDIR}/${SOURCENAME}__CRASS"
    mkdir -vp "$CRASS_OUT"
    local SOURCE_MODIFIED="$SOURCE-modified"

    printf "\n--------------------------------------------------------------------------------\n"
    printf "SOURCE:    ${SOURCE}\n"
    printf "CRASS_OUT: ${CRASS_OUT}\n"
    printf " --------------------------------------------------------------------------------\n\n"

    rm -rf "$SOURCE_MODIFIED"
    cp -r "$SOURCE" "$SOURCE_MODIFIED"

    echo "[+] Invoking ./bloat-it.sh \"$SOURCE_MODIFIED\""
    ./bloat-it.sh "$SOURCE_MODIFIED"

    echo "[+] Invoking ./clean-it.sh \"$SOURCE_MODIFIED\""
    ./clean-it.sh "$SOURCE_MODIFIED"

    echo "[+] Forking into ./grep-it.sh \"$SOURCE_MODIFIED\""
    ( ./grep-it.sh "$SOURCE_MODIFIED" "$CRASS_OUT"  >| "${CRASS_OUT_BASEDIR}/${SOURCENAME}.grepout" 2>&1; rm -rf "$SOURCE_MODIFIED" ) &

    disown %

  done
}

goto_fail "$@"


