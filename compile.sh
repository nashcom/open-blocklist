#!/bin/bash
############################################################################
# Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE
############################################################################

GO_BUILD_TAGS=""

log_error_exit()
{
  echo
  echo "ERROR: $@"
  echo
  exit 1
}

usage()
{
  echo
  echo "Usage: $(basename $0) [options]"
  echo
  echo "Options"
  echo "-------"
  echo
  echo "-pprof      enable pprof profiling endpoint"
  echo "-unittest   enable built-in unit tests (run before startup)"
  echo
  echo "Options can be combined: $(basename $0) -pprof -unittest"
  echo
}

add_build_tag()
{
  if [ -z "$GO_BUILD_TAGS" ]; then
    GO_BUILD_TAGS="-tags $1"
  else
    GO_BUILD_TAGS="$GO_BUILD_TAGS,$1"
  fi
}

for a in "$@"; do

  p=$(echo "$a" | awk '{print tolower($0)}')

  case "$p" in

    -pprof)
      add_build_tag pprof
      ;;

    -unittest)
      add_build_tag unittest
      ;;

    -h|/h|-\?|/\?|-help|--help|help|usage)
      usage
      exit 0
      ;;

    *)
      log_error_exit "Invalid parameter [$a]"
      ;;
  esac
done

docker run --rm -v "$PWD/src":/src -v "$PWD/bin":/bin -w /src golang:alpine go build $GO_BUILD_TAGS -trimpath -ldflags="-s -w -X main.gBuildPlatform=alpine" -o /bin/open-blocklist
