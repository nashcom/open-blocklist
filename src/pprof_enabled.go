//go:build pprof
package main

import (
    _ "net/http/pprof"
    "net/http"
)

func initPprof() {
    go http.ListenAndServe(gProfileListener, nil)
}
