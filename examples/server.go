// Copyright 2014 Jamie Hall. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"net/http"

	"github.com/SlyMarbo/spdy"
)

func httpHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example server.\n"))
}

func main() {
	// spdy.EnableDebugOutput()
	http.HandleFunc("/", httpHandler)
	log.Printf("About to listen on 10443. Go to https://127.0.0.1:10443/")
	err := spdy.ListenAndServeSpdyOnly(":10443", "cert.pem", "key.pem", nil)
	if err != nil {
		log.Fatal(err)
	}
}
