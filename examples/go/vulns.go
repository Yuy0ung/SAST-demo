package main

import (
	"net/http"
)

func complexHandler(w http.ResponseWriter, r *http.Request) {
	// 1. SSRF
	// Source
	urls, _ := r.URL.Query()["url"]
	if len(urls) > 0 {
		target := urls[0]
		//sink
		http.Get(target)
	}
}
