package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func complexHandler(w http.ResponseWriter, r *http.Request) {
	// 1. SSRF
	// Source
	urls, _ := r.URL.Query()["url"]
	if len(urls) > 0 {
		target := urls[0]
		// Sink
		http.Get(target)
	}

	// 2. Path Traversal
	files, _ := r.URL.Query()["file"]
	if len(files) > 0 {
		filename := files[0]
		// Sink
		os.Open(filename)
		// Another Sink
		ioutil.ReadFile(filename)
	}

	// 3. XSS
	inputs, _ := r.URL.Query()["input"]
	if len(inputs) > 0 {
		userInput := inputs[0]
		// Sink
		w.Write([]byte(userInput))
		fmt.Fprintf(w, "Hello %s", userInput)
	}
}
