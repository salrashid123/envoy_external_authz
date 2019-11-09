package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"

	"golang.org/x/net/http2"
)

var ()

func fronthandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/ called")
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))
	w.Header().Set("X-Custom-Header-From-Backend", "from backend")
	fmt.Fprint(w, "ok")
}

func main() {

	http.HandleFunc("/", fronthandler)

	var server *http.Server
	server = &http.Server{
		Addr: ":11000",
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	server.ListenAndServe()
}
