//go:build windows

package main

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/jchv/go-webview2"
)

func runNativeGUI(initialPath string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("Error initializing local GUI bridge: %v\n", err)
		return
	}
	port := listener.Addr().(*net.TCPAddr).Port

	setupRoutes()

	server := &http.Server{}
	go func() {
		_ = server.Serve(listener)
	}()

	w := webview2.New(false)
	if w == nil {
		fmt.Println("Error: WebView2 native desktop engine failed to initialize.")
		return
	}
	defer w.Destroy()

	w.SetTitle("ProDiscover Basic - [Project - Suspect Evidence]")
	w.SetSize(1280, 880, webview2.HintNone)

	guiURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	if initialPath != "" {
		guiURL += "?path=" + initialPath
	}
	w.Navigate(guiURL)

	w.Run()

	_ = server.Close()
	os.Exit(0)
}
