//go:build !windows

package main

func runNativeGUI(initialPath string) {
	handleServe([]string{"8080"})
}
