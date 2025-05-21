//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
	"time"
)

func main() {
	fmt.Println("Loading DLL...")

	// Load the DLL
	handle, err := syscall.LoadLibrary("mymodule.dll")
	if err != nil {
		fmt.Printf("Error loading library: %v\n", err)
		return
	}
	defer syscall.FreeLibrary(handle)

	fmt.Println("DLL loaded successfully! Handle:", handle)
	fmt.Println("Keep this window open to use the DLL console.")

	// Keep the program running
	for {
		time.Sleep(1 * time.Hour)
	}
}
