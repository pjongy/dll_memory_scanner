package main

import "C"
import (
	"fmt"
	"runtime"
	"syscall"
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	allocConsole        = kernel32.NewProc("AllocConsole")
	freeConsole         = kernel32.NewProc("FreeConsole")
	virtualQuery        = kernel32.NewProc("VirtualQuery")
	virtualProtect      = kernel32.NewProc("VirtualProtect")
	getCurrentProcess   = kernel32.NewProc("GetCurrentProcess")
	getCurrentProcessId = kernel32.NewProc("GetCurrentProcessId")
)

// Memory constants
const (
	MEM_COMMIT             = 0x1000
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80
	PAGE_GUARD             = 0x100
)

// CommandHandler interface for processing commands
type CommandHandler interface {
	HandleCommand(cmd string, args []string) bool
	GetHelp() map[string]string
}

// init function is automatically executed when DLL is loaded
func init() {
	// Run in a goroutine to avoid blocking the main thread
	go func() {
		// Free any existing console, then create a new one
		freeConsole.Call()
		r, _, _ := allocConsole.Call()
		if r == 0 {
			return
		}

		fmt.Println("DLL loaded and initialized!")

		// Start CLI receiver
		receiver := NewCommandReceiver()

		// Add command handlers
		receiver.AddHandler(&DefaultCommandHandler{})
		receiver.AddHandler(NewMemoryScannerCommandHandler())

		receiver.Start()
	}()
}

func main() {
	// This function is not executed in DLL mode, but is required
	runtime.LockOSThread()
	select {} // Wait forever
}
