package main

import (
	"fmt"
	"strings"
)

// DefaultCommandHandler provides basic command functionality
type DefaultCommandHandler struct{}

func (h *DefaultCommandHandler) HandleCommand(cmd string, args []string) bool {
	switch cmd {
	case "help":
		fmt.Println("Available commands:")
		for cmd, desc := range h.GetHelp() {
			fmt.Printf("  %-10s - %s\n", cmd, desc)
		}
		return true
	case "exit":
		fmt.Println("Exiting program...")
		return false
	case "echo":
		fmt.Println(strings.Join(args, " "))
		return true
	case "info":
		pid, _, _ := getCurrentProcessId.Call()
		fmt.Printf("Process ID: %d\n", pid)
		return true
	default:
		return true // Pass to next handler
	}
}

func (h *DefaultCommandHandler) GetHelp() map[string]string {
	return map[string]string{
		"help": "Display available commands",
		"exit": "Exit program",
		"echo": "Display the provided text",
		"info": "Display process information",
	}
}
