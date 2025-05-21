package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// CommandReceiver handles the command line interface
type CommandReceiver struct {
	handlers []CommandHandler
	running  bool
}

func NewCommandReceiver() *CommandReceiver {
	return &CommandReceiver{
		handlers: []CommandHandler{},
		running:  false,
	}
}

func (r *CommandReceiver) AddHandler(handler CommandHandler) {
	r.handlers = append(r.handlers, handler)
}

func (r *CommandReceiver) Start() {
	r.running = true
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("Interactive shell started. Type 'help' to see available commands.")
	fmt.Print("> ")

	for scanner.Scan() && r.running {
		input := scanner.Text()
		parts := strings.Fields(input)

		if len(parts) > 0 {
			cmd := parts[0]
			args := parts[1:]

			continueRunning := true

			for _, handler := range r.handlers {
				if handlerResult := handler.HandleCommand(cmd, args); !handlerResult {
					continueRunning = false
					break
				}
			}

			if !continueRunning {
				r.running = false
			}
		}

		if r.running {
			fmt.Print("> ")
		}
	}
}

func (r *CommandReceiver) Stop() {
	r.running = false
}
