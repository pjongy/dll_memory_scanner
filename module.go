package main

import "C"
import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
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
)

// MEMORY_BASIC_INFORMATION structure
type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

// MemoryScanner handles memory scanning operations
type MemoryScanner struct {
	memoryRegions []MEMORY_BASIC_INFORMATION
	results       []uintptr
	processHandle uintptr
	processID     uint32
}

func NewMemoryScanner() *MemoryScanner {
	handle, _, _ := getCurrentProcess.Call()
	id, _, _ := getCurrentProcessId.Call()
	
	return &MemoryScanner{
		memoryRegions: []MEMORY_BASIC_INFORMATION{},
		results:       []uintptr{},
		processHandle: handle,
		processID:     uint32(id),
	}
}

// ParseHexPattern parses a hex string with wildcards
// Returns the byte pattern and a mask where 0 = wildcard, 1 = match exact byte
func ParseHexPattern(hexStr string) ([]byte, []byte, error) {
	// Remove spaces
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	
	if len(hexStr)%2 != 0 {
		return nil, nil, fmt.Errorf("hex pattern must have an even number of characters")
	}
	
	// Calculate result length
	length := len(hexStr) / 2
	pattern := make([]byte, length)
	mask := make([]byte, length)
	
	for i := 0; i < length; i++ {
		hexByte := hexStr[i*2 : i*2+2]
		
		if hexByte == "??" {
			// Wildcard - use 0 in pattern (doesn't matter) and 0 in mask
			pattern[i] = 0
			mask[i] = 0
		} else {
			// Regular hex byte
			b, err := hex.DecodeString(hexByte)
			if err != nil {
				return nil, nil, err
			}
			pattern[i] = b[0]
			mask[i] = 1 // Indicate this byte must match exactly
		}
	}
	
	return pattern, mask, nil
}

// EnumerateMemoryRegions finds all readable memory regions
func (scanner *MemoryScanner) EnumerateMemoryRegions() error {
	scanner.memoryRegions = []MEMORY_BASIC_INFORMATION{}
	
	var address uintptr
	for {
		var mbi MEMORY_BASIC_INFORMATION
		ret, _, err := virtualQuery.Call(
			address,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		
		if ret == 0 {
			if err != syscall.Errno(0) {
				// End of enumeration reached
				break
			}
			return err
		}
		
		// Add region if it's committed memory and readable
		if mbi.State&MEM_COMMIT != 0 && isReadable(mbi.Protect) {
			scanner.memoryRegions = append(scanner.memoryRegions, mbi)
		}
		
		// Move to next region
		address = mbi.BaseAddress + mbi.RegionSize
		
		// Break if we've wrapped around (unlikely but possible in 32-bit)
		if address < mbi.BaseAddress {
			break
		}
	}
	
	return nil
}

// isReadable checks if the memory protection allows reading
func isReadable(protect uint32) bool {
	return protect&(PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|
		PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY) != 0
}

// SearchInt32 searches for a 32-bit integer value in memory
func (scanner *MemoryScanner) SearchInt32(value int32) {
	scanner.results = []uintptr{}
	
	// First ensure we have the memory regions
	if len(scanner.memoryRegions) == 0 {
		scanner.EnumerateMemoryRegions()
	}
	
	valueBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueBytes, uint32(value))
	
	for _, region := range scanner.memoryRegions {
		// Read memory region
		buffer := make([]byte, region.RegionSize)
		
		// In the same process, we can directly read memory
		for i := uintptr(0); i < region.RegionSize; i++ {
			// Use defer/recover to handle any access violations
			func() {
				defer func() {
					if r := recover(); r != nil {
						// Memory access failed, skip this address
					}
				}()
				
				// Read byte directly
				if i < region.RegionSize {
					buffer[i] = *(*byte)(unsafe.Pointer(region.BaseAddress + i))
				}
			}()
		}
		
		// Search for value in buffer
		for i := 0; i <= len(buffer)-4; i++ {
			if bytes.Equal(buffer[i:i+4], valueBytes) {
				address := region.BaseAddress + uintptr(i)
				scanner.results = append(scanner.results, address)
			}
		}
	}
}

// FilterInt32 filters previous results with a new int32 value
func (scanner *MemoryScanner) FilterInt32(value int32) {
	if len(scanner.results) == 0 {
		return
	}
	
	newResults := []uintptr{}
	valueBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueBytes, uint32(value))
	
	for _, address := range scanner.results {
		// Use defer/recover to handle any access violations
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Memory access failed, skip this address
				}
			}()
			
			// Read 4 bytes directly
			buffer := make([]byte, 4)
			for i := 0; i < 4; i++ {
				buffer[i] = *(*byte)(unsafe.Pointer(address + uintptr(i)))
			}
			
			if bytes.Equal(buffer, valueBytes) {
				newResults = append(newResults, address)
			}
		}()
	}
	
	scanner.results = newResults
}

// SearchBytesWithMask searches for a byte pattern in memory with wildcard support
func (scanner *MemoryScanner) SearchBytesWithMask(pattern []byte, mask []byte) {
	scanner.results = []uintptr{}
	
	// First ensure we have the memory regions
	if len(scanner.memoryRegions) == 0 {
		scanner.EnumerateMemoryRegions()
	}
	
	for _, region := range scanner.memoryRegions {
		// Read memory region
		buffer := make([]byte, region.RegionSize)
		
		// In the same process, we can directly read memory
		for i := uintptr(0); i < region.RegionSize; i++ {
			// Use defer/recover to handle any access violations
			func() {
				defer func() {
					if r := recover(); r != nil {
						// Memory access failed, skip this address
					}
				}()
				
				// Read byte directly
				if i < region.RegionSize {
					buffer[i] = *(*byte)(unsafe.Pointer(region.BaseAddress + i))
				}
			}()
		}
		
		// Search for pattern in buffer with mask
		patternLen := len(pattern)
		for i := 0; i <= len(buffer)-patternLen; i++ {
			match := true
			
			for j := 0; j < patternLen; j++ {
				// If mask is 0, this is a wildcard - always matches
				// If mask is 1, bytes must match exactly
				if mask[j] == 1 && buffer[i+j] != pattern[j] {
					match = false
					break
				}
			}
			
			if match {
				address := region.BaseAddress + uintptr(i)
				scanner.results = append(scanner.results, address)
			}
		}
	}
}

// CommandHandler interface for processing commands
type CommandHandler interface {
	HandleCommand(cmd string, args []string) bool
	GetHelp() map[string]string
}

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

// MemoryScannerCommandHandler provides memory scanning commands
type MemoryScannerCommandHandler struct {
	scanner *MemoryScanner
}

func NewMemoryScannerCommandHandler() *MemoryScannerCommandHandler {
	return &MemoryScannerCommandHandler{
		scanner: NewMemoryScanner(),
	}
}

func (h *MemoryScannerCommandHandler) HandleCommand(cmd string, args []string) bool {
	switch cmd {
	case "scan":
		if len(args) < 2 {
			fmt.Println("Usage: scan [type] [value]")
			fmt.Println("Types: int32, hex")
			fmt.Println("Example: scan hex FF??DE")
			fmt.Println("Note: Use ?? as wildcards in hex pattern")
			return true
		}
		
		scanType := args[0]
		valueStr := args[1]
		
		switch scanType {
		case "int32":
			value, err := strconv.ParseInt(valueStr, 10, 32)
			if err != nil {
				fmt.Printf("Invalid value: %s\n", err)
				return true
			}
			
			fmt.Println("Scanning memory for int32 value:", value)
			h.scanner.SearchInt32(int32(value))
			fmt.Printf("Found %d matches\n", len(h.scanner.results))
			
			if len(h.scanner.results) > 0 && len(h.scanner.results) <= 100 {
				fmt.Println("Addresses:")
				for _, addr := range h.scanner.results {
					fmt.Printf("0x%X\n", addr)
				}
			}
			
		case "hex":
			pattern, mask, err := ParseHexPattern(valueStr)
			if err != nil {
				fmt.Printf("Invalid hex pattern: %s\n", err)
				return true
			}
			
			// Show pattern with wildcards for user clarity
			patternDisplay := ""
			for i, b := range pattern {
				if mask[i] == 0 {
					patternDisplay += "?? "
				} else {
					patternDisplay += fmt.Sprintf("%02X ", b)
				}
			}
			fmt.Printf("Scanning memory for hex pattern: %s\n", strings.TrimSpace(patternDisplay))
			
			h.scanner.SearchBytesWithMask(pattern, mask)
			fmt.Printf("Found %d matches\n", len(h.scanner.results))
			
			if len(h.scanner.results) > 0 && len(h.scanner.results) <= 100 {
				fmt.Println("Addresses:")
				for _, addr := range h.scanner.results {
					fmt.Printf("0x%X\n", addr)
				}
			}
			
		default:
			fmt.Println("Unknown scan type. Use 'int32' or 'hex'")
		}
		
		return true
		
	case "filter":
		if len(args) < 1 {
			fmt.Println("Usage: filter [value]")
			return true
		}
		
		value, err := strconv.ParseInt(args[0], 10, 32)
		if err != nil {
			fmt.Printf("Invalid value: %s\n", err)
			return true
		}
		
		fmt.Println("Filtering previous results for value:", value)
		h.scanner.FilterInt32(int32(value))
		fmt.Printf("Found %d matches after filtering\n", len(h.scanner.results))
		
		if len(h.scanner.results) > 0 && len(h.scanner.results) <= 100 {
			fmt.Println("Addresses:")
			for _, addr := range h.scanner.results {
				fmt.Printf("0x%X\n", addr)
			}
		}
		
		return true
		
	case "memory":
		if len(args) == 0 {
			fmt.Println("Usage: memory list|info|read|write [arguments]")
			return true
		}
		
		switch args[0] {
		case "list":
			fmt.Println("Enumerating memory regions...")
			err := h.scanner.EnumerateMemoryRegions()
			if err != nil {
				fmt.Printf("Error: %s\n", err)
				return true
			}
			
			fmt.Printf("Found %d readable memory regions\n", len(h.scanner.memoryRegions))
			if len(h.scanner.memoryRegions) > 0 && len(h.scanner.memoryRegions) <= 100 {
				fmt.Println("Memory regions:")
				for i, region := range h.scanner.memoryRegions {
					fmt.Printf("%d: Base=0x%X, Size=%d bytes, Protection=0x%X\n",
						i, region.BaseAddress, region.RegionSize, region.Protect)
				}
			}
			
		case "read":
			if len(args) < 2 {
				fmt.Println("Usage: memory read [address] [length]")
				return true
			}
			
			address, err := strconv.ParseUint(args[1], 0, 64)
			if err != nil {
				fmt.Printf("Invalid address: %s\n", err)
				return true
			}
			
			length := 16 // Default length
			if len(args) >= 3 {
				length64, err := strconv.ParseInt(args[2], 10, 32)
				if err != nil {
					fmt.Printf("Invalid length: %s\n", err)
					return true
				}
				length = int(length64)
				if length > 1024 {
					length = 1024 // Cap at 1KB
				}
			}
			
			fmt.Printf("Reading %d bytes from address 0x%X\n", length, address)
			buffer := make([]byte, length)
			
			// Use defer/recover to handle any access violations
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Println("Error: Memory access violation")
					}
				}()
				
				// Read memory
				for i := 0; i < length; i++ {
					buffer[i] = *(*byte)(unsafe.Pointer(uintptr(address) + uintptr(i)))
				}
				
				// Display as hex dump
				for i := 0; i < length; i += 16 {
					// Address
					fmt.Printf("0x%08X: ", address+uint64(i))
					
					// Hex values
					for j := 0; j < 16; j++ {
						if i+j < length {
							fmt.Printf("%02X ", buffer[i+j])
						} else {
							fmt.Print("   ")
						}
					}
					
					// ASCII representation
					fmt.Print(" | ")
					for j := 0; j < 16; j++ {
						if i+j < length {
							b := buffer[i+j]
							if b >= 32 && b <= 126 { // Printable ASCII
								fmt.Printf("%c", b)
							} else {
								fmt.Print(".")
							}
						}
					}
					fmt.Println()
				}
			}()
			
		case "write":
			if len(args) < 3 {
				fmt.Println("Usage: memory write [address] [type] [value]")
				fmt.Println("Types: int32, byte")
				return true
			}
			
			address, err := strconv.ParseUint(args[1], 0, 64)
			if err != nil {
				fmt.Printf("Invalid address: %s\n", err)
				return true
			}
			
			writeType := args[2]
			valueStr := args[3]
			
			var oldProtect uint32
			
			// Change memory protection to allow writing
			ret, _, _ := virtualProtect.Call(
				uintptr(address),
				4, // Size depends on type
				PAGE_EXECUTE_READWRITE,
				uintptr(unsafe.Pointer(&oldProtect)),
			)
			
			if ret == 0 {
				fmt.Println("Error: Could not change memory protection")
				return true
			}
			
			// Use defer/recover to handle any access violations
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Println("Error: Memory access violation")
					}
					
					// Restore original protection
					virtualProtect.Call(
						uintptr(address),
						4,
						uintptr(oldProtect),
						uintptr(unsafe.Pointer(&oldProtect)),
					)
				}()
				
				switch writeType {
				case "int32":
					value, err := strconv.ParseInt(valueStr, 10, 32)
					if err != nil {
						fmt.Printf("Invalid value: %s\n", err)
						return
					}
					
					// Write int32 value
					*(*int32)(unsafe.Pointer(uintptr(address))) = int32(value)
					fmt.Printf("Wrote int32 value %d to address 0x%X\n", value, address)
					
				case "byte":
					value, err := strconv.ParseUint(valueStr, 0, 8)
					if err != nil {
						fmt.Printf("Invalid value: %s\n", err)
						return
					}
					
					// Write byte value
					*(*byte)(unsafe.Pointer(uintptr(address))) = byte(value)
					fmt.Printf("Wrote byte value 0x%X to address 0x%X\n", value, address)
					
				default:
					fmt.Println("Unknown write type. Use 'int32' or 'byte'")
				}
			}()
			
		default:
			fmt.Println("Unknown memory command. Use 'list', 'read', or 'write'")
		}
		
		return true
		
	default:
		return true // Pass to next handler
	}
}

func (h *MemoryScannerCommandHandler) GetHelp() map[string]string {
	return map[string]string{
		"scan":   "Scan memory for values - scan [type] [value]",
		"filter": "Filter previous results - filter [value]",
		"memory": "Memory operations - memory list|read|write [args]",
	}
}

// CommandReceiver handles the command line interface
type CommandReceiver struct {
	handlers []CommandHandler
	running  bool
}

func NewCommandReceiver() *CommandReceiver {
	return &CommandReceiver{
		handlers: []CommandHandler{&DefaultCommandHandler{}},
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

// init function is automatically executed when DLL is loaded
func init() {
	// Run in a goroutine to avoid blocking the main thread
	go func() {
		// Create console window
		r, _, _ := allocConsole.Call()
		if r == 0 {
			return
		}
		
		fmt.Println("DLL loaded and initialized!")
		
		// Start CLI receiver
		receiver := NewCommandReceiver()
		
		// Add memory scanner command handler
		memoryHandler := NewMemoryScannerCommandHandler()
		receiver.AddHandler(memoryHandler)
		
		receiver.Start()
	}()
}

func main() {
	// This function is not executed in DLL mode, but is required
	runtime.LockOSThread()
	select {} // Wait forever
}
