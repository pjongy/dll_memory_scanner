package main

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

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
			if len(args) < 4 {
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
