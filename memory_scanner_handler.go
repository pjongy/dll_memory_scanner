package main

import (
	"bufio"
	"fmt"
	"os"
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

// viewResults displays scan results in pages with navigation
func (h *MemoryScannerCommandHandler) viewResults(pageSize int) {
	addresses := h.scanner.GetResults()
	if len(addresses) == 0 {
		fmt.Println("No results to display")
		return
	}

	totalPages := (len(addresses) + pageSize - 1) / pageSize
	currentPage := 1
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("\n--- Results Page %d/%d (Total: %d) ---\n", currentPage, totalPages, len(addresses))

		// Calculate page bounds
		startIdx := (currentPage - 1) * pageSize
		endIdx := startIdx + pageSize
		if endIdx > len(addresses) {
			endIdx = len(addresses)
		}

		// Display addresses and values for current page
		for i := startIdx; i < endIdx; i++ {
			addr := addresses[i]

			// Try to read the current value
			var value int32
			var valueStr string

			func() {
				defer func() {
					if r := recover(); r != nil {
						valueStr = "[ERROR]"
					}
				}()

				// Read current value
				value = *(*int32)(unsafe.Pointer(addr))
				valueStr = fmt.Sprintf("%d (0x%X)", value, uint32(value))
			}()

			fmt.Printf("%3d: 0x%X = %s\n", i+1, addr, valueStr)
		}

		// Navigation prompt
		fmt.Print("\nNavigation - n(ext)/p(revious)/q(uit): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "n", "next":
			if currentPage < totalPages {
				currentPage++
			}
		case "p", "prev", "previous":
			if currentPage > 1 {
				currentPage--
			}
		case "q", "quit", "exit":
			return
		default:
			// Try to parse as a page number
			if pageNum, err := strconv.Atoi(input); err == nil && pageNum > 0 && pageNum <= totalPages {
				currentPage = pageNum
			}
		}
	}
}

func (h *MemoryScannerCommandHandler) HandleCommand(cmd string, args []string) bool {
	switch cmd {
	case "scan":
		if len(args) < 1 {
			fmt.Println("Usage: scan [type] [value]")
			fmt.Println("Types: int32, hex, changed, unchanged, increased, decreased")
			fmt.Println("Example: scan int32 100")
			fmt.Println("Example: scan hex FF??DE (use ?? as wildcards)")
			fmt.Println("Example: scan changed (requires previous scan)")
			return true
		}

		scanType := args[0]

		switch scanType {
		case "int32":
			if len(args) < 2 {
				fmt.Println("Usage: scan int32 [value]")
				return true
			}

			valueStr := args[1]
			value, err := strconv.ParseInt(valueStr, 10, 32)
			if err != nil {
				fmt.Printf("Invalid value: %s\n", err)
				return true
			}

			fmt.Println("Scanning memory for int32 value:", value)
			h.scanner.SearchInt32(int32(value))

			addresses := h.scanner.GetResults()
			fmt.Printf("Found %d matches\n", len(addresses))

			if len(addresses) > 0 && len(addresses) <= 100 {
				fmt.Println("Addresses:")
				for _, addr := range addresses {
					fmt.Printf("0x%X\n", addr)
				}
			}

		case "hex":
			if len(args) < 2 {
				fmt.Println("Usage: scan hex [pattern]")
				return true
			}

			valueStr := args[1]
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

			addresses := h.scanner.GetResults()
			fmt.Printf("Found %d matches\n", len(addresses))

			if len(addresses) > 0 && len(addresses) <= 100 {
				fmt.Println("Addresses:")
				for _, addr := range addresses {
					fmt.Printf("0x%X\n", addr)
				}
			}

		case "changed", "unchanged", "increased", "decreased":
			// Value change monitoring commands
			fmt.Printf("Checking for %s values since previous scan...\n", scanType)

			var scanTypeValue int
			switch scanType {
			case "changed":
				scanTypeValue = ValueTypeChanged
			case "unchanged":
				scanTypeValue = ValueTypeUnchanged
			case "increased":
				scanTypeValue = ValueTypeIncreased
			case "decreased":
				scanTypeValue = ValueTypeDecreased
			}

			h.scanner.MonitorInt32Values(scanTypeValue)

			addresses := h.scanner.GetResults()
			fmt.Printf("Found %d matches\n", len(addresses))

			if len(addresses) > 0 && len(addresses) <= 100 {
				fmt.Println("Addresses:")
				for _, addr := range addresses {
					fmt.Printf("0x%X\n", addr)
				}
			}

		default:
			fmt.Println("Unknown scan type. Use 'int32', 'hex', 'changed', 'unchanged', 'increased', or 'decreased'")
		}

		return true

	case "view":
		pageSize := 10 // Default page size
		if len(args) > 0 {
			if size, err := strconv.Atoi(args[0]); err == nil && size > 0 {
				pageSize = size
			}
		}

		h.viewResults(pageSize)
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

		addresses := h.scanner.GetResults()
		fmt.Printf("Found %d matches after filtering\n", len(addresses))

		if len(addresses) > 0 && len(addresses) <= 100 {
			fmt.Println("Addresses:")
			for _, addr := range addresses {
				fmt.Printf("0x%X\n", addr)
			}
		}

		return true

	case "store":
		fmt.Println("Storing current results for future comparison...")
		h.scanner.StoreCurrentResults()
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
		"scan":   "Scan memory - scan [type] [value] - Types: int32, hex, changed, unchanged, increased, decreased",
		"view":   "View current results with paging - view [page_size]",
		"filter": "Filter previous results - filter [value]",
		"store":  "Store current results for comparison in future scans",
		"memory": "Memory operations - memory list|read|write [args]",
	}
}
