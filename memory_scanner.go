package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
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
