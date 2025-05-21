package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// Scan types for memory value change monitoring
const (
	ValueTypeExact     = iota // Exact value match
	ValueTypeChanged          // Value changed since last scan
	ValueTypeUnchanged        // Value unchanged since last scan
	ValueTypeIncreased        // Value increased since last scan
	ValueTypeDecreased        // Value decreased since last scan
)

// ScanResult stores a scan result with address and value
type ScanResult struct {
	Address uintptr
	Value   []byte
}

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
	results       []ScanResult
	previousScan  []ScanResult
	processHandle uintptr
	processID     uint32
	mutex         sync.Mutex // For thread safety
}

func NewMemoryScanner() *MemoryScanner {
	handle, _, _ := getCurrentProcess.Call()
	id, _, _ := getCurrentProcessId.Call()

	return &MemoryScanner{
		memoryRegions: []MEMORY_BASIC_INFORMATION{},
		results:       []ScanResult{},
		previousScan:  []ScanResult{},
		processHandle: handle,
		processID:     uint32(id),
	}
}

// GetResults returns the current scan results addresses
func (scanner *MemoryScanner) GetResults() []uintptr {
	addresses := make([]uintptr, len(scanner.results))
	for i, result := range scanner.results {
		addresses[i] = result.Address
	}
	return addresses
}

// StoreCurrentResults saves current results for future comparison
func (scanner *MemoryScanner) StoreCurrentResults() {
	scanner.previousScan = make([]ScanResult, len(scanner.results))
	copy(scanner.previousScan, scanner.results)
}

// SaveNamedResults saves current scan results with a name for later retrieval
func (scanner *MemoryScanner) SaveNamedResults(name string) {
	// Would implement storing results in a map
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
	scanner.mutex.Lock()
	defer scanner.mutex.Unlock()

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

// SearchInt32 searches for a 32-bit integer value in memory using goroutines
func (scanner *MemoryScanner) SearchInt32(value int32) {
	scanner.mutex.Lock()
	defer scanner.mutex.Unlock()

	// First ensure we have the memory regions
	if len(scanner.memoryRegions) == 0 {
		scanner.EnumerateMemoryRegions()
	}

	// Convert value to bytes
	valueBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueBytes, uint32(value))

	// Determine number of goroutines to use (half of available CPU cores)
	numCPU := runtime.NumCPU()
	numWorkers := numCPU / 2
	if numWorkers < 1 {
		numWorkers = 1
	}

	var wg sync.WaitGroup
	resultsChan := make(chan ScanResult, 1000)

	// Divide regions among workers
	regionsPerWorker := (len(scanner.memoryRegions) + numWorkers - 1) / numWorkers

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		startIdx := w * regionsPerWorker
		endIdx := (w + 1) * regionsPerWorker
		if endIdx > len(scanner.memoryRegions) {
			endIdx = len(scanner.memoryRegions)
		}

		go func(regions []MEMORY_BASIC_INFORMATION) {
			defer wg.Done()

			for _, region := range regions {
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
						resultValue := make([]byte, 4)
						copy(resultValue, buffer[i:i+4])
						resultsChan <- ScanResult{Address: address, Value: resultValue}
					}
				}
			}
		}(scanner.memoryRegions[startIdx:endIdx])
	}

	// Close channel when all workers are done
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Clear previous results and collect new ones
	scanner.results = []ScanResult{}
	for result := range resultsChan {
		scanner.results = append(scanner.results, result)
	}
}

// MonitorInt32Values scans for changes based on previous scan
func (scanner *MemoryScanner) MonitorInt32Values(scanType int) {
	scanner.mutex.Lock()
	defer scanner.mutex.Unlock()

	// Need previous scan results to compare
	if len(scanner.previousScan) == 0 {
		fmt.Println("No previous scan results to compare with")
		return
	}

	// Store current values from all previous addresses
	currentValues := make(map[uintptr]int32)
	for _, prevResult := range scanner.previousScan {
		// Read current value at this address
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Memory access failed, skip this address
				}
			}()

			// Read 4 bytes directly as int32
			value := *(*int32)(unsafe.Pointer(prevResult.Address))
			currentValues[prevResult.Address] = value
		}()
	}

	// Compare values based on scan type
	scanner.results = []ScanResult{}
	for address, currentValue := range currentValues {
		// Get previous value
		var previousValue int32
		for _, prevResult := range scanner.previousScan {
			if prevResult.Address == address {
				previousValue = int32(binary.LittleEndian.Uint32(prevResult.Value))
				break
			}
		}

		// Check if this address matches the scan criteria
		matchFound := false
		switch scanType {
		case ValueTypeChanged:
			matchFound = currentValue != previousValue
		case ValueTypeUnchanged:
			matchFound = currentValue == previousValue
		case ValueTypeIncreased:
			matchFound = currentValue > previousValue
		case ValueTypeDecreased:
			matchFound = currentValue < previousValue
		}

		if matchFound {
			// Store the result
			valueBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(valueBytes, uint32(currentValue))
			scanner.results = append(scanner.results, ScanResult{
				Address: address,
				Value:   valueBytes,
			})
		}
	}
}

// FilterInt32 filters previous results with a new int32 value
func (scanner *MemoryScanner) FilterInt32(value int32) {
	scanner.mutex.Lock()
	defer scanner.mutex.Unlock()

	if len(scanner.results) == 0 {
		return
	}

	valueBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueBytes, uint32(value))

	newResults := []ScanResult{}

	for _, result := range scanner.results {
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
				buffer[i] = *(*byte)(unsafe.Pointer(result.Address + uintptr(i)))
			}

			if bytes.Equal(buffer, valueBytes) {
				newResults = append(newResults, ScanResult{
					Address: result.Address,
					Value:   buffer,
				})
			}
		}()
	}

	scanner.results = newResults
}

// SearchBytesWithMask searches for a byte pattern in memory with wildcard support
func (scanner *MemoryScanner) SearchBytesWithMask(pattern []byte, mask []byte) {
	scanner.mutex.Lock()
	defer scanner.mutex.Unlock()

	// First ensure we have the memory regions
	if len(scanner.memoryRegions) == 0 {
		scanner.EnumerateMemoryRegions()
	}

	// Determine number of goroutines to use (half of available CPU cores)
	numCPU := runtime.NumCPU()
	numWorkers := numCPU / 2
	if numWorkers < 1 {
		numWorkers = 1
	}

	var wg sync.WaitGroup
	resultsChan := make(chan ScanResult, 1000)

	// Divide regions among workers
	regionsPerWorker := (len(scanner.memoryRegions) + numWorkers - 1) / numWorkers

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		startIdx := w * regionsPerWorker
		endIdx := (w + 1) * regionsPerWorker
		if endIdx > len(scanner.memoryRegions) {
			endIdx = len(scanner.memoryRegions)
		}

		go func(regions []MEMORY_BASIC_INFORMATION) {
			defer wg.Done()

			for _, region := range regions {
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
						resultValue := make([]byte, patternLen)
						copy(resultValue, buffer[i:i+patternLen])
						resultsChan <- ScanResult{Address: address, Value: resultValue}
					}
				}
			}
		}(scanner.memoryRegions[startIdx:endIdx])
	}

	// Close channel when all workers are done
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Clear previous results and collect new ones
	scanner.results = []ScanResult{}
	for result := range resultsChan {
		scanner.results = append(scanner.results, result)
	}
}
