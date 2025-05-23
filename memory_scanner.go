package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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

// ProgressTracker tracks scanning progress
type ProgressTracker struct {
	totalRegions     int64
	processedRegions int64
	totalBytes       int64
	processedBytes   int64
	startTime        time.Time
	mutex            sync.RWMutex
}

func NewProgressTracker() *ProgressTracker {
	return &ProgressTracker{
		startTime: time.Now(),
	}
}

func (p *ProgressTracker) SetTotal(regions int, bytes int64) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.totalRegions = int64(regions)
	p.totalBytes = bytes
}

func (p *ProgressTracker) AddProcessed(bytes int64) {
	atomic.AddInt64(&p.processedRegions, 1)
	atomic.AddInt64(&p.processedBytes, bytes)
}

func (p *ProgressTracker) GetProgress() (float64, float64, time.Duration) {
	processedRegions := atomic.LoadInt64(&p.processedRegions)
	processedBytes := atomic.LoadInt64(&p.processedBytes)

	p.mutex.RLock()
	defer p.mutex.RUnlock()

	regionProgress := float64(processedRegions) / float64(p.totalRegions) * 100
	byteProgress := float64(processedBytes) / float64(p.totalBytes) * 100
	elapsed := time.Since(p.startTime)

	return regionProgress, byteProgress, elapsed
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

func (scanner *MemoryScanner) EnumerateMemoryRegions(needLock bool) error {
	if needLock {
		scanner.mutex.Lock()
		defer scanner.mutex.Unlock()
	}

	scanner.memoryRegions = nil
	var addr uintptr
	for {
		var mbi MEMORY_BASIC_INFORMATION
		ret, _, _ := virtualQuery.Call(
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if ret == 0 {
			break
		}
		if mbi.State&MEM_COMMIT != 0 &&
			mbi.Protect&(PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|
				PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|
				PAGE_EXECUTE_WRITECOPY) != 0 &&
			mbi.Protect&PAGE_GUARD == 0 {
			scanner.memoryRegions = append(scanner.memoryRegions, mbi)
		}
		addr = mbi.BaseAddress + mbi.RegionSize
	}
	return nil
}

// showProgress displays real-time progress
func showProgress(tracker *ProgressTracker, done chan bool) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	fmt.Println("Scanning progress:")

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			regionProgress, byteProgress, elapsed := tracker.GetProgress()

			// Create simple progress bar
			barWidth := 20
			regionBars := int(regionProgress * float64(barWidth) / 100)
			byteBars := int(byteProgress * float64(barWidth) / 100)

			regionBar := strings.Repeat("=", regionBars) + strings.Repeat("-", barWidth-regionBars)
			byteBar := strings.Repeat("=", byteBars) + strings.Repeat("-", barWidth-byteBars)

			// Print progress on new lines (more reliable on Windows)
			fmt.Printf("Regions: [%s] %6.1f%% | Bytes: [%s] %6.1f%% | Time: %v\n",
				regionBar, regionProgress, byteBar, byteProgress, elapsed.Truncate(time.Second))
		}
	}
}

func readMemoryRegion(region MEMORY_BASIC_INFORMATION) []byte {
	buf := make([]byte, region.RegionSize)
	const chunk = uintptr(4096)
	for off := uintptr(0); off < region.RegionSize; off += chunk {
		size := chunk
		if region.RegionSize-off < chunk {
			size = region.RegionSize - off
		}
		base := region.BaseAddress + off
		var mbi MEMORY_BASIC_INFORMATION
		virtualQuery.Call(
			base,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if mbi.State&MEM_COMMIT == 0 || mbi.Protect&PAGE_GUARD != 0 {
			continue
		}
		slice := unsafe.Slice((*byte)(unsafe.Pointer(base)), size)
		copy(buf[off:off+size], slice)
	}
	return buf
}

// SearchInt32 searches for a 32-bit integer value in memory using goroutines
func (scanner *MemoryScanner) SearchInt32(value int32) {
	scanner.mutex.Lock()
	defer scanner.mutex.Unlock()

	// find memory region each search is called (memory protection can be changed) but not needed for monitor after scan
	err := scanner.EnumerateMemoryRegions(false) // Don't need lock, already locked
	if err != nil {
		fmt.Printf("Error enumerating memory regions: %v\n", err)
		return
	}

	// Convert value to bytes
	valueBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueBytes, uint32(value))

	// Calculate total bytes to scan
	var totalBytes int64
	for _, region := range scanner.memoryRegions {
		totalBytes += int64(region.RegionSize)
	}

	// Use more goroutines for better CPU utilization
	numCPU := runtime.NumCPU()
	numWorkers := numCPU * 2 // Use twice the number of CPU cores
	if numWorkers > len(scanner.memoryRegions) {
		numWorkers = len(scanner.memoryRegions)
	}

	// Log scan information
	fmt.Printf("Scan Info: %d memory regions, %d MB total, %d CPU cores, %d goroutines\n",
		len(scanner.memoryRegions), totalBytes/(1024*1024), numCPU, numWorkers)

	// Setup progress tracking
	tracker := NewProgressTracker()
	tracker.SetTotal(len(scanner.memoryRegions), totalBytes)

	progressDone := make(chan bool)
	go showProgress(tracker, progressDone)

	var wg sync.WaitGroup
	resultsChan := make(chan ScanResult, 10000) // Larger buffer
	regionChan := make(chan MEMORY_BASIC_INFORMATION, len(scanner.memoryRegions))

	// Send all regions to channel
	for _, region := range scanner.memoryRegions {
		regionChan <- region
	}
	close(regionChan)

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for region := range regionChan {
				// Read memory region efficiently
				buffer := readMemoryRegion(region)

				// Search for value in buffer
				for i := 0; i <= len(buffer)-4; i++ {
					if bytes.Equal(buffer[i:i+4], valueBytes) {
						address := region.BaseAddress + uintptr(i)
						resultValue := make([]byte, 4)
						copy(resultValue, buffer[i:i+4])
						resultsChan <- ScanResult{Address: address, Value: resultValue}
					}
				}

				// Update progress
				tracker.AddProcessed(int64(region.RegionSize))
			}
		}()
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

	// Stop progress display
	progressDone <- true

	// Final progress update
	fmt.Printf("\nScan completed! Found %d matches in %v\n",
		len(scanner.results), time.Since(tracker.startTime).Truncate(time.Millisecond))
}

// MonitorValues scans for changes based on previous scan (both int32, hex)
func (scanner *MemoryScanner) MonitorValues(scanType int) {
	scanner.mutex.Lock()
	defer scanner.mutex.Unlock()

	if len(scanner.previousScan) == 0 {
		fmt.Println("No previous scan results to compare with")
		return
	}

	// 1) Refresh the list of readable memory regions
	if err := scanner.EnumerateMemoryRegions(false); err != nil {
		fmt.Println("Failed to enumerate memory regions:", err)
		return
	}

	// 2) Calculate total bytes to process for progress tracking
	var totalBytes int64
	for _, prev := range scanner.previousScan {
		totalBytes += int64(len(prev.Value))
	}
	tracker := NewProgressTracker()
	tracker.SetTotal(len(scanner.previousScan), totalBytes)
	done := make(chan bool)
	go showProgress(tracker, done)

	// 3) Read current values only from valid regions
	currentValues := make(map[uintptr][]byte, len(scanner.previousScan))
	for _, prev := range scanner.previousScan {
		addr := prev.Address
		size := len(prev.Value)

		// Check if this address range is still within a committed, readable region
		valid := false
		for _, region := range scanner.memoryRegions {
			start := region.BaseAddress
			end := region.BaseAddress + region.RegionSize
			if addr >= start && addr+uintptr(size) <= end {
				valid = true
				break
			}
		}
		if !valid {
			tracker.AddProcessed(int64(size))
			continue
		}

		// Safely read the bytes
		buf := make([]byte, size)
		func() {
			defer func() { recover() }()
			for i := 0; i < size; i++ {
				buf[i] = *(*byte)(unsafe.Pointer(addr + uintptr(i)))
			}
			currentValues[addr] = append([]byte(nil), buf...)
		}()
		tracker.AddProcessed(int64(size))
	}

	// 4) Compare with previous values and collect matches
	scanner.results = scanner.results[:0]
	for addr, cur := range currentValues {
		// Find the previous byte slice
		var prevBytes []byte
		for _, p := range scanner.previousScan {
			if p.Address == addr {
				prevBytes = p.Value
				break
			}
		}

		// Determine match based on scanType
		var match bool
		switch scanType {
		case ValueTypeChanged:
			match = !bytes.Equal(cur, prevBytes)
		case ValueTypeUnchanged:
			match = bytes.Equal(cur, prevBytes)
		case ValueTypeIncreased:
			match = bytes.Compare(cur, prevBytes) > 0
		case ValueTypeDecreased:
			match = bytes.Compare(cur, prevBytes) < 0
		}

		if match {
			scanner.results = append(scanner.results, ScanResult{
				Address: addr,
				Value:   cur,
			})
		}
	}

	// 5) Signal completion of progress display
	done <- true
	fmt.Printf("\nMonitoring completed: %d matches found\n", len(scanner.results))
}

// FilterInt32 filters previous results with a new int32 value
func (scanner *MemoryScanner) FilterInt32(value int32) {
	scanner.mutex.Lock()
	defer scanner.mutex.Unlock()

	if len(scanner.results) == 0 {
		return
	}

	fmt.Printf("Filtering %d addresses for value %d...\n", len(scanner.results), value)

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
	fmt.Printf("Filter completed! %d matches remain\n", len(scanner.results))
}

// SearchBytesWithMask searches for a byte pattern in memory with wildcard support
func (scanner *MemoryScanner) SearchBytesWithMask(pattern []byte, mask []byte) {
	scanner.mutex.Lock()
	defer scanner.mutex.Unlock()

	// find memory region each search is called (memory protection can be changed) but not needed for monitor after scan
	err := scanner.EnumerateMemoryRegions(false) // Don't need lock, already locked
	if err != nil {
		fmt.Printf("Error enumerating memory regions: %v\n", err)
		return
	}

	// Calculate total bytes to scan
	var totalBytes int64
	for _, region := range scanner.memoryRegions {
		totalBytes += int64(region.RegionSize)
	}

	// Use more goroutines for better CPU utilization
	numCPU := runtime.NumCPU()
	numWorkers := numCPU * 2 // Use twice the number of CPU cores
	if numWorkers > len(scanner.memoryRegions) {
		numWorkers = len(scanner.memoryRegions)
	}

	// Log scan information
	fmt.Printf("Pattern Scan Info: %d memory regions, %d MB total, %d CPU cores, %d goroutines, pattern length: %d bytes\n",
		len(scanner.memoryRegions), totalBytes/(1024*1024), numCPU, numWorkers, len(pattern))

	// Setup progress tracking
	tracker := NewProgressTracker()
	tracker.SetTotal(len(scanner.memoryRegions), totalBytes)

	progressDone := make(chan bool)
	go showProgress(tracker, progressDone)

	var wg sync.WaitGroup
	resultsChan := make(chan ScanResult, 10000) // Larger buffer
	regionChan := make(chan MEMORY_BASIC_INFORMATION, len(scanner.memoryRegions))

	// Send all regions to channel
	for _, region := range scanner.memoryRegions {
		regionChan <- region
	}
	close(regionChan)

	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for region := range regionChan {
				// Read memory region efficiently
				buffer := readMemoryRegion(region)

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

				// Update progress
				tracker.AddProcessed(int64(region.RegionSize))
			}
		}()
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

	// Stop progress display
	progressDone <- true

	// Final progress update
	fmt.Printf("\nPattern scan completed! Found %d matches in %v\n",
		len(scanner.results), time.Since(tracker.startTime).Truncate(time.Millisecond))
}
