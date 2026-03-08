// Package health reports system stats in WebSocket pong messages.
//
// Stats are sampled in a background goroutine every 5 seconds and cached.
// GetPongCached() returns instantly with the latest cached values,
// preventing the old 1-second CPU blocking sample from delaying pong responses.
package health

import (
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"

	dockermgr "github.com/revelion/daemon/internal/docker"
)

const (
	// How often to sample system stats in the background.
	sampleInterval = 5 * time.Second
)

// PongMessage matches the daemon->brain pong format from build plan Section 2.3.2.
type PongMessage struct {
	Type       string  `json:"type"`
	Containers int     `json:"containers"`
	CPUPct     float64 `json:"cpu_pct"`
	MemoryMB   int     `json:"memory_mb"`
	DiskFreeGB float64 `json:"disk_free_gb"`
	Version    string  `json:"version"`
	OS         string  `json:"os"`
	Arch       string  `json:"arch"`
}

// Reporter collects system stats for pong responses.
type Reporter struct {
	docker *dockermgr.Manager

	mu         sync.RWMutex
	cpuPct     float64
	memoryMB   int
	diskFreeGB float64

	stopCh chan struct{}
}

func NewReporter(docker *dockermgr.Manager) *Reporter {
	r := &Reporter{
		docker: docker,
		stopCh: make(chan struct{}),
	}
	// Take an initial non-blocking sample
	r.sampleOnce()
	// Start background sampler
	go r.backgroundSampler()
	return r
}

// Stop shuts down the background sampler.
func (r *Reporter) Stop() {
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
}

// backgroundSampler collects CPU/memory/disk stats every sampleInterval.
func (r *Reporter) backgroundSampler() {
	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.sampleOnce()
		case <-r.stopCh:
			return
		}
	}
}

// sampleOnce takes a single system stats sample.
func (r *Reporter) sampleOnce() {
	cpuPct := 0.0
	memoryMB := 0
	diskFreeGB := 0.0

	// CPU usage — 1-second sample (fine in background goroutine, NOT in message path)
	percents, err := cpu.Percent(1*time.Second, false)
	if err == nil && len(percents) > 0 {
		cpuPct = percents[0]
	} else if err != nil {
		log.Printf("Failed to get CPU stats: %v", err)
	}

	// Memory usage
	vmem, err := mem.VirtualMemory()
	if err == nil {
		memoryMB = int(vmem.Used / 1024 / 1024)
	}

	// Disk free space
	diskPath := "/"
	if runtime.GOOS == "windows" {
		diskPath = "C:\\"
	}
	usage, err := disk.Usage(diskPath)
	if err == nil {
		diskFreeGB = float64(usage.Free) / (1024 * 1024 * 1024)
	}

	r.mu.Lock()
	r.cpuPct = cpuPct
	r.memoryMB = memoryMB
	r.diskFreeGB = diskFreeGB
	r.mu.Unlock()
}

// GetPongCached returns a pong message with cached system stats.
// This is instant — no blocking I/O.
func (r *Reporter) GetPongCached() PongMessage {
	r.mu.RLock()
	cpuPct := r.cpuPct
	memoryMB := r.memoryMB
	diskFreeGB := r.diskFreeGB
	r.mu.RUnlock()

	return PongMessage{
		Type:       "pong",
		Containers: r.docker.ActiveContainers(),
		CPUPct:     cpuPct,
		MemoryMB:   memoryMB,
		DiskFreeGB: diskFreeGB,
		Version:    "0.2.0",
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
	}
}

// GetPong is kept for backward compatibility but uses cached stats.
func (r *Reporter) GetPong() PongMessage {
	return r.GetPongCached()
}
