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
	Type              string  `json:"type"`
	Containers        int     `json:"containers"`
	CPUPct            float64 `json:"cpu_pct"`
	MemoryMB          int     `json:"memory_mb"`
	DiskFreeGB        float64 `json:"disk_free_gb"`
	Version           string  `json:"version"`
	OS                string  `json:"os"`
	Arch              string  `json:"arch"`
	DockerStatus      string  `json:"docker_status"`
	ImageStatus       string  `json:"image_status"`
	ImagePullProgress int     `json:"image_pull_progress"`
}

// Reporter collects system stats for pong responses.
type Reporter struct {
	docker     *dockermgr.Manager
	sandboxImg string
	version    string

	mu           sync.RWMutex
	cpuPct       float64
	memoryMB     int
	diskFreeGB   float64
	dockerStatus string
	imageStatus  string
	imagePullPct int

	onNeedsPull func() // called when Docker is running but image is missing
	stopCh      chan struct{}
}

// SetOnNeedsPull registers a callback for when Docker is running but image is missing.
func (r *Reporter) SetOnNeedsPull(cb func()) {
	r.mu.Lock()
	r.onNeedsPull = cb
	r.mu.Unlock()
}

func NewReporter(docker *dockermgr.Manager, sandboxImage string, version string) *Reporter {
	r := &Reporter{
		docker:       docker,
		sandboxImg:   sandboxImage,
		version:      version,
		dockerStatus: "unknown",
		imageStatus:  "unknown",
		stopCh:       make(chan struct{}),
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

	// Docker status
	dockerStatus := "stopped"
	imageStatus := ""
	if r.docker.IsAvailable() {
		dockerStatus = "running"
		if r.docker.IsImagePresent(r.sandboxImg) {
			imageStatus = "ready"
		} else {
			imageStatus = "missing"
		}
	}

	r.mu.Lock()
	r.cpuPct = cpuPct
	r.memoryMB = memoryMB
	r.diskFreeGB = diskFreeGB
	r.dockerStatus = dockerStatus
	// Don't overwrite imageStatus if a pull is in progress
	needsPull := false
	if r.imageStatus != "pulling" {
		r.imageStatus = imageStatus
		// Trigger re-pull if Docker is running but image is missing
		if dockerStatus == "running" && imageStatus == "missing" && r.onNeedsPull != nil {
			needsPull = true
		}
	}
	cb := r.onNeedsPull
	r.mu.Unlock()

	if needsPull && cb != nil {
		go cb()
	}
}

// GetPongCached returns a pong message with cached system stats.
// This is instant — no blocking I/O.
func (r *Reporter) GetPongCached() PongMessage {
	r.mu.RLock()
	cpuPct := r.cpuPct
	memoryMB := r.memoryMB
	diskFreeGB := r.diskFreeGB
	dockerStatus := r.dockerStatus
	imageStatus := r.imageStatus
	imagePullPct := r.imagePullPct
	r.mu.RUnlock()

	return PongMessage{
		Type:              "pong",
		Containers:        r.docker.ActiveContainers(),
		CPUPct:            cpuPct,
		MemoryMB:          memoryMB,
		DiskFreeGB:        diskFreeGB,
		Version:           r.version,
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		DockerStatus:      dockerStatus,
		ImageStatus:       imageStatus,
		ImagePullProgress: imagePullPct,
	}
}

// SetImageStatus updates the image status and pull progress from external callers.
func (r *Reporter) SetImageStatus(status string, pct int) {
	r.mu.Lock()
	r.imageStatus = status
	r.imagePullPct = pct
	r.mu.Unlock()
}

// GetPong is kept for backward compatibility but uses cached stats.
func (r *Reporter) GetPong() PongMessage {
	return r.GetPongCached()
}
