package container_parser

import (
	"context"
	"time"

	"github.com/docker/docker/client"
)

type Client struct {
	cli *client.Client
	ctx context.Context
}

type VolumeScanJob struct {
	ScanID      string
	VolumeName  string
	Path        string
	Status      string // "pending", "running", "completed", "failed"
	StartedAt   time.Time
	CompletedAt time.Time
	Progress    int
	TotalItems  int
	Error       string
}

// Container представляет информацию о Docker контейнере
type Container struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Image           string            `json:"image"`
	Status          string            `json:"status"`
	State           string            `json:"state"`
	Created         time.Time         `json:"created"`
	StartedAt       time.Time         `json:"started_at"`
	FinishedAt      time.Time         `json:"finished_at"`
	Labels          map[string]string `json:"labels"`
	Ports           []Port            `json:"ports"`
	NetworkSettings NetworkSettings   `json:"network_settings"`
	Mounts          []Mount           `json:"mounts"`
	Command         string            `json:"command"`
}

// ContainerStats представляет статистику использования ресурсов контейнера
type ContainerStats struct {
	ContainerID  string    `json:"container_id"`
	Timestamp    time.Time `json:"timestamp"`
	CPUUsage     CPUStats  `json:"cpu_usage"`
	MemoryUsage  MemStats  `json:"memory_usage"`
	NetworkStats NetStats  `json:"network_stats"`
	DiskIOStats  DiskStats `json:"disk_io_stats"`
	PIDs         int       `json:"pids"`
	Uptime       string    `json:"uptime"`
}

// CPUStats представляет статистику использования CPU
type CPUStats struct {
	TotalUsage      float64 `json:"total_usage"`
	SystemUsage     float64 `json:"system_usage"`
	OnlineCPUs      int     `json:"online_cpus"`
	UsagePercent    float64 `json:"usage_percent"`
	ThrottledTime   uint64  `json:"throttled_time"`
	ThrottledPeriod uint64  `json:"throttled_period"`
}

// MemStats представляет статистику использования памяти
type MemStats struct {
	Usage    uint64  `json:"usage"`
	Limit    uint64  `json:"limit"`
	MaxUsage uint64  `json:"max_usage"`
	Percent  float64 `json:"percent"`
	Cache    uint64  `json:"cache"`
	RSS      uint64  `json:"rss"`
}

// NetStats представляет статистику сети
type NetStats struct {
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
	TxDropped uint64 `json:"tx_dropped"`
}

// DiskStats представляет статистику дискового ввода/вывода
type DiskStats struct {
	ReadBytes  uint64 `json:"read_bytes"`
	WriteBytes uint64 `json:"write_bytes"`
	ReadOps    uint64 `json:"read_ops"`
	WriteOps   uint64 `json:"write_ops"`
}

// Port представляет информацию о порте контейнера
type Port struct {
	IP          string `json:"ip"`
	PrivatePort uint16 `json:"private_port"`
	PublicPort  uint16 `json:"public_port"`
	Type        string `json:"type"`
}

// NetworkSettings представляет сетевые настройки контейнера
type NetworkSettings struct {
	Networks   map[string]Network `json:"networks"`
	IPAddress  string             `json:"ip_address"`
	Gateway    string             `json:"gateway"`
	MacAddress string             `json:"mac_address"`
}

// Network представляет сетевую информацию
type Network struct {
	IPAddress    string `json:"ip_address"`
	Gateway      string `json:"gateway"`
	MacAddress   string `json:"mac_address"`
	NetworkID    string `json:"network_id"`
	EndpointID   string `json:"endpoint_id"`
	IPv6Gateway  string `json:"ipv6_gateway"`
	GlobalIPv6   string `json:"global_ipv6"`
	PrefixLength int    `json:"prefix_length"`
}

// Mount представляет информацию о монтировании
type Mount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
	Propagation string `json:"propagation"`
}

// ContainerSummary представляет краткую информацию о контейнере для списка
type ContainerSummary struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Image      string    `json:"image"`
	Status     string    `json:"status"`
	State      string    `json:"state"`
	Created    time.Time `json:"created"`
	Uptime     string    `json:"uptime"`
	CPUPercent float64   `json:"cpu_percent"`
	MemPercent float64   `json:"mem_percent"`
	NetworkRx  string    `json:"network_rx"`
	NetworkTx  string    `json:"network_tx"`
}

// SystemInfo представляет информацию о системе Docker
type SystemInfo struct {
	ContainersRunning int    `json:"containers_running"`
	ContainersStopped int    `json:"containers_stopped"`
	ContainersPaused  int    `json:"containers_paused"`
	ContainersTotal   int    `json:"containers_total"`
	Images            int    `json:"images"`
	ServerVersion     string `json:"server_version"`
	OSType            string `json:"os_type"`
	Architecture      string `json:"architecture"`
	CPUs              int    `json:"cpus"`
	Memory            uint64 `json:"memory"`
	Swap              uint64 `json:"swap"`
	KernelVersion     string `json:"kernel_version"`
	DockerRootDir     string `json:"docker_root_dir"`
}

// Volume represents a Docker volume
type Volume struct {
	// Basic information
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	CreatedAt  time.Time         `json:"created_at"`
	Labels     map[string]string `json:"labels,omitempty"`
	Scope      string            `json:"scope"` // local, global
	Options    map[string]string `json:"options,omitempty"`

	// Usage information
	UsageData *VolumeUsageData `json:"usage_data,omitempty"`
}

// VolumeUsageData represents volume usage statistics
type VolumeUsageData struct {
	SizeBytes int64 `json:"size_bytes"`
	RefCount  int   `json:"ref_count"`
}

// VolumeCreateRequest represents a request to create a volume
type VolumeCreateRequest struct {
	Name       string            `json:"name,omitempty"`
	Driver     string            `json:"driver,omitempty"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// VolumeListOptions represents options for listing volumes
type VolumeListOptions struct {
	Filters map[string][]string `json:"filters,omitempty"`
}

// VolumeInspectResponse represents detailed volume information
type VolumeInspectResponse struct {
	Volume
	Status map[string]interface{} `json:"status,omitempty"`
}

// VolumeStats represents volume statistics
type VolumeStats struct {
	Name       string    `json:"name"`
	SizeBytes  int64     `json:"size_bytes"`
	RefCount   int       `json:"ref_count"`
	CreatedAt  time.Time `json:"created_at"`
	Mountpoint string    `json:"mountpoint"`
	Driver     string    `json:"driver"`
}

// VolumeMountInfo represents information about how a volume is mounted in containers
type VolumeMountInfo struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	MountPath     string `json:"mount_path"`
	ReadOnly      bool   `json:"read_only"`
	Propagation   string `json:"propagation,omitempty"`
}

// VolumeDetail represents detailed volume information including mount info
type VolumeDetail struct {
	Volume
	Containers []VolumeMountInfo `json:"containers,omitempty"`
	Size       string            `json:"size,omitempty"`
}

// VolumeSummary represents summary information for volume listing
type VolumeSummary struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	CreatedAt  time.Time         `json:"created_at"`
	Size       string            `json:"size,omitempty"`
	RefCount   int               `json:"ref_count"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// VolumePruneReport represents the result of pruning unused volumes
type VolumePruneReport struct {
	VolumesDeleted          []string `json:"volumes_deleted"`
	SpaceReclaimed          uint64   `json:"space_reclaimed"`
	SpaceReclaimedFormatted string   `json:"space_reclaimed_formatted,omitempty"`
}

// VolumeContents represents the contents of a volume
type VolumeContents struct {
	Name     string               `json:"name"`
	Path     string               `json:"path,omitempty"`
	Contents []VolumeContentEntry `json:"contents"`
	Total    int                  `json:"total"`
}

// VolumeContentEntry represents a single file or directory in a volume
type VolumeContentEntry struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Type      string    `json:"type"` // "file", "directory", "symlink"
	Size      int64     `json:"size,omitempty"`
	Mode      string    `json:"mode,omitempty"`
	Modified  time.Time `json:"modified,omitempty"`
	IsDir     bool      `json:"is_dir"`
	IsSymlink bool      `json:"is_symlink,omitempty"`
}

// VolumeCacheEntry represents a cached entry in the volume hierarchy
type VolumeCacheEntry struct {
	Name      string              `json:"name"`
	Path      string              `json:"path"`
	Type      string              `json:"type"` // "file", "directory", "symlink"
	Size      int64               `json:"size,omitempty"`
	Mode      string              `json:"mode,omitempty"`
	Modified  time.Time           `json:"modified,omitempty"`
	IsDir     bool                `json:"is_dir"`
	IsSymlink bool                `json:"is_symlink,omitempty"`
	Children  []*VolumeCacheEntry `json:"children,omitempty"`
}

// VolumeCache represents the complete cached volume information
type VolumeCache struct {
	VolumeName string              `json:"volume_name"`
	Path       string              `json:"path"`
	Entries    []*VolumeCacheEntry `json:"entries"`
	Total      int                 `json:"total"`
	UpdatedAt  time.Time           `json:"updated_at"`
	Scanning   bool                `json:"scanning"`
}

// VolumeScanRequest represents a request to start volume scanning
type VolumeScanRequest struct {
	VolumeName string `json:"volume_name"`
	Path       string `json:"path,omitempty"`
}

// VolumeScanResponse represents the response from a scan operation
type VolumeScanResponse struct {
	ScanID     string    `json:"scan_id"`
	VolumeName string    `json:"volume_name"`
	Path       string    `json:"path"`
	StartedAt  time.Time `json:"started_at"`
	Status     string    `json:"status"`
}

// VolumeScanStatus represents the status of a scan operation
type VolumeScanStatus struct {
	ScanID      string    `json:"scan_id"`
	VolumeName  string    `json:"volume_name"`
	Path        string    `json:"path"`
	Status      string    `json:"status"` // "pending", "running", "completed", "failed"
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
	Progress    int       `json:"progress"`
	TotalItems  int       `json:"total_items"`
	Error       string    `json:"error,omitempty"`
}
