package container_parser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
)

// NewContainerParser создает новый Docker клиент
func NewContainerParser() (*Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	return &Client{
		cli: cli,
		ctx: context.Background(),
	}, nil
}

func extractNetworkInfo(inspect container.InspectResponse) (string, map[string]string, string) {
	if inspect.NetworkSettings == nil || len(inspect.NetworkSettings.Networks) == 0 {
		return "", nil, ""
	}

	networks := make(map[string]string)
	var primaryIP, primaryGateway string
	var firstNetwork string

	// Собираем все сети
	for netName, net := range inspect.NetworkSettings.Networks {
		if net != nil && net.IPAddress != "" {
			networks[netName] = net.IPAddress

			// Запоминаем первый как "основной"
			if firstNetwork == "" {
				firstNetwork = netName
				primaryIP = net.IPAddress
				primaryGateway = net.Gateway
			}

			// Приоритет для сетей с "bridge" или "default" в названии
			if strings.Contains(strings.ToLower(netName), "bridge") ||
				strings.Contains(strings.ToLower(netName), "default") {
				primaryIP = net.IPAddress
				primaryGateway = net.Gateway
			}
		}
	}

	return primaryIP, networks, primaryGateway
}

// ListContainers возвращает список всех контейнеров
func (c *Client) ListContainers(all bool) ([]ContainerSummary, error) {
	containers, err := c.cli.ContainerList(c.ctx, container.ListOptions{
		All:     all,
		Size:    true,
		Filters: filters.NewArgs(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	// Debug: log number of containers found
	fmt.Printf("Debug: Found %d containers from Docker API\n", len(containers))

	var result []ContainerSummary
	for _, container := range containers {
		// Debug: log container info
		fmt.Printf("Debug: Processing container: ID=%s, Name=%s, State=%s\n",
			container.ID[:12],
			strings.TrimPrefix(container.Names[0], "/"),
			container.State)

		labels := container.Labels
		isCompose := false
		composeProject := ""
		composeService := ""

		if project, ok := labels["com.docker.compose.project"]; ok {
			isCompose = true
			composeProject = project
			composeService = labels["com.docker.compose.service"]
		}

		summary := ContainerSummary{
			ID:             container.ID[:12],
			Name:           strings.TrimPrefix(container.Names[0], "/"),
			Image:          container.Image,
			Status:         container.Status,
			State:          container.State,
			Created:        time.Unix(container.Created, 0),
			Labels:         labels,
			IsCompose:      isCompose,
			ComposeProject: composeProject,
			ComposeService: composeService,
		}

		inspect, err := c.cli.ContainerInspect(c.ctx, container.ID)
		if err != nil {
			fmt.Printf("Debug: Failed to inspect container %s: %v\n", container.ID[:12], err)
		} else {
			summary.IPAddress, summary.Networks, summary.Gateway = extractNetworkInfo(inspect)
		}
		// Получаем статистику для контейнера
		stats, err := c.GetContainerStats(container.ID)
		if err == nil {
			summary.CPUPercent = stats.CPUUsage.UsagePercent
			summary.MemPercent = stats.MemoryUsage.Percent
			summary.NetworkRx = formatBytes(stats.NetworkStats.RxBytes)
			summary.NetworkTx = formatBytes(stats.NetworkStats.TxBytes)

			// Рассчитываем uptime
			if container.State == "running" {
				summary.Uptime = calculateUptime(time.Unix(container.Created, 0))
			}
		} else {
			// Debug: log stats error
			fmt.Printf("Debug: Failed to get stats for container %s: %v\n", container.ID[:12], err)
		}

		result = append(result, summary)
	}

	// Debug: log final result
	fmt.Printf("Debug: Returning %d container summaries\n", len(result))

	return result, nil
}

// GetContainer возвращает детальную информацию о контейнере
func (c *Client) GetContainer(id string) (*Container, error) {
	containerInfo, err := c.cli.ContainerInspect(c.ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	// Преобразуем порты
	var ports []Port
	for port, bindings := range containerInfo.NetworkSettings.Ports {
		for _, binding := range bindings {
			publicPort, _ := strconv.Atoi(binding.HostPort)
			ports = append(ports, Port{
				IP:          binding.HostIP,
				PrivatePort: uint16(port.Int()),
				PublicPort:  uint16(publicPort),
				Type:        port.Proto(),
			})
		}
	}

	// Преобразуем сети
	networks := make(map[string]Network)
	for name, net := range containerInfo.NetworkSettings.Networks {
		networks[name] = Network{
			IPAddress:    net.IPAddress,
			Gateway:      net.Gateway,
			MacAddress:   net.MacAddress,
			NetworkID:    net.NetworkID,
			EndpointID:   net.EndpointID,
			IPv6Gateway:  net.IPv6Gateway,
			GlobalIPv6:   net.GlobalIPv6Address,
			PrefixLength: net.IPPrefixLen,
		}
	}

	// Преобразуем монтирования
	var mounts []Mount
	for _, mount := range containerInfo.Mounts {
		mounts = append(mounts, Mount{
			Type:        string(mount.Type),
			Source:      mount.Source,
			Destination: mount.Destination,
			Mode:        mount.Mode,
			RW:          mount.RW,
			Propagation: string(mount.Propagation),
		})
	}

	created, _ := time.Parse(time.RFC3339Nano, containerInfo.Created)
	startedAt, _ := time.Parse(time.RFC3339Nano, containerInfo.State.StartedAt)
	finishedAt, _ := time.Parse(time.RFC3339Nano, containerInfo.State.FinishedAt)

	containerA := &Container{
		ID:         containerInfo.ID[:12],
		Name:       strings.TrimPrefix(containerInfo.Name, "/"),
		Image:      containerInfo.Config.Image,
		Status:     containerInfo.State.Status,
		State:      containerInfo.State.Status,
		Created:    created,
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
		Labels:     containerInfo.Config.Labels,
		Ports:      ports,
		NetworkSettings: NetworkSettings{
			Networks:   networks,
			IPAddress:  containerInfo.NetworkSettings.IPAddress,
			Gateway:    containerInfo.NetworkSettings.Gateway,
			MacAddress: containerInfo.NetworkSettings.MacAddress,
		},
		Mounts:  mounts,
		Command: strings.Join(containerInfo.Config.Cmd, " "),
	}

	return containerA, nil
}

// GetContainerStats возвращает статистику использования ресурсов контейнера
func (c *Client) GetContainerStats(id string) (*ContainerStats, error) {
	stats, err := c.cli.ContainerStats(c.ctx, id, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get container stats: %w", err)
	}
	defer stats.Body.Close()

	// Парсим статистику как общую структуру
	var statsJSON map[string]interface{}
	if err := json.NewDecoder(stats.Body).Decode(&statsJSON); err != nil {
		return nil, fmt.Errorf("failed to decode stats: %w", err)
	}

	// Извлекаем базовые данные
	cpuPercent := 0.0
	memPercent := 0.0
	var netStats NetStats
	var diskStats DiskStats
	var cpuTotalUsage uint64
	var cpuSystemUsage uint64
	var onlineCPUs uint64
	var memoryUsage uint64
	var memoryLimit uint64
	var memoryMaxUsage uint64
	var memoryCache uint64
	var memoryRSS uint64
	var pids uint64
	var throttledTime uint64
	var throttledPeriods uint64

	// Пытаемся извлечь данные о CPU
	if cpuStats, ok := statsJSON["cpu_stats"].(map[string]interface{}); ok {
		// Извлекаем использование CPU
		if cpuUsage, ok := cpuStats["cpu_usage"].(map[string]interface{}); ok {
			if totalUsage, ok := cpuUsage["total_usage"].(float64); ok {
				cpuTotalUsage = uint64(totalUsage)
			}
			if systemUsage, ok := cpuUsage["usage_in_kernelmode"].(float64); ok {
				cpuSystemUsage = uint64(systemUsage)
			}
		}

		// Извлекаем количество CPU
		if onlineCPUsVal, ok := cpuStats["online_cpus"].(float64); ok {
			onlineCPUs = uint64(onlineCPUsVal)
		}

		// Извлекаем данные о троттлинге
		if throttling, ok := cpuStats["throttling_data"].(map[string]interface{}); ok {
			if throttledTimeVal, ok := throttling["throttled_time"].(float64); ok {
				throttledTime = uint64(throttledTimeVal)
			}
			if periodsVal, ok := throttling["periods"].(float64); ok {
				throttledPeriods = uint64(periodsVal)
			}
		}

		// Рассчитываем процент использования CPU (нужны precpu_stats)
		if precpuStats, ok := statsJSON["precpu_stats"].(map[string]interface{}); ok {
			if precpuUsage, ok := precpuStats["cpu_usage"].(map[string]interface{}); ok {
				if prevTotal, ok := precpuUsage["total_usage"].(float64); ok {
					// Получаем system_cpu_usage из текущей и предыдущей статистики
					var systemCPUUsage, prevSystemCPUUsage float64
					if currentSystem, ok := cpuStats["system_cpu_usage"].(float64); ok {
						systemCPUUsage = currentSystem
					}
					if prevSystem, ok := precpuStats["system_cpu_usage"].(float64); ok {
						prevSystemCPUUsage = prevSystem
					}

					// Рассчитываем дельты
					cpuDelta := float64(cpuTotalUsage) - prevTotal
					systemDelta := systemCPUUsage - prevSystemCPUUsage

					// Рассчитываем процент использования CPU
					if systemDelta > 0 && cpuDelta > 0 {
						// Формула: (cpuDelta / systemDelta) * onlineCPUs * 100
						cpuPercent = (cpuDelta / systemDelta) * float64(onlineCPUs) * 100.0
					}
				}
			}
		}
	}

	// Пытаемся извлечь данные о памяти
	if memoryStats, ok := statsJSON["memory_stats"].(map[string]interface{}); ok {
		if usage, ok := memoryStats["usage"].(float64); ok {
			memoryUsage = uint64(usage)
		}
		if limit, ok := memoryStats["limit"].(float64); ok {
			memoryLimit = uint64(limit)
		}
		if maxUsage, ok := memoryStats["max_usage"].(float64); ok {
			memoryMaxUsage = uint64(maxUsage)
		}
		if stats, ok := memoryStats["stats"].(map[string]interface{}); ok {
			if cache, ok := stats["cache"].(float64); ok {
				memoryCache = uint64(cache)
			}
			if rss, ok := stats["rss"].(float64); ok {
				memoryRSS = uint64(rss)
			}
		}

		// Также проверяем max_usage на верхнем уровне
		if maxUsage, ok := memoryStats["max_usage"].(float64); ok && maxUsage > 0 {
			memoryMaxUsage = uint64(maxUsage)
		}

		// Рассчитываем процент использования памяти
		if memoryLimit > 0 {
			memPercent = (float64(memoryUsage) / float64(memoryLimit)) * 100
		}
	}

	// Пытаемся извлечь данные о сети
	if networks, ok := statsJSON["networks"].(map[string]interface{}); ok {
		for _, net := range networks {
			if netMap, ok := net.(map[string]interface{}); ok {
				if rxBytes, ok := netMap["rx_bytes"].(float64); ok {
					netStats.RxBytes += uint64(rxBytes)
				}
				if txBytes, ok := netMap["tx_bytes"].(float64); ok {
					netStats.TxBytes += uint64(txBytes)
				}
				if rxPackets, ok := netMap["rx_packets"].(float64); ok {
					netStats.RxPackets += uint64(rxPackets)
				}
				if txPackets, ok := netMap["tx_packets"].(float64); ok {
					netStats.TxPackets += uint64(txPackets)
				}
				if rxErrors, ok := netMap["rx_errors"].(float64); ok {
					netStats.RxErrors += uint64(rxErrors)
				}
				if txErrors, ok := netMap["tx_errors"].(float64); ok {
					netStats.TxErrors += uint64(txErrors)
				}
				if rxDropped, ok := netMap["rx_dropped"].(float64); ok {
					netStats.RxDropped += uint64(rxDropped)
				}
				if txDropped, ok := netMap["tx_dropped"].(float64); ok {
					netStats.TxDropped += uint64(txDropped)
				}
			}
		}
	}

	// Пытаемся извлечь данные о дисковом I/O
	if blkioStats, ok := statsJSON["blkio_stats"].(map[string]interface{}); ok {
		if ioServiceBytes, ok := blkioStats["io_service_bytes_recursive"].([]interface{}); ok {
			for _, io := range ioServiceBytes {
				if ioMap, ok := io.(map[string]interface{}); ok {
					if op, ok := ioMap["op"].(string); ok {
						if value, ok := ioMap["value"].(float64); ok {
							if op == "Read" {
								diskStats.ReadBytes += uint64(value)
							} else if op == "Write" {
								diskStats.WriteBytes += uint64(value)
							}
						}
					}
				}
			}
		}
		if ioServiced, ok := blkioStats["io_serviced_recursive"].([]interface{}); ok {
			for _, io := range ioServiced {
				if ioMap, ok := io.(map[string]interface{}); ok {
					if op, ok := ioMap["op"].(string); ok {
						if value, ok := ioMap["value"].(float64); ok {
							if op == "Read" {
								diskStats.ReadOps += uint64(value)
							} else if op == "Write" {
								diskStats.WriteOps += uint64(value)
							}
						}
					}
				}
			}
		}
	}

	// Извлекаем количество процессов
	if pidsStats, ok := statsJSON["pids_stats"].(map[string]interface{}); ok {
		if current, ok := pidsStats["current"].(float64); ok {
			pids = uint64(current)
		}
	}

	// Создаем полную статистику
	containerStats := &ContainerStats{
		ContainerID: id[:12],
		Timestamp:   time.Now(),
		CPUUsage: CPUStats{
			TotalUsage:      float64(cpuTotalUsage),
			SystemUsage:     float64(cpuSystemUsage),
			OnlineCPUs:      int(onlineCPUs),
			UsagePercent:    cpuPercent,
			ThrottledTime:   throttledTime,
			ThrottledPeriod: throttledPeriods,
		},
		MemoryUsage: MemStats{
			Usage:    memoryUsage,
			Limit:    memoryLimit,
			MaxUsage: memoryMaxUsage,
			Percent:  memPercent,
			Cache:    memoryCache,
			RSS:      memoryRSS,
		},
		NetworkStats: netStats,
		DiskIOStats:  diskStats,
		PIDs:         int(pids),
		Uptime:       "0s", // Uptime будет рассчитан отдельно при необходимости
	}

	return containerStats, nil
}

// GetSystemInfo возвращает информацию о системе Docker
func (c *Client) GetSystemInfo() (*SystemInfo, error) {
	info, err := c.cli.Info(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get system info: %w", err)
	}

	return &SystemInfo{
		ContainersRunning: info.ContainersRunning,
		ContainersStopped: info.ContainersStopped,
		ContainersPaused:  info.ContainersPaused,
		ContainersTotal:   info.Containers,
		Images:            info.Images,
		ServerVersion:     info.ServerVersion,
		OSType:            info.OSType,
		Architecture:      info.Architecture,
		CPUs:              info.NCPU,
		Memory:            uint64(info.MemTotal),
		Swap:              0, // Docker API doesn't provide swap info in Info
		KernelVersion:     info.KernelVersion,
		DockerRootDir:     info.DockerRootDir,
	}, nil
}

// StartContainer запускает контейнер
func (c *Client) StartContainer(id string) error {
	err := c.cli.ContainerStart(c.ctx, id, container.StartOptions{})
	return err
}

// StopContainer останавливает контейнер
func (c *Client) StopContainer(id string, timeout *int) error {
	if timeout == nil {
		defaultTimeout := 10
		timeout = &defaultTimeout
	}
	var stopOptions container.StopOptions
	if timeout != nil {
		stopOptions = container.StopOptions{Timeout: timeout}
	}
	err := c.cli.ContainerStop(c.ctx, id, stopOptions)
	return err
}

// RestartContainer перезапускает контейнер
func (c *Client) RestartContainer(id string, timeout *int) error {
	if timeout == nil {
		defaultTimeout := 10
		timeout = &defaultTimeout
	}
	return c.cli.ContainerRestart(c.ctx, id, container.StopOptions{Timeout: timeout})
}

// GetContainerLogs возвращает логи контейнера
func (c *Client) GetContainerLogs(id string, tail string, follow bool) (io.ReadCloser, error) {
	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       tail,
		Follow:     follow,
		Timestamps: true,
	}

	return c.cli.ContainerLogs(c.ctx, id, options)
}

// RemoveContainer удаляет контейнер
func (c *Client) RemoveContainer(id string, force bool, removeVolumes bool) error {
	options := container.RemoveOptions{
		Force:         force,
		RemoveVolumes: removeVolumes,
	}

	return c.cli.ContainerRemove(c.ctx, id, options)
}

// ListVolumes возвращает список всех томов
func (c *Client) ListVolumes() ([]VolumeSummary, error) {
	volumes, err := c.cli.VolumeList(c.ctx, volume.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list volumes: %w", err)
	}

	var result []VolumeSummary
	for _, vol := range volumes.Volumes {
		// Parse CreatedAt string to time.Time
		createdAt, _ := time.Parse(time.RFC3339, vol.CreatedAt)

		// Safely handle UsageData which can be nil
		var refCount int
		var sizeBytes int64
		if vol.UsageData != nil {
			refCount = int(vol.UsageData.RefCount)
			sizeBytes = vol.UsageData.Size
		}

		summary := VolumeSummary{
			Name:       vol.Name,
			Driver:     vol.Driver,
			Mountpoint: vol.Mountpoint,
			CreatedAt:  createdAt,
			RefCount:   refCount,
			Labels:     vol.Labels,
		}

		// Форматируем размер в читаемый формат
		if vol.UsageData != nil {
			summary.Size = formatBytes(uint64(sizeBytes))
		}

		result = append(result, summary)
	}

	return result, nil
}

// GetVolume возвращает детальную информацию о томе
func (c *Client) GetVolume(name string) (*VolumeDetail, error) {
	vol, err := c.cli.VolumeInspect(c.ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect volume: %w", err)
	}

	// Получаем информацию о контейнерах, использующих этот том
	containers, err := c.ListContainers(true)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var mountInfo []VolumeMountInfo
	for _, container := range containers {
		containerDetail, err := c.GetContainer(container.ID)
		if err != nil {
			continue
		}

		for _, mount := range containerDetail.Mounts {
			if mount.Type == "volume" && mount.Source == vol.Name {
				mountInfo = append(mountInfo, VolumeMountInfo{
					ContainerID:   containerDetail.ID,
					ContainerName: containerDetail.Name,
					MountPath:     mount.Destination,
					ReadOnly:      !mount.RW,
					Propagation:   mount.Propagation,
				})
			}
		}
	}

	// Parse CreatedAt string to time.Time
	createdAt, _ := time.Parse(time.RFC3339, vol.CreatedAt)

	// Safely handle UsageData which can be nil
	var usageData *VolumeUsageData
	if vol.UsageData != nil {
		usageData = &VolumeUsageData{
			SizeBytes: vol.UsageData.Size,
			RefCount:  int(vol.UsageData.RefCount),
		}
	}

	volumeDetail := &VolumeDetail{
		Volume: Volume{
			Name:       vol.Name,
			Driver:     vol.Driver,
			Mountpoint: vol.Mountpoint,
			CreatedAt:  createdAt,
			Labels:     vol.Labels,
			Scope:      vol.Scope,
			Options:    vol.Options,
			UsageData:  usageData,
		},
		Containers: mountInfo,
	}

	// Форматируем размер в читаемый формат
	if vol.UsageData != nil {
		volumeDetail.Size = formatBytes(uint64(vol.UsageData.Size))
	}

	return volumeDetail, nil
}

// CreateVolume создает новый том
func (c *Client) CreateVolume(req VolumeCreateRequest) (*Volume, error) {
	volumeReq := volume.CreateOptions{
		Name:       req.Name,
		Driver:     req.Driver,
		DriverOpts: req.DriverOpts,
		Labels:     req.Labels,
	}

	vol, err := c.cli.VolumeCreate(c.ctx, volumeReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create volume: %w", err)
	}

	// Safely handle UsageData which can be nil
	var usageData *VolumeUsageData
	if vol.UsageData != nil {
		usageData = &VolumeUsageData{
			SizeBytes: vol.UsageData.Size,
			RefCount:  int(vol.UsageData.RefCount),
		}
	}

	// Parse CreatedAt string to time.Time
	createdAt, _ := time.Parse(time.RFC3339, vol.CreatedAt)
	return &Volume{
		Name:       vol.Name,
		Driver:     vol.Driver,
		Mountpoint: vol.Mountpoint,
		CreatedAt:  createdAt,
		Labels:     vol.Labels,
		Scope:      vol.Scope,
		Options:    vol.Options,
		UsageData:  usageData,
	}, nil
}

// RemoveVolume удаляет том
func (c *Client) RemoveVolume(name string, force bool) error {
	return c.cli.VolumeRemove(c.ctx, name, force)
}

// PruneVolumes удаляет неиспользуемые тома
func (c *Client) PruneVolumes() (*VolumePruneReport, error) {
	report, err := c.cli.VolumesPrune(c.ctx, filters.NewArgs())
	if err != nil {
		return nil, fmt.Errorf("failed to prune volumes: %w", err)
	}

	// Создаем модель отчета
	pruneReport := &VolumePruneReport{
		VolumesDeleted: report.VolumesDeleted,
		SpaceReclaimed: report.SpaceReclaimed,
	}

	// Форматируем размер в читаемый формат
	pruneReport.SpaceReclaimedFormatted = formatBytes(uint64(report.SpaceReclaimed))

	return pruneReport, nil
}

// formatBytes форматирует байты в читаемый формат
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// calculateUptime рассчитывает время работы контейнера
func calculateUptime(created time.Time) string {
	uptime := time.Since(created)

	if uptime < time.Minute {
		return fmt.Sprintf("%ds", int(uptime.Seconds()))
	}
	if uptime < time.Hour {
		return fmt.Sprintf("%dm", int(uptime.Minutes()))
	}
	if uptime < 24*time.Hour {
		hours := int(uptime.Hours())
		minutes := int(uptime.Minutes()) % 60
		return fmt.Sprintf("%dh%dm", hours, minutes)
	}

	days := int(uptime.Hours() / 24)
	hours := int(uptime.Hours()) % 24
	return fmt.Sprintf("%dd%dh", days, hours)
}

// GetVolumeContents возвращает содержимое тома
// Сначала пытается использовать существующий контейнер, если том уже смонтирован
// Если контейнеров нет, создает временный контейнер
func (c *Client) GetVolumeContents(volumeName string, path string) (*VolumeContents, error) {
	// Проверяем существование тома
	vol, err := c.cli.VolumeInspect(c.ctx, volumeName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect volume: %w", err)
	}

	// Получаем список контейнеров и ищем те, которые используют этот том
	containers, err := c.cli.ContainerList(c.ctx, container.ListOptions{
		All:     true,
		Size:    false,
		Filters: filters.NewArgs(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var mountInfo []VolumeMountInfo
	for _, container := range containers {
		// Используем ContainerInspect только для получения монтированных томов
		// Это быстрее, чем GetContainer с полной информацией
		containerInfo, err := c.cli.ContainerInspect(c.ctx, container.ID)
		if err != nil {
			continue
		}

		for _, mount := range containerInfo.Mounts {
			if mount.Type == "volume" && mount.Source == vol.Name {
				mountInfo = append(mountInfo, VolumeMountInfo{
					ContainerID:   container.ID,
					ContainerName: strings.TrimPrefix(container.Names[0], "/"),
					MountPath:     mount.Destination,
					ReadOnly:      !mount.RW,
					Propagation:   string(mount.Propagation),
				})
			}
		}
	}

	// Если есть работающие контейнеры, использующие том, пробуем использовать их
	for _, mi := range mountInfo {
		// Properly join mountPath and path
		joinedPath := mi.MountPath
		if path != "/" && path != "" {
			if !strings.HasSuffix(joinedPath, "/") {
				joinedPath += "/"
			}
			joinedPath += strings.TrimPrefix(path, "/")
		}
		contents, err := c.getVolumeContentsFromContainer(mi.ContainerID, joinedPath)
		if err == nil {
			// Добавляем информацию о контейнерах к результату
			return &VolumeContents{
				Name:     vol.Name,
				Path:     path,
				Contents: contents.Contents,
				Total:    contents.Total,
			}, nil
		}
	}

	// Если нет работающих контейнеров, создаем временный
	// Ensure path starts with /
	tempPath := path
	if !strings.HasPrefix(tempPath, "/") {
		tempPath = "/" + tempPath
	}
	return c.getVolumeContentsWithTempContainer(vol.Name, tempPath)
}

// getVolumeContentsFromContainer возвращает содержимое тома через docker exec
func (c *Client) getVolumeContentsFromContainer(containerID string, mountPath string) (*VolumeContents, error) {
	// Ensure mountPath ends with / so ls shows contents, not the directory itself
	if !strings.HasSuffix(mountPath, "/") {
		mountPath += "/"
	}
	// Используем ls -la для получения полной информации о файлах
	execConfig := container.ExecOptions{
		Cmd:          []string{"sh", "-c", fmt.Sprintf("ls -la %s 2>/dev/null || echo ''", mountPath)},
		AttachStdout: true,
		AttachStderr: true,
	}

	execResp, err := c.cli.ContainerExecCreate(c.ctx, containerID, execConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create exec: %w", err)
	}

	// Подключаемся к выполнению команды
	hijackedResp, err := c.cli.ContainerExecAttach(c.ctx, execResp.ID, container.ExecAttachOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec: %w", err)
	}
	defer hijackedResp.Close()

	// Читаем вывод
	output, err := io.ReadAll(hijackedResp.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read exec output: %w", err)
	}

	// Парсим вывод ls -la
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	contents := make([]VolumeContentEntry, 0)

	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "total ") {
			continue
		}

		// Парсим строку ls -la
		entry, err := parseLsLine(line, mountPath)
		if err != nil || entry == nil {
			continue
		}
		contents = append(contents, *entry)
	}

	// Сортируем: сначала директории, потом файлы
	sort.Slice(contents, func(i, j int) bool {
		if contents[i].IsDir && !contents[j].IsDir {
			return true
		}
		if !contents[i].IsDir && contents[j].IsDir {
			return false
		}
		return contents[i].Name < contents[j].Name
	})

	return &VolumeContents{
		Name:     "",
		Path:     "",
		Contents: contents,
		Total:    len(contents),
	}, nil
}

// parseLsLine парсирует строку вывода ls -la
// Формат: -rw-r--r--  1 user group 1024 Jan 1 12:00 filename
func parseLsLine(line string, mountPath string) (*VolumeContentEntry, error) {
	// Debug: log line being parsed
	fmt.Printf("Debug: Parsing ls line: '%s' with mountPath: '%s'\n", line, mountPath)
	parts := strings.Fields(line)
	fmt.Printf("Debug: Parts count: %d, parts: %v\n", len(parts), parts)
	if len(parts) < 9 {
		fmt.Printf("Debug: Line has fewer than 9 parts, skipping\n")
		return nil, nil
	}

	// Skip . and .. entries
	filename := parts[8]
	fmt.Printf("Debug: Filename: '%s'\n", filename)
	if filename == "." || filename == ".." {
		return nil, nil
	}

	// parts[0] = permissions (rwxr-xr-x)
	permissions := parts[0]
	// parts[4] = size (в байтах)
	sizeStr := parts[4]
	// parts[5..7] = date (Jan 1 12:00)
	// parts[8] = filename
	fmt.Printf("Debug: Permissions: '%s', Size: '%s', Date parts: %v\n", permissions, sizeStr, parts[5:8])

	// Преобразуем размер
	size, _ := strconv.ParseInt(sizeStr, 10, 64)

	// Определяем тип по первому символу прав
	var entryTypeStr string
	isDir := false
	isSymlink := false

	permChar := permissions[0]
	switch permChar {
	case 'd':
		entryTypeStr = "directory"
		isDir = true
	case 'l':
		entryTypeStr = "symlink"
		isSymlink = true
	default:
		entryTypeStr = "file"
	}

	// Пытаемся распарсить дату (формат ls: Jan 1 12:00 или Jan 1 2024)
	monthStr := parts[5]
	dayStr := parts[6]
	timeOrYear := parts[7]

	// Формируем дату (используем текущий год по умолчанию)
	now := time.Now()
	year := now.Year()

	// Парсим месяц
	months := map[string]int{
		"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
		"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
	}
	month, ok := months[monthStr]
	if !ok {
		month = int(now.Month())
	}

	// Парсим день
	day, _ := strconv.Atoi(dayStr)

	// Парсим время или год
	var hour, minute int
	if strings.Contains(timeOrYear, ":") {
		// Это время (12:00)
		timeParts := strings.Split(timeOrYear, ":")
		hour, _ = strconv.Atoi(timeParts[0])
		minute, _ = strconv.Atoi(timeParts[1])
	} else {
		// Это год (2024)
		year, _ = strconv.Atoi(timeOrYear)
		hour, minute = 0, 0
	}

	modified := time.Date(year, time.Month(month), day, hour, minute, 0, 0, time.UTC)

	// Создаем запись
	entry := VolumeContentEntry{
		Name:      filename,
		Path:      filepath.ToSlash(filepath.Join(mountPath, filename)),
		Type:      entryTypeStr,
		Size:      size,
		Mode:      permissions,
		Modified:  modified,
		IsDir:     isDir,
		IsSymlink: isSymlink,
	}
	fmt.Printf("Debug: Created entry: %+v\n", entry)

	return &entry, nil
}

// getVolumeContentsWithTempContainer возвращает содержимое тома через временный контейнер
func (c *Client) getVolumeContentsWithTempContainer(volumeName string, path string) (*VolumeContents, error) {
	// Проверяем существование тома
	vol, err := c.cli.VolumeInspect(c.ctx, volumeName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect volume: %w", err)
	}

	// Пробуем использовать доступные образы для чтения содержимого
	images := []string{"alpine:latest", "alpine:3.19", "busybox:latest", "busybox:1.36"}
	var containerID string

	for _, image := range images {
		containerConfig := &container.Config{
			Image:      image,
			Cmd:        []string{"sh", "-c", "tail -f /dev/null"},
			Tty:        false,
			OpenStdin:  false,
			WorkingDir: "/volume",
		}

		hostConfig := &container.HostConfig{
			Binds: []string{fmt.Sprintf("%s:/volume", vol.Name)},
		}

		// Пробуем создать контейнер
		resp, err := c.cli.ContainerCreate(c.ctx, containerConfig, hostConfig, nil, nil, "")
		if err == nil {
			containerID = resp.ID
			break
		}
	}

	if containerID == "" {
		return nil, fmt.Errorf("failed to create container: none of the standard images (alpine, busybox) are available. Please pull at least one: docker pull alpine:latest")
	}

	// Убедимся, что контейнер будет удален
	defer func() {
		c.cli.ContainerRemove(c.ctx, containerID, container.RemoveOptions{
			Force: true,
		})
	}()

	// Запускаем контейнер
	if err := c.cli.ContainerStart(c.ctx, containerID, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Ensure path ends with / so ls shows contents, not the directory itself
	lsPath := path
	if !strings.HasSuffix(path, "/") {
		lsPath = path + "/"
	}
	// Используем ls -la для получения полной информации о файлах
	execConfig := container.ExecOptions{
		Cmd:          []string{"sh", "-c", "ls -la /volume" + lsPath + " 2>/dev/null || echo ''"},
		AttachStdout: true,
		AttachStderr: true,
	}

	execResp, err := c.cli.ContainerExecCreate(c.ctx, containerID, execConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create exec: %w", err)
	}

	// Подключаемся к выполнению команды
	hijackedResp, err := c.cli.ContainerExecAttach(c.ctx, execResp.ID, container.ExecAttachOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec: %w", err)
	}
	defer hijackedResp.Close()

	// Читаем вывод
	output, err := io.ReadAll(hijackedResp.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read exec output: %w", err)
	}

	// Ждем завершения выполнения
	_, err = c.cli.ContainerExecInspect(c.ctx, execResp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect exec: %w", err)
	}

	// Останавливаем контейнер
	timeoutSec := 5
	c.cli.ContainerStop(c.ctx, containerID, container.StopOptions{Timeout: &timeoutSec})

	// Парсим вывод ls -la
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	contents := make([]VolumeContentEntry, 0)

	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "total ") {
			continue
		}

		// Парсим строку ls -la
		entry, err := parseLsLine(line, "/volume"+path)
		if err != nil || entry == nil {
			continue
		}
		contents = append(contents, *entry)
	}

	// Сортируем: сначала директории, потом файлы
	sort.Slice(contents, func(i, j int) bool {
		if contents[i].IsDir && !contents[j].IsDir {
			return true
		}
		if !contents[i].IsDir && contents[j].IsDir {
			return false
		}
		return contents[i].Name < contents[j].Name
	})

	return &VolumeContents{
		Name:     volumeName,
		Path:     path,
		Contents: contents,
		Total:    len(contents),
	}, nil
}

// ScanVolumeHierarchy выполняет асинхронное сканирование иерархии тома
func (c *Client) ScanVolumeHierarchy(volumeName, path string) (*VolumeCache, error) {
	// Проверяем существование тома
	vol, err := c.cli.VolumeInspect(c.ctx, volumeName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect volume: %w", err)
	}

	// Создаем временный контейнер для сканирования
	images := []string{"alpine:latest", "alpine:3.19", "busybox:latest", "busybox:1.36"}
	var containerID string

	for _, image := range images {
		containerConfig := &container.Config{
			Image:      image,
			Cmd:        []string{"sh", "-c", "tail -f /dev/null"},
			Tty:        false,
			OpenStdin:  false,
			WorkingDir: "/volume",
		}

		hostConfig := &container.HostConfig{
			Binds: []string{fmt.Sprintf("%s:/volume", vol.Name)},
		}

		resp, err := c.cli.ContainerCreate(c.ctx, containerConfig, hostConfig, nil, nil, "")
		if err == nil {
			containerID = resp.ID
			break
		}
	}

	if containerID == "" {
		return nil, fmt.Errorf("failed to create container: none of the standard images (alpine, busybox) are available")
	}

	// Запускаем контейнер
	if err := c.cli.ContainerStart(c.ctx, containerID, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Ждем пока контейнер запустится (ожидаем несколько секунд)
	for i := 0; i < 10; i++ {
		inspect, err := c.cli.ContainerInspect(c.ctx, containerID)
		if err == nil && inspect.State.Running {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	defer func() {
		c.cli.ContainerRemove(c.ctx, containerID, container.RemoveOptions{
			Force: true,
		})
	}()

	// Выполняем ls -laR для получения иерархии
	execConfig := container.ExecOptions{
		Cmd:          []string{"sh", "-c", fmt.Sprintf("cd /volume%s && ls -laR 2>/dev/null || echo ''", path)},
		AttachStdout: true,
		AttachStderr: true,
	}

	execResp, err := c.cli.ContainerExecCreate(c.ctx, containerID, execConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create exec: %w", err)
	}

	hijackedResp, err := c.cli.ContainerExecAttach(c.ctx, execResp.ID, container.ExecAttachOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec: %w", err)
	}
	defer hijackedResp.Close()

	output, err := io.ReadAll(hijackedResp.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read exec output: %w", err)
	}

	// Очищаем вывод от управляющих символов
	cleanOutput := make([]byte, 0, len(output))
	foundFirstPrintable := false
	for i := 0; i < len(output); i++ {
		b := output[i]
		if b < 32 && b != '\n' && b != '\t' {
			if !foundFirstPrintable {
				continue
			}
			cleanOutput = append(cleanOutput, ' ')
			foundFirstPrintable = true
		} else {
			cleanOutput = append(cleanOutput, b)
			foundFirstPrintable = true
		}
	}

	// Парсим вывод ls -laR
	lines := strings.Split(strings.TrimSpace(string(cleanOutput)), "\n")
	entries := make(map[string]*VolumeCacheEntry)

	// Текущая директория при обходе
	var currentDir = "/"

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Строка с именем директории (для ls -laR)
		if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "total") {
			currentDir = strings.TrimSuffix(line, ":")
			// Удаляем управляющие символы и нормализуем путь
			currentDir = strings.Map(func(r rune) rune {
				if r < 32 && r != '\n' && r != '\t' {
					return -1
				}
				return r
			}, currentDir)
			currentDir = strings.TrimSpace(currentDir)
			currentDir = strings.TrimPrefix(currentDir, "./")
			currentDir = strings.TrimPrefix(currentDir, "/")
			if currentDir == "" || currentDir == "." {
				currentDir = "/"
			} else if !strings.HasPrefix(currentDir, "/") {
				currentDir = "/" + currentDir
			}
			continue
		}

		// Пропускаем строки "total" и ошибки
		if strings.HasPrefix(line, "total") || strings.HasPrefix(line, "ls: cannot access") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 9 {
			continue
		}

		filename := parts[8]

		// Пропускаем ссылки на текущую/родительскую директорию
		if filename == "." || filename == ".." {
			continue
		}

		// parts[0] = permissions, parts[4] = size, parts[5..7] = date
		permissions := parts[0]
		sizeStr := parts[4]

		// Определяем тип по первому символу прав
		entryTypeStr := "file"
		isDir := false
		isSymlink := false

		permChar := permissions[0]
		switch permChar {
		case 'd':
			entryTypeStr = "directory"
			isDir = true
		case 'l':
			entryTypeStr = "symlink"
			isSymlink = true
		}

		// Преобразуем размер
		size, _ := strconv.ParseInt(sizeStr, 10, 64)

		// Пытаемся распарсить дату (формат ls: Jan 1 12:00 или Jan 1 2024)
		monthStr := parts[5]
		dayStr := parts[6]
		timeOrYear := parts[7]

		// Формируем дату (используем текущий год по умолчанию)
		now := time.Now()
		year := now.Year()

		// Парсим месяц
		months := map[string]int{
			"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
			"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
		}
		month, ok := months[monthStr]
		if !ok {
			month = int(now.Month())
		}

		// Парсим день
		day, _ := strconv.Atoi(dayStr)

		// Парсим время или год
		var hour, minute int
		if strings.Contains(timeOrYear, ":") {
			// Это время (12:00)
			timeParts := strings.Split(timeOrYear, ":")
			hour, _ = strconv.Atoi(timeParts[0])
			minute, _ = strconv.Atoi(timeParts[1])
		} else {
			// Это год (2024)
			year, _ = strconv.Atoi(timeOrYear)
			hour, minute = 0, 0
		}

		modified := time.Date(year, time.Month(month), day, hour, minute, 0, 0, time.UTC)

		mode := permissions
		// filename уже был объявлен выше

		// Получаем относительный путь (без /volume)
		// Если currentDir это "/", то файл в корне тома
		// Иначе путь должен быть currentDir + filename
		var relPath string
		if currentDir == "/" {
			relPath = "/" + filename
		} else {
			relPath = currentDir + "/" + filename
		}

		// Очищаем путь от управляющих символов
		relPath = strings.Map(func(r rune) rune {
			if r < 32 && r != '\n' && r != '\t' {
				return -1
			}
			return r
		}, relPath)
		relPath = strings.TrimSpace(relPath)
		relPath = strings.ReplaceAll(relPath, "//", "/")
		relPath = strings.TrimPrefix(relPath, "./")
		// Убираем ведущий ./ из пути
		if relPath == "" || relPath == "." {
			relPath = "/"
		}

		// Построим полный путь для уникализации (используем relPath как основу)
		fullPath := "/volume" + relPath

		entries[fullPath] = &VolumeCacheEntry{
			Name:      filename,
			Path:      relPath,
			Type:      entryTypeStr,
			Size:      size,
			Mode:      mode,
			Modified:  modified,
			IsDir:     isDir,
			IsSymlink: isSymlink,
		}
	}

	// Строим иерархию
	pathMap := make(map[string]*VolumeCacheEntry)
	for _, entry := range entries {
		pathMap[entry.Path] = entry
	}

	var rootEntries []*VolumeCacheEntry

	// Строим иерархию
	for _, entry := range entries {
		if entry.Name == "." || entry.Name == ".." || entry.Path == "/" {
			continue
		}

		parentPath := filepath.Dir(entry.Path)
		if parentPath == "." {
			parentPath = "/"
		}

		parent := pathMap[parentPath]
		if parent != nil {
			if parent.Children == nil {
				parent.Children = make([]*VolumeCacheEntry, 0)
			}
			parent.Children = append(parent.Children, entry)
		} else {
			// Родитель не найден - добавляем в rootEntries
			found := false
			for _, root := range rootEntries {
				if root.Path == entry.Path {
					found = true
					break
				}
			}
			if !found {
				rootEntries = append(rootEntries, entry)
			}
		}
	}

	return &VolumeCache{
		VolumeName: volumeName,
		Path:       path,
		Entries:    rootEntries,
		Total:      len(entries),
		UpdatedAt:  time.Now(),
		Scanning:   false,
	}, nil
}
