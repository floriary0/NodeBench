package collector

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nodebench/nodebench/internal/model"
)

type Result struct {
	Environment model.Environment
	CPU         model.CPU
	Memory      model.Memory
	Disk        model.Disk
}

func Collect(workDir string) Result {
	result := Result{
		Environment: model.Environment{
			CountryCode:    "ZZ",
			Country:        "未知",
			Region:         "未知",
			City:           "未知",
			Timezone:       "UTC",
			OSName:         runtime.GOOS,
			OSVersion:      "未识别",
			Kernel:         kernelVersion(),
			Architecture:   architecture(),
			Virtualization: virtualization(),
			LoadAverage:    loadAverage(),
			UptimeSeconds:  uptimeSeconds(),
			ProcessCount:   processCount(),
			ServiceCount:   0,
		},
		CPU: model.CPU{
			Model:      "未识别",
			Sockets:    1,
			Cores:      runtime.NumCPU(),
			Threads:    runtime.NumCPU(),
			Features:   []string{},
			Confidence: "medium",
		},
		Memory: model.Memory{Confidence: "medium"},
		Disk:   model.Disk{Type: "未识别", Confidence: "medium"},
	}

	if runtime.GOOS == "linux" {
		readOSRelease(&result.Environment)
		readCPUInfo(&result.CPU)
		readCPUHardware(&result.CPU)
		readMemoryInfo(&result.Memory)
		readMemoryFeatures(&result.Memory)
		result.Environment.Container = containerType()
		result.Environment.ClockSource = readOptional("/sys/devices/system/clocksource/clocksource0/current_clocksource")
		result.Environment.BIOSVendor = readOptional("/sys/class/dmi/id/bios_vendor")
		result.Environment.Chipset = firstOptional(
			readOptional("/sys/class/dmi/id/board_name"),
			readOptional("/sys/class/dmi/id/product_name"),
		)
		result.Environment.NICModel = nicModel()
		result.Environment.Locale = environmentLocale()
		result.Environment.ServiceCount = runningServiceCount()
	}
	readDisk(workDir, &result.Disk)
	readDiskDetails(workDir, &result.Disk)
	return result
}

func architecture() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

func kernelVersion() string {
	output, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return runtime.GOOS
	}
	return strings.TrimSpace(string(output))
}

func virtualization() string {
	if runtime.GOOS != "linux" {
		return "未识别"
	}
	if output, err := exec.Command("systemd-detect-virt", "--vm").Output(); err == nil {
		if value := normalizeVirtualization(strings.TrimSpace(string(output))); value != "" {
			return value
		}
	}
	parts := []string{}
	for _, path := range []string{
		"/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/board_vendor", "/sys/hypervisor/type",
	} {
		if value := readOptional(path); value != nil {
			parts = append(parts, *value)
		}
	}
	if value := normalizeVirtualization(strings.Join(parts, " ")); value != "" {
		return value
	}
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil && strings.Contains(strings.ToLower(string(data)), "hypervisor") {
		return "虚拟机（类型未识别）"
	}
	return "未识别"
}

func readOSRelease(environment *model.Environment) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return
	}
	defer file.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if found {
			values[key] = strings.Trim(value, `"'`)
		}
	}
	if values["NAME"] != "" {
		environment.OSName = values["NAME"]
	}
	if values["VERSION_ID"] != "" {
		environment.OSVersion = values["VERSION_ID"]
	}
}

func readCPUInfo(cpu *model.CPU) {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "model name", "Hardware":
			if cpu.Model == "未识别" {
				cpu.Model = value
			}
		case "cpu MHz":
			if cpu.FrequencyMHz.Current == nil {
				if mhz, err := strconv.ParseFloat(value, 64); err == nil {
					cpu.FrequencyMHz.Current = &mhz
				}
			}
		case "flags", "Features":
			if len(cpu.Features) == 0 {
				allowed := map[string]string{
					"aes": "AES", "avx": "AVX", "avx2": "AVX2",
					"bmi1": "BMI", "bmi2": "BMI2", "vmx": "VT-x", "svm": "AMD-V",
				}
				for _, flag := range strings.Fields(value) {
					if normalized, ok := allowed[flag]; ok {
						cpu.Features = append(cpu.Features, normalized)
					}
				}
			}
		}
	}
}

func readMemoryInfo(memory *model.Memory) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer file.Close()
	values := map[string]int64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err == nil {
			values[strings.TrimSuffix(fields[0], ":")] = value * 1024
		}
	}
	memory.TotalBytes = values["MemTotal"]
	memory.AvailableBytes = values["MemAvailable"]
	memory.UsedBytes = memory.TotalBytes - memory.AvailableBytes
	memory.SwapTotalBytes = values["SwapTotal"]
	memory.SwapUsedBytes = values["SwapTotal"] - values["SwapFree"]
}

func normalizeVirtualization(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "kvm"), strings.Contains(lower, "qemu"):
		return "KVM"
	case strings.Contains(lower, "vmware"):
		return "VMware"
	case strings.Contains(lower, "virtualbox"), strings.Contains(lower, "oracle corporation"):
		return "VirtualBox"
	case strings.Contains(lower, "microsoft"), strings.Contains(lower, "hyper-v"), strings.Contains(lower, "virtual machine"):
		return "Hyper-V"
	case strings.Contains(lower, "xen"):
		return "Xen"
	case strings.Contains(lower, "openvz"):
		return "OpenVZ"
	case strings.Contains(lower, "bhyve"):
		return "bhyve"
	case strings.Contains(lower, "parallels"):
		return "Parallels"
	case strings.Contains(lower, "amazon ec2"):
		return "Amazon EC2"
	case strings.Contains(lower, "google compute"):
		return "Google Compute Engine"
	default:
		return ""
	}
}

func readCPUHardware(cpu *model.CPU) {
	for _, spec := range []struct {
		path   string
		target **float64
	}{
		{"/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq", &cpu.FrequencyMHz.Minimum},
		{"/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", &cpu.FrequencyMHz.Maximum},
	} {
		if value := readOptional(spec.path); value != nil {
			if khz, err := strconv.ParseFloat(*value, 64); err == nil {
				mhz := khz / 1000
				*spec.target = &mhz
			}
		}
	}

	cachePaths, _ := filepath.Glob("/sys/devices/system/cpu/cpu0/cache/index*")
	var l1 int64
	for _, path := range cachePaths {
		level := readOptional(filepath.Join(path, "level"))
		size := readOptional(filepath.Join(path, "size"))
		if level == nil || size == nil {
			continue
		}
		bytes := parseCacheBytes(*size)
		switch *level {
		case "1":
			l1 += bytes
		case "2":
			setMaxInt64(&cpu.Cache.L2Bytes, bytes)
		case "3":
			setMaxInt64(&cpu.Cache.L3Bytes, bytes)
		}
	}
	if l1 > 0 {
		cpu.Cache.L1Bytes = &l1
	}
}

func parseCacheBytes(value string) int64 {
	value = strings.TrimSpace(strings.ToUpper(value))
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(value, "K"):
		multiplier = 1024
		value = strings.TrimSuffix(value, "K")
	case strings.HasSuffix(value, "M"):
		multiplier = 1024 * 1024
		value = strings.TrimSuffix(value, "M")
	}
	number, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0
	}
	return number * multiplier
}

func setMaxInt64(target **int64, value int64) {
	if value <= 0 {
		return
	}
	if *target == nil || value > **target {
		copy := value
		*target = &copy
	}
}

func readMemoryFeatures(memory *model.Memory) {
	if data, err := os.ReadFile("/sys/kernel/mm/ksm/run"); err == nil {
		value := strings.TrimSpace(string(data)) == "1"
		memory.KSMEnabled = &value
	}
	for _, path := range []string{"/sys/module/virtio_balloon", "/sys/devices/virtual/balloon"} {
		if _, err := os.Stat(path); err == nil {
			value := true
			memory.BalloonEnabled = &value
			return
		}
	}
	value := false
	memory.BalloonEnabled = &value
}

func readDisk(workDir string, disk *model.Disk) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(workDir, &stat); err != nil {
		return
	}
	blockSize := int64(stat.Bsize)
	disk.TotalBytes = int64(stat.Blocks) * blockSize
	disk.AvailableBytes = int64(stat.Bavail) * blockSize
	disk.UsedBytes = disk.TotalBytes - int64(stat.Bfree)*blockSize
}

func readDiskDetails(workDir string, disk *model.Disk) {
	output, err := exec.Command("findmnt", "-n", "-o", "SOURCE,FSTYPE", "-T", workDir).Output()
	if err != nil {
		return
	}
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) < 2 {
		return
	}
	source, filesystem := fields[0], fields[1]
	disk.Filesystem = &filesystem
	switch {
	case strings.HasPrefix(source, "/dev/nvme"):
		disk.Type = "NVMe"
	case strings.HasPrefix(source, "/dev/"):
		device := rootBlockDevice(filepath.Base(source))
		if rotational := readOptional(filepath.Join("/sys/class/block", device, "queue/rotational")); rotational != nil {
			if *rotational == "1" {
				disk.Type = "HDD"
			} else {
				disk.Type = "SSD"
			}
		} else {
			disk.Type = "虚拟磁盘"
		}
	case source == "overlay":
		disk.Type = "容器叠加磁盘"
	default:
		disk.Type = "虚拟磁盘"
	}
}

func rootBlockDevice(device string) string {
	resolved, err := filepath.EvalSymlinks(filepath.Join("/sys/class/block", device))
	if err != nil {
		return device
	}
	parent := filepath.Base(filepath.Dir(resolved))
	if parent == "block" {
		return device
	}
	return parent
}

func loadAverage() [3]float64 {
	var result [3]float64
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return result
	}
	fields := strings.Fields(string(data))
	for index := 0; index < 3 && index < len(fields); index++ {
		result[index], _ = strconv.ParseFloat(fields[index], 64)
	}
	return result
}

func uptimeSeconds() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	value, _ := strconv.ParseFloat(strings.Fields(string(data))[0], 64)
	return int64(value)
}

func processCount() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err == nil {
			count++
		}
	}
	return count
}

func runningServiceCount() int {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "systemctl",
		"--no-pager", "--no-legend", "--type=service", "--state=running", "list-units").Output()
	if err != nil {
		return 0
	}
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

func environmentLocale() *string {
	for _, key := range []string{"LC_ALL", "LANG"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return &value
		}
	}
	return nil
}

func nicModel() *string {
	iface := defaultIPv4Interface()
	if iface == "" {
		return nil
	}
	if link, err := filepath.EvalSymlinks(filepath.Join("/sys/class/net", iface, "device/driver")); err == nil {
		value := filepath.Base(link)
		return &value
	}
	if data, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "device/uevent")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if value, found := strings.CutPrefix(line, "DRIVER="); found && value != "" {
				return &value
			}
		}
	}
	return nil
}

func defaultIPv4Interface() string {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[1] == "00000000" {
			flags, _ := strconv.ParseUint(fields[3], 16, 64)
			if flags&1 != 0 {
				return fields[0]
			}
		}
	}
	return ""
}

func containerType() *string {
	for path, name := range map[string]string{
		"/.dockerenv":        "docker",
		"/run/.containerenv": "podman",
	} {
		if _, err := os.Stat(path); err == nil {
			value := name
			return &value
		}
	}
	return nil
}

func firstOptional(values ...*string) *string {
	for _, value := range values {
		if value != nil && strings.TrimSpace(*value) != "" {
			return value
		}
	}
	return nil
}

func readOptional(path string) *string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return nil
	}
	return &value
}
