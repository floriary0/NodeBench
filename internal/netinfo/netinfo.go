package netinfo

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func Collect(network map[string]any) {
	network["ipv4_available"] = hasDefaultIPv4Route()
	network["ipv6_available"] = hasGlobalIPv6()
	network["congestion_control"] = readString("/proc/sys/net/ipv4/tcp_congestion_control")
	network["queue_discipline"] = readString("/proc/sys/net/core/default_qdisc")
	network["tcp_rmem_bytes"] = readIntArray("/proc/sys/net/ipv4/tcp_rmem", 3)
	network["tcp_wmem_bytes"] = readIntArray("/proc/sys/net/ipv4/tcp_wmem", 3)
	if iface := defaultIPv4Interface(); iface != "" {
		if value := readInt(filepath.Join("/sys/class/net", iface, "mtu")); value != nil {
			network["mtu"] = *value
		}
	}
}

func hasDefaultIPv4Route() bool {
	return defaultIPv4Interface() != ""
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

func hasGlobalIPv6() bool {
	file, err := os.Open("/proc/net/if_inet6")
	if err != nil {
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[5] == "lo" {
			continue
		}
		scope, _ := strconv.ParseUint(fields[3], 16, 8)
		if scope == 0 {
			return true
		}
	}
	return false
}

func readString(path string) any {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return nil
	}
	return value
}

func readInt(path string) *int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return nil
	}
	return &value
}

func readIntArray(path string, expected int) []int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return make([]int64, expected)
	}
	fields := strings.Fields(string(data))
	result := make([]int64, expected)
	for index := 0; index < expected && index < len(fields); index++ {
		result[index], _ = strconv.ParseInt(fields[index], 10, 64)
	}
	return result
}
