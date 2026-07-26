package privacy

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var fullIPv4 = regexp.MustCompile(`(?:^|[^0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:$|[^0-9/])`)

var forbiddenKeys = map[string]struct{}{
	"hostname":              {},
	"username":              {},
	"machine_id":            {},
	"mac":                   {},
	"mac_address":           {},
	"instance_id":           {},
	"serial":                {},
	"serial_number":         {},
	"device_path":           {},
	"mount_path":            {},
	"environment_variables": {},
	"headers":               {},
	"authorization":         {},
	"password":              {},
	"api_token":             {},
}

func MaskIP(value string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return "", fmt.Errorf("无效 IP 地址")
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return fmt.Sprintf("%d.%d.*.*", ipv4[0], ipv4[1]), nil
	}
	parts := strings.Split(ip.String(), ":")
	kept := make([]string, 0, 3)
	for _, part := range parts {
		if part == "" {
			continue
		}
		kept = append(kept, part)
		if len(kept) == 3 {
			break
		}
	}
	if len(kept) < 3 {
		return "", fmt.Errorf("IPv6 地址无法安全脱敏")
	}
	return strings.Join(kept, ":") + ":*:*:*:*:*", nil
}

func ScanJSON(payload []byte) error {
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return fmt.Errorf("解析待扫描 JSON: %w", err)
	}
	if unsafe(value, "") {
		return fmt.Errorf("结果包含禁止字段或未脱敏 IP")
	}
	return nil
}

func unsafe(value any, key string) bool {
	if _, blocked := forbiddenKeys[key]; blocked {
		return true
	}
	switch typed := value.(type) {
	case string:
		if key == "bgp_prefix" {
			return false
		}
		return fullIPv4.MatchString(typed)
	case []any:
		for _, item := range typed {
			if unsafe(item, key) {
				return true
			}
		}
	case map[string]any:
		for childKey, child := range typed {
			if unsafe(child, childKey) {
				return true
			}
		}
	}
	return false
}
