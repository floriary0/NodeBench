package render

import (
	"fmt"
	"math"
	"strings"

	"github.com/nodebench/nodebench/internal/model"
)

func Text(report model.Report, viewURL string) string {
	provider := valueOr(report.UserSupplied.Provider, "未填写厂商")
	plan := valueOr(report.UserSupplied.Plan, "未填写套餐")
	var builder strings.Builder
	fmt.Fprintf(&builder, "NodeBench %s\n", report.ClientVersion)
	fmt.Fprintf(&builder, "报告：%s\n", report.ReportID)
	fmt.Fprintf(&builder, "VPS ：%s · %s\n", provider, plan)
	fmt.Fprintf(&builder, "系统：%s %s · %s · %s\n",
		report.Environment.OSName, report.Environment.OSVersion,
		report.Environment.Architecture, report.Environment.Virtualization)
	fmt.Fprintf(&builder, "CPU ：%s · %d vCPU\n", report.CPU.Model, report.CPU.Cores)
	fmt.Fprintf(&builder, "内存：%s GiB · 可用 %s GiB\n",
		gibibytes(report.Memory.TotalBytes), gibibytes(report.Memory.AvailableBytes))
	fmt.Fprintf(&builder, "磁盘：%d GiB · 可用 %d GiB\n",
		int64(math.Round(float64(report.Disk.TotalBytes)/(1<<30))),
		int64(math.Round(float64(report.Disk.AvailableBytes)/(1<<30))))
	fmt.Fprintf(&builder, "CPU ：单核 %s events/s · 多核 %s events/s\n",
		number(report.CPU.SingleCoreScore), number(report.CPU.MultiCoreScore))
	fmt.Fprintf(&builder, "内存：读 %s · 写 %s · 延迟 %s\n",
		rate(report.Memory.ReadBytesPerSecond), rate(report.Memory.WriteBytesPerSecond),
		nanoseconds(report.Memory.LatencyNS))
	fmt.Fprintf(&builder, "磁盘：顺序读 %s · 顺序写 %s · 4K Q32 读/写 %s/%s IOPS\n",
		rate(report.Disk.SequentialReadBytesPerSecond),
		rate(report.Disk.SequentialWriteBytesPerSecond),
		number(report.Disk.Random4KReadIOPS), number(report.Disk.Random4KWriteIOPS))
	fmt.Fprintf(&builder, "TCP ：三网 %d 节点 · 国际站点 %d/%d 可达 · CDN %d/%d 可达 · 流量 %s\n",
		arrayLength(report.Network["province_tcp"]),
		summaryInt(report.Network["global_target_summary"], "reachable"),
		summaryInt(report.Network["global_target_summary"], "tested"),
		summaryInt(report.Network["cdn_target_summary"], "reachable"),
		summaryInt(report.Network["cdn_target_summary"], "tested"),
		byteSize(report.Network["traffic_bytes"]))
	fmt.Fprintf(&builder, "线路：%d 条回程 · %s\n", len(report.Routes), routeTypes(report.Routes))
	fmt.Fprintf(&builder, "IP  ：%s · 风险 %s/100 · 服务 %d/%d 可用\n",
		valueOr(report.Environment.MaskedIPv4, "未测"),
		mapNumber(report.IPQuality, "risk_score"),
		availableServices(report.Services), len(report.Services))
	fmt.Fprintf(&builder, "评分：%s 分 · %s · 完整度 %d%%\n",
		overallValue(report.Scores), overallGrade(report.Scores),
		int64(math.Round(report.Completeness.Ratio*100)))
	fmt.Fprintf(&builder, "结论：%s\n", mapString(report.SemanticEvaluation, "summary", "数据不足"))
	if len(report.Warnings) > 0 {
		fmt.Fprintf(&builder, "异常：")
		for index, warning := range report.Warnings {
			if index > 0 {
				fmt.Fprintf(&builder, " · ")
			}
			fmt.Fprintf(&builder, "[%s] %s", warning.Severity, warning.Message)
		}
		fmt.Fprintln(&builder)
	}
	fmt.Fprintf(&builder, "报告链接：%s\n", viewURL)
	return builder.String()
}

func routeTypes(routes []any) string {
	counts := map[string]int{}
	order := make([]string, 0)
	for _, value := range routes {
		route, ok := value.(map[string]any)
		if !ok {
			continue
		}
		label, _ := route["route_type"].(string)
		if label == "" {
			continue
		}
		if counts[label] == 0 {
			order = append(order, label)
		}
		counts[label]++
	}
	if len(order) == 0 {
		return "未测"
	}
	parts := make([]string, 0, len(order))
	for _, label := range order {
		parts = append(parts, fmt.Sprintf("%s×%d", label, counts[label]))
	}
	return strings.Join(parts, " · ")
}

func arrayLength(value any) int {
	if values, ok := value.([]any); ok {
		return len(values)
	}
	return 0
}

func summaryInt(value any, key string) int {
	summary, ok := value.(map[string]any)
	if !ok {
		return 0
	}
	switch number := summary[key].(type) {
	case int:
		return number
	case int64:
		return int(number)
	case float64:
		return int(number)
	default:
		return 0
	}
}

func byteSize(value any) string {
	var bytes int64
	switch number := value.(type) {
	case int:
		bytes = int64(number)
	case int64:
		bytes = number
	case float64:
		bytes = int64(number)
	}
	return fmt.Sprintf("%d MiB", int64(math.Round(float64(bytes)/(1024*1024))))
}

func valueOr(value *string, fallback string) string {
	if value == nil || *value == "" {
		return fallback
	}
	return *value
}

func number(value *float64) string {
	if value == nil {
		return "未测"
	}
	return fmt.Sprintf("%d", int64(math.Round(*value)))
}

func rate(value *float64) string {
	if value == nil {
		return "未测"
	}
	return fmt.Sprintf("%d MiB/s", int64(math.Round(*value/(1024*1024))))
}

func availableServices(services []any) int {
	count := 0
	for _, raw := range services {
		service, ok := raw.(map[string]any)
		available, availableOK := service["available"].(bool)
		if ok && availableOK && available {
			count++
		}
	}
	return count
}

func mapNumber(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok || value == nil {
		return "未测"
	}
	number, ok := numeric(value)
	if !ok {
		return "未测"
	}
	return fmt.Sprintf("%d", int64(math.Round(number)))
}

func overallValue(scores map[string]any) string {
	overall, ok := scores["overall"].(map[string]any)
	if !ok {
		return "未测"
	}
	return mapNumber(overall, "value")
}

func overallGrade(scores map[string]any) string {
	overall, ok := scores["overall"].(map[string]any)
	if !ok {
		return "N/A"
	}
	return mapString(overall, "grade", "N/A")
}

func mapString(values map[string]any, key, fallback string) string {
	value, ok := values[key].(string)
	if !ok || value == "" {
		return fallback
	}
	return value
}

func numeric(value any) (float64, bool) {
	switch number := value.(type) {
	case int:
		return float64(number), true
	case int64:
		return float64(number), true
	case float64:
		return number, true
	default:
		return 0, false
	}
}

func gibibytes(value int64) string {
	gib := float64(value) / (1 << 30)
	if value > 0 && gib < 1 {
		return fmt.Sprintf("%.1f", gib)
	}
	return fmt.Sprintf("%d", int64(math.Round(gib)))
}

func nanoseconds(value *float64) string {
	if value == nil {
		return "未测"
	}
	return fmt.Sprintf("%.0f ns", *value)
}
