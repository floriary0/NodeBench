package scoring

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/nodebench/nodebench/internal/model"
)

type dimension struct {
	Value        int
	Grade        string
	Confidence   string
	Completeness float64
	Positives    []string
	Negatives    []string
	Available    bool
}

// Apply calculates deterministic v1 scores only from fields already present in
// the report. Missing modules remain N/A and are excluded from the overall
// weighted average instead of being treated as a zero score.
func Apply(report *model.Report) {
	compute := computeScore(report)
	storage := storageScore(report)
	china := chinaNetworkScore(report)
	route := routeScore(report)
	ip := ipScore(report)
	web := webScore(compute, storage, china, route)

	dimensions := map[string]dimension{
		"compute": compute, "storage": storage, "china_network": china,
		"routes": route, "ip": ip, "web": web,
	}
	weights := map[string]float64{
		"compute": 0.20, "storage": 0.15, "china_network": 0.25,
		"routes": 0.20, "ip": 0.10, "web": 0.10,
	}
	weighted, totalWeight, completeness := 0.0, 0.0, 0.0
	for name, value := range dimensions {
		if !value.Available {
			continue
		}
		weight := weights[name]
		weighted += float64(value.Value) * weight
		totalWeight += weight
		completeness += value.Completeness * weight
	}
	overall := 0
	overallGrade := "N/A"
	confidence := "low"
	if totalWeight > 0 {
		overall = round(weighted / totalWeight)
		overallGrade = grade(overall)
		completeness /= totalWeight
		if completeness >= 0.85 {
			confidence = "high"
		} else if completeness >= 0.55 {
			confidence = "medium"
		}
	}

	report.Scores = map[string]any{
		"overall": map[string]any{
			"value": overall, "grade": overallGrade, "confidence": confidence,
			"completeness": roundRatio(completeness),
		},
		"dimensions": map[string]any{
			"compute": dimensionMap(compute), "storage": dimensionMap(storage),
			"china_network": dimensionMap(china), "routes": dimensionMap(route),
			"ip": dimensionMap(ip), "web": dimensionMap(web),
		},
		"use_cases": buildUseCases(compute, storage, china, route, ip, web),
		"value":     valueScore(report, overall),
	}
	report.ScoringVersion = "1.0.0"
	report.SemanticEvaluation = semanticEvaluation(overall, compute, storage, china, route, ip)
}

func computeScore(report *model.Report) dimension {
	if report.CPU.SingleCoreScore == nil && report.CPU.MultiCoreScore == nil {
		return unavailable()
	}
	values := []float64{}
	if report.CPU.SingleCoreScore != nil {
		values = append(values, clamp(*report.CPU.SingleCoreScore/2800*100))
	}
	if report.CPU.MultiCoreScore != nil {
		target := 2600.0 * float64(max(report.CPU.Cores, 1))
		values = append(values, clamp(*report.CPU.MultiCoreScore/target*100))
	}
	value := average(values)
	result := available(value, report.CPU.Confidence, float64(len(values))/2)
	if value >= 80 {
		result.Positives = append(result.Positives, "CPU 吞吐表现良好")
	} else if value < 55 {
		result.Negatives = append(result.Negatives, "CPU 性能偏弱")
	}
	return result
}

func storageScore(report *model.Report) dimension {
	values := []float64{}
	appendRatio := func(value *float64, target float64) {
		if value != nil {
			values = append(values, clamp(*value/target*100))
		}
	}
	appendRatio(report.Disk.SequentialReadBytesPerSecond, 1.2e9)
	appendRatio(report.Disk.SequentialWriteBytesPerSecond, 8e8)
	appendRatio(report.Disk.Random4KReadIOPS, 60000)
	appendRatio(report.Disk.Random4KWriteIOPS, 40000)
	if len(values) == 0 {
		return unavailable()
	}
	value := average(values)
	result := available(value, report.Disk.Confidence, float64(len(values))/4)
	if value >= 80 {
		result.Positives = append(result.Positives, "磁盘吞吐与随机性能良好")
	} else if value < 55 {
		result.Negatives = append(result.Negatives, "磁盘性能偏弱")
	}
	return result
}

func chinaNetworkScore(report *model.Report) dimension {
	rows, ok := report.Network["province_tcp"].([]any)
	if !ok || len(rows) == 0 {
		return unavailable()
	}
	latencies := []float64{}
	retransmissions := []float64{}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if value, ok := asFloat(row["latency_ms"]); ok {
			latencies = append(latencies, value)
		}
		if value, ok := asFloat(row["retransmission_ratio"]); ok {
			retransmissions = append(retransmissions, value)
		}
	}
	if len(latencies) == 0 && len(retransmissions) == 0 {
		return unavailable()
	}
	latency := median(latencies)
	retransmission := average(retransmissions)
	latencyScore := clamp(108 - math.Max(0, latency-50)*0.22)
	retransmissionScore := clamp(100 - retransmission*180)
	value := latencyScore
	if len(retransmissions) > 0 {
		value = latencyScore*0.65 + retransmissionScore*0.35
	}
	completeness := float64(len(rows)) / 93
	result := available(value, "high", math.Min(completeness, 1))
	if retransmission <= 0.01 {
		result.Positives = append(result.Positives, "全国节点 TCP 重传较低")
	} else if retransmission > 0.05 {
		result.Negatives = append(result.Negatives, "部分节点 TCP 重传偏高")
	}
	if latency > 220 {
		result.Negatives = append(result.Negatives, "大陆方向中位延迟偏高")
	}
	return result
}

func routeScore(report *model.Report) dimension {
	if len(report.Routes) == 0 {
		return unavailable()
	}
	values := []float64{}
	labels := map[string]int{}
	for _, raw := range report.Routes {
		route, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		label, _ := route["route_type"].(string)
		if label == "" {
			continue
		}
		labels[label]++
		values = append(values, routeValue(label))
	}
	if len(values) == 0 {
		return unavailable()
	}
	value := average(values)
	result := available(value, "high", math.Min(float64(len(values))/93, 1))
	best := bestRoute(labels)
	if best != "" && routeValue(best) >= 88 {
		result.Positives = append(result.Positives, "检测到 "+best+" 优质线路")
	}
	if value < 65 {
		result.Negatives = append(result.Negatives, "回程以普通线路为主")
	}
	return result
}

func ipScore(report *model.Report) dimension {
	values := []float64{}
	if risk, ok := asFloat(report.IPQuality["risk_score"]); ok {
		values = append(values, clamp(100-risk))
	}
	tested, availableCount := 0, 0
	for _, raw := range report.Services {
		service, ok := raw.(map[string]any)
		if !ok || service["available"] == nil {
			continue
		}
		available, ok := service["available"].(bool)
		if !ok {
			continue
		}
		tested++
		if available {
			availableCount++
		}
	}
	if tested > 0 {
		values = append(values, float64(availableCount)/float64(tested)*100)
	}
	if len(values) == 0 {
		return unavailable()
	}
	result := available(average(values), "medium", float64(len(values))/2)
	if tested > 0 && availableCount == tested {
		result.Positives = append(result.Positives, "已测服务全部可用")
	} else if tested > 0 && availableCount*2 < tested {
		result.Negatives = append(result.Negatives, "主流服务可用率偏低")
	}
	if risk, ok := asFloat(report.IPQuality["risk_score"]); ok && risk >= 60 {
		result.Negatives = append(result.Negatives, "IP 风险评分偏高")
	}
	return result
}

func webScore(compute, storage, china, route dimension) dimension {
	inputs := []struct {
		item   dimension
		weight float64
	}{{compute, .3}, {storage, .25}, {china, .2}, {route, .25}}
	total, weight, completeness := 0.0, 0.0, 0.0
	for _, input := range inputs {
		if !input.item.Available {
			continue
		}
		total += float64(input.item.Value) * input.weight
		completeness += input.item.Completeness * input.weight
		weight += input.weight
	}
	if weight == 0 {
		return unavailable()
	}
	result := available(total/weight, "medium", completeness/weight)
	if result.Value >= 80 {
		result.Positives = append(result.Positives, "性能与线路适合常规建站")
	} else if result.Value < 55 {
		result.Negatives = append(result.Negatives, "建站综合能力偏弱")
	}
	return result
}

func buildUseCases(compute, storage, china, route, ip, web dimension) map[string]any {
	return map[string]any{
		"website": useCase(weightedAvailable([]dimension{web, compute, storage}, []float64{.5, .25, .25}), "建站"),
		"relay":   useCase(weightedAvailable([]dimension{china, route}, []float64{.55, .45}), "中转"),
		"egress":  useCase(weightedAvailable([]dimension{ip, china}, []float64{.65, .35}), "落地"),
		"compute": useCase(scoreOrZero(compute), "计算"),
		"storage": useCase(scoreOrZero(storage), "存储"),
		"email":   useCase(scoreOrZero(ip), "邮件"),
	}
}

func useCase(value int, name string) map[string]any {
	verdict := "数据不足"
	reason := name + "所需模块尚未完成"
	if value > 0 {
		switch {
		case value >= 85:
			verdict = "推荐"
		case value >= 70:
			verdict = "适合"
		case value >= 55:
			verdict = "一般"
		default:
			verdict = "不建议"
		}
		reason = fmt.Sprintf("%s相关维度综合评分 %d", name, value)
	}
	return map[string]any{"value": value, "verdict": verdict, "reason": reason}
}

func valueScore(report *model.Report, overall int) any {
	price := report.UserSupplied.Price
	if price == nil || price.MonthlyEquivalentMinor == nil || price.Currency != "CNY" {
		return nil
	}
	monthly := *price.MonthlyEquivalentMinor
	if monthly <= 0 {
		return nil
	}
	affordability := clamp(100 - float64(monthly)/100*0.35)
	return map[string]any{
		"value":             round(float64(overall)*0.7 + affordability*0.3),
		"monthly_cny_minor": monthly,
	}
}

func semanticEvaluation(overall int, values ...dimension) map[string]any {
	strengths, risks := []string{}, []string{}
	missing := 0
	for _, value := range values {
		strengths = append(strengths, value.Positives...)
		risks = append(risks, value.Negatives...)
		if !value.Available {
			missing++
		}
	}
	headline := "已完成可用维度评分"
	summary := fmt.Sprintf("当前可用维度综合评分 %d 分，所有核心评分维度均已纳入。", overall)
	if missing > 0 {
		summary = fmt.Sprintf("当前可用维度综合评分 %d 分；%d 个缺失维度未按零分计入总分。", overall, missing)
	}
	recommended, notRecommended := []string{}, []string{}
	if overall >= 75 {
		recommended = append(recommended, "常规建站", "轻量计算")
	}
	if len(risks) > 0 {
		notRecommended = append(notRecommended, "对异常指标高度敏感的生产业务")
	}
	return map[string]any{
		"headline": headline, "summary": summary,
		"strengths": unique(strengths), "risks": unique(risks),
		"recommended_for": recommended, "not_recommended_for": notRecommended,
	}
}

func available(value float64, confidence string, completeness float64) dimension {
	result := dimension{
		Value: round(clamp(value)), Grade: grade(round(clamp(value))),
		Confidence: confidence, Completeness: roundRatio(completeness), Available: true,
		Positives: []string{}, Negatives: []string{},
	}
	if result.Confidence != "high" && result.Confidence != "medium" {
		result.Confidence = "low"
	}
	return result
}

func unavailable() dimension {
	return dimension{
		Value: 0, Grade: "N/A", Confidence: "low", Completeness: 0,
		Positives: []string{}, Negatives: []string{},
	}
}

func dimensionMap(value dimension) map[string]any {
	return map[string]any{
		"value": value.Value, "grade": value.Grade, "confidence": value.Confidence,
		"completeness": value.Completeness, "positives": value.Positives,
		"negatives": value.Negatives,
	}
}

func grade(value int) string {
	switch {
	case value >= 90:
		return "S"
	case value >= 80:
		return "A"
	case value >= 70:
		return "B"
	case value >= 60:
		return "C"
	default:
		return "D"
	}
}

func routeValue(label string) float64 {
	upper := strings.ToUpper(label)
	switch {
	case strings.Contains(upper, "CN2 GIA"), strings.Contains(upper, "CTG GIA"),
		strings.Contains(upper, "9929"), strings.Contains(upper, "CMIN2"),
		strings.Contains(upper, "CERNET2"):
		return 95
	case strings.Contains(upper, "CN2 GT"), strings.Contains(upper, "10099"),
		strings.Contains(upper, "CMI"), strings.Contains(upper, "CERNET"):
		return 84
	case strings.Contains(upper, "4837"), strings.Contains(upper, "163"):
		return 70
	case strings.Contains(upper, "UNKNOWN"), strings.Contains(upper, "未知"):
		return 50
	default:
		return 62
	}
}

func bestRoute(labels map[string]int) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := routeValue(keys[i]), routeValue(keys[j])
		if left == right {
			return labels[keys[i]] > labels[keys[j]]
		}
		return left > right
	})
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func weightedAvailable(values []dimension, weights []float64) int {
	total, weight := 0.0, 0.0
	for index, value := range values {
		if !value.Available {
			continue
		}
		total += float64(value.Value) * weights[index]
		weight += weights[index]
	}
	if weight == 0 {
		return 0
	}
	return round(total / weight)
}

func scoreOrZero(value dimension) int {
	if !value.Available {
		return 0
	}
	return value.Value
}

func asFloat(value any) (float64, bool) {
	switch number := value.(type) {
	case float64:
		return number, true
	case float32:
		return float64(number), true
	case int:
		return float64(number), true
	case int64:
		return float64(number), true
	default:
		return 0, false
	}
}

func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	total := 0.0
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	copyValues := append([]float64(nil), values...)
	sort.Float64s(copyValues)
	middle := len(copyValues) / 2
	if len(copyValues)%2 == 0 {
		return (copyValues[middle-1] + copyValues[middle]) / 2
	}
	return copyValues[middle]
}

func unique(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func round(value float64) int {
	return int(math.Round(value))
}

func roundRatio(value float64) float64 {
	return math.Round(math.Max(0, math.Min(1, value))*100) / 100
}

func clamp(value float64) float64 {
	return math.Max(0, math.Min(100, value))
}
