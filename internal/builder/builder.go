package builder

import (
	"time"

	"github.com/nodebench/nodebench/internal/collector"
	"github.com/nodebench/nodebench/internal/model"
)

func New(reportID string, startedAt time.Time, user model.UserSupplied, system collector.Result) model.Report {
	dimension := func() map[string]any {
		return map[string]any{
			"value": 0, "grade": "N/A", "confidence": "low", "completeness": 0,
			"positives": []string{}, "negatives": []string{},
		}
	}
	useCase := func() map[string]any {
		return map[string]any{"value": 0, "verdict": "数据不足", "reason": "对应测评模块尚未执行"}
	}
	return model.Report{
		SchemaVersion:      "1.0.0",
		ClientVersion:      model.ClientVersion,
		ScoringVersion:     "1.0.0",
		NodeCatalogVersion: "2026.07.1",
		ReportID:           reportID,
		Status:             "completed_local_only",
		Visibility:         "public",
		StartedAt:          startedAt.UTC(),
		CompletedAt:        time.Now().UTC(),
		UserSupplied:       user,
		Environment:        system.Environment,
		CPU:                system.CPU,
		Memory:             system.Memory,
		Disk:               system.Disk,
		Network: map[string]any{
			"ipv4_available": false, "ipv6_available": false,
			"nat_type": nil, "congestion_control": nil, "queue_discipline": nil,
			"mtu": nil, "tcp_rmem_bytes": []int64{0, 0, 0}, "tcp_wmem_bytes": []int64{0, 0, 0},
			"dns_latency_ms": nil, "dnssec_available": nil,
			"bgp": map[string]any{
				"registry": nil, "updated_at": nil, "upstream_count": 0, "peer_count": 0,
				"exchange_count": 0, "active_neighbor_count": 0, "prefix_utilization": nil,
			},
			"ports": []any{}, "china_carriers": []any{}, "province_tcp": []any{},
			"tcp_quality_summary": map[string]any{
				"zero_retransmission_count": 0, "light_retransmission_count": 0, "severe_retransmission_count": 0,
			},
			"global_targets": []any{}, "cdn_targets": []any{},
			"global_target_summary": map[string]any{"tested": 0, "reachable": 0, "median_latency_ms": nil},
			"cdn_target_summary":    map[string]any{"tested": 0, "reachable": 0, "median_latency_ms": nil},
			"traffic_bytes":         0, "traffic_hard_limit_bytes": 12 * 1024 * 1024 * 1024, "max_concurrency": 2,
		},
		Routes:   []any{},
		Services: []any{},
		IPQuality: map[string]any{
			"ip_type": "unknown", "native_ip": nil, "usage_type": "unknown",
			"company_type": "unknown", "usage_country_code": nil,
			"registration_country_code": nil, "risk_score": nil, "risk_level": "unknown",
			"residential_probability": nil, "proxy": nil, "vpn": nil, "tor": nil,
			"server": nil, "abuse": nil, "bot": nil, "risk_sources": []any{},
			"blacklist": map[string]any{"checked": 0, "clean": 0, "listed": 0, "unknown": 0},
		},
		Scores: map[string]any{
			"overall": map[string]any{"value": 0, "grade": "N/A", "confidence": "low", "completeness": 0.2},
			"dimensions": map[string]any{
				"compute": dimension(), "storage": dimension(), "china_network": dimension(),
				"routes": dimension(), "ip": dimension(), "web": dimension(),
			},
			"use_cases": map[string]any{
				"website": useCase(), "relay": useCase(), "egress": useCase(),
				"compute": useCase(), "storage": useCase(), "email": useCase(),
			},
			"value": nil,
		},
		SemanticEvaluation: map[string]any{
			"headline":  "基础环境采集完成",
			"summary":   "当前构建仅完成系统、CPU、内存和磁盘容量采集；性能、网络、线路和 IP 模块将在后续阶段接入。",
			"strengths": []string{}, "risks": []string{"网络与性能数据尚未采集"},
			"recommended_for": []string{}, "not_recommended_for": []string{},
		},
		Modules: []model.Module{
			{ID: "environment", Status: "success", Confidence: "medium"},
			{ID: "performance", Status: "skipped", Confidence: "low", Message: stringPointer("阶段 3 后续接入")},
			{ID: "china_network", Status: "skipped", Confidence: "low", Message: stringPointer("阶段 3 后续接入")},
			{ID: "routes", Status: "skipped", Confidence: "low", Message: stringPointer("阶段 3 后续接入")},
			{ID: "ip_services", Status: "skipped", Confidence: "low", Message: stringPointer("阶段 3 后续接入")},
		},
		Completeness: model.Completeness{
			Ratio: 0.2, SuccessfulModules: 1, MissingFields: []string{
				"cpu.benchmarks", "memory.benchmarks", "disk.benchmarks",
				"network.china_carriers", "routes", "ip_quality", "services", "scores",
			},
		},
		Warnings: []model.Warning{},
	}
}

func Finalize(report *model.Report) {
	report.CompletedAt = time.Now().UTC()
	report.DurationMS = report.CompletedAt.Sub(report.StartedAt).Milliseconds()
}

func stringPointer(value string) *string {
	return &value
}
