package main

import (
	"testing"

	"github.com/nodebench/nodebench/internal/model"
)

func TestApplyStage3CompletenessUsesMeasuredFields(t *testing.T) {
	report := model.Report{
		Modules: []model.Module{
			{ID: "environment", Status: "success"},
			{ID: "performance", Status: "success"},
			{ID: "network_stack", Status: "success"},
			{ID: "china_network", Status: "success"},
			{ID: "routes", Status: "success"},
			{ID: "bandwidth", Status: "success"},
			{ID: "ip_services", Status: "partial"},
			{ID: "scoring", Status: "success"},
		},
		IPQuality: map[string]any{"risk_score": float64(12)},
		Services: []any{
			map[string]any{"available": true},
			map[string]any{"available": false},
		},
	}
	applyStage3Completeness(&report)
	if report.Completeness.Ratio != 1 {
		t.Fatalf("ratio = %v, want 1", report.Completeness.Ratio)
	}
	if len(report.Completeness.MissingFields) != 0 {
		t.Fatalf("missing fields = %#v", report.Completeness.MissingFields)
	}
	if report.Completeness.SuccessfulModules != 7 || report.Completeness.PartialModules != 1 {
		t.Fatalf("module counts = %#v", report.Completeness)
	}
}

func TestApplyStage3CompletenessReportsSkippedModules(t *testing.T) {
	report := model.Report{
		Modules: []model.Module{
			{ID: "environment", Status: "success"},
			{ID: "performance", Status: "skipped"},
			{ID: "network_stack", Status: "success"},
			{ID: "china_network", Status: "skipped"},
			{ID: "routes", Status: "skipped"},
			{ID: "bandwidth", Status: "skipped"},
			{ID: "ip_services", Status: "success"},
			{ID: "scoring", Status: "success"},
		},
		IPQuality: map[string]any{"ip_type": "datacenter"},
		Services: []any{
			map[string]any{"available": true},
			map[string]any{"available": nil},
		},
	}
	applyStage3Completeness(&report)
	if report.Completeness.Ratio != 0.35 {
		t.Fatalf("ratio = %v, want 0.35", report.Completeness.Ratio)
	}
	if len(report.Completeness.MissingFields) != 5 {
		t.Fatalf("missing fields = %#v", report.Completeness.MissingFields)
	}
}
