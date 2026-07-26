package ipservice

import (
	"encoding/json"
	"net"
	"testing"
)

func TestNormalizeAttributeType(t *testing.T) {
	datacenter := true
	if got := normalizeAttributeType("isp", &datacenter); got != "datacenter" {
		t.Fatalf("normalizeAttributeType datacenter = %q", got)
	}
	if got := normalizeAttributeType("isp", nil); got != "residential" {
		t.Fatalf("normalizeAttributeType isp = %q", got)
	}
	if got := normalizeAttributeType("business", nil); got != "business" {
		t.Fatalf("normalizeAttributeType business = %q", got)
	}
}

func TestNativeIPTypeMatchesNodeQualityCountryRule(t *testing.T) {
	if kind, native := nativeIPType("US", "US"); kind != "native" || native != true {
		t.Fatalf("same country = %q, %#v", kind, native)
	}
	if kind, native := nativeIPType("US", "HK"); kind != "broadcast" || native != false {
		t.Fatalf("different country = %q, %#v", kind, native)
	}
	if kind, native := nativeIPType("US", ""); kind != "unknown" || native != nil {
		t.Fatalf("missing registration = %q, %#v", kind, native)
	}
}

func TestPublicIPRejectsPrivateAddresses(t *testing.T) {
	if publicIP(net.ParseIP("10.0.0.1")) {
		t.Fatal("private address accepted")
	}
	if !publicIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("public address rejected")
	}
}

func TestRiskLevelUsesIncreasingSeverity(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{10, "low"}, {30, "medium_low"}, {60, "medium"}, {90, "high"},
	}
	for _, test := range tests {
		if got := riskLevel(test.score); got != test.want {
			t.Fatalf("riskLevel(%v) = %q, want %q", test.score, got, test.want)
		}
	}
}

func TestParseRiskScoreSupportsIPAPIFormats(t *testing.T) {
	tests := []struct {
		raw  string
		want float64
	}{
		{`"0.0018 (Low)"`, 0},
		{`0.456`, 46},
		{`"0.995 (Very High)"`, 100},
	}
	for _, test := range tests {
		got, ok := parseRiskScore(json.RawMessage(test.raw)).(float64)
		if !ok || got != test.want {
			t.Fatalf("parseRiskScore(%s) = %v, want %v", test.raw, got, test.want)
		}
	}
	if got := parseRiskScore(json.RawMessage(`"unknown"`)); got != nil {
		t.Fatalf("parseRiskScore unknown = %v, want nil", got)
	}
}
