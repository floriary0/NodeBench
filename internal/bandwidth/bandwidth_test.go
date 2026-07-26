package bandwidth

import "testing"

func TestParseRate(t *testing.T) {
	tests := []struct {
		output string
		want   float64
	}{
		{"Average download rate: 123.4MB/s", 987200000},
		{"Average upload rate: 1.5GB/s", 12000000000},
	}
	for _, test := range tests {
		got := parseRate([]byte(test.output))
		if got == nil || *got != test.want {
			t.Fatalf("parseRate(%q) = %v, want %v", test.output, got, test.want)
		}
	}
	if got := parseRate([]byte("probe failed")); got != nil {
		t.Fatalf("parseRate failure = %v, want nil", *got)
	}
}

func TestNormalizeCarrier(t *testing.T) {
	for input, want := range map[string]string{"电信": "telecom", "CU": "unicom", "ChinaMobile": "mobile"} {
		if got := normalizeCarrier(input); got != want {
			t.Fatalf("normalizeCarrier(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestEnrichRouteAddsMissingRouteData(t *testing.T) {
	row := map[string]any{"carrier": "telecom", "return_route": nil}
	routes := []any{map[string]any{
		"carrier": "telecom", "route_type": "CN2 GIA",
		"entry_city": "上海", "as_path": []int64{4134, 4809},
	}}
	enrichRoute(row, routes, "telecom")
	if row["return_route"] != "CN2 GIA" || row["entry_city"] != "上海" {
		t.Fatalf("enrichRoute = %#v", row)
	}
	path, ok := row["asn_path"].([]int64)
	if !ok || len(path) != 2 || path[1] != 4809 {
		t.Fatalf("enrichRoute asn_path = %#v", row["asn_path"])
	}
}

func TestCarrierRouteUsesMostCommonReturnRoute(t *testing.T) {
	routes := []any{
		map[string]any{"carrier": "telecom", "route_type": "CN2GIA", "as_path": []int64{4809}},
		map[string]any{"carrier": "telecom", "route_type": "163", "as_path": []int64{4134}},
		map[string]any{"carrier": "telecom", "route_type": "163", "as_path": []int64{4134}},
	}
	routeType, _, asPath := carrierRoute(routes, "telecom")
	if routeType != "163" || len(asPath) != 1 || asPath[0] != 4134 {
		t.Fatalf("carrierRoute = %#v, %#v", routeType, asPath)
	}
}
