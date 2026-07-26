package identity

import (
	"net/url"
	"strings"
	"testing"
)

func TestReportURLIsPublicAndContainsNoSecret(t *testing.T) {
	value := ReportURL("https://report.example", "nb_example")
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Fragment != "" || parsed.RawQuery != "" || strings.Contains(value, "secret") {
		t.Fatalf("public report URL contains credentials: %s", value)
	}
}
