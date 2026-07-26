package upload

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nodebench/nodebench/internal/model"
)

func TestSendRejectsMismatchedWorkerIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_, _ = response.Write([]byte(`{
			"report_id":"nb_wrong_report",
			"status":"created",
			"view_path":"/report/nb_wrong_report",
			"expires_at":"2026-10-01T00:00:00Z"
		}`))
	}))
	defer server.Close()

	_, err := Send(context.Background(), server.URL, model.UploadEnvelope{
		Credentials: model.Credentials{
			UploadSecret: "upload",
		},
		Report: model.Report{ReportID: "nb_expected_report"},
	})
	if err == nil {
		t.Fatal("expected mismatched report identity to fail")
	}
}
