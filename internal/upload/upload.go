package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nodebench/nodebench/internal/model"
)

const maxPayloadBytes = 256 * 1024

type Result struct {
	ReportID  string `json:"report_id"`
	Status    string `json:"status"`
	ViewPath  string `json:"view_path"`
	ExpiresAt string `json:"expires_at"`
}

func Send(ctx context.Context, workerURL string, envelope model.UploadEnvelope) (Result, error) {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return Result{}, fmt.Errorf("生成上传载荷: %w", err)
	}
	if len(payload) > maxPayloadBytes {
		return Result{}, fmt.Errorf("上传载荷超过 256 KiB")
	}
	endpoint := strings.TrimRight(workerURL, "/") + "/api/reports"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return Result{}, fmt.Errorf("创建上传请求: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "NodeBench/"+model.ClientVersion)
	response, err := (&http.Client{Timeout: 20 * time.Second}).Do(request)
	if err != nil {
		return Result{}, fmt.Errorf("上传报告: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return Result{}, fmt.Errorf("读取 Worker 响应: %w", err)
	}
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("Worker 返回 HTTP %d", response.StatusCode)
	}
	var result Result
	if err := json.Unmarshal(body, &result); err != nil {
		return Result{}, fmt.Errorf("解析 Worker 响应: %w", err)
	}
	expectedPath := "/report/" + envelope.Report.ReportID
	if result.ReportID != envelope.Report.ReportID || result.ViewPath != expectedPath {
		return Result{}, fmt.Errorf("Worker 返回的报告标识或路径不匹配")
	}
	return result, nil
}
