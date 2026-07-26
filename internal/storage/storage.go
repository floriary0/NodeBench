package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nodebench/nodebench/internal/model"
	"github.com/nodebench/nodebench/internal/privacy"
)

type Paths struct {
	TaskDir     string
	ReportJSON  string
	ReportText  string
	Credentials string
}

type State struct {
	ReportID      string    `json:"report_id"`
	Status        string    `json:"status"`
	CurrentModule *string   `json:"current_module"`
	Completed     int       `json:"completed_modules"`
	Total         int       `json:"total_modules"`
	UpdatedAt     time.Time `json:"updated_at"`
	LastError     *string   `json:"last_error"`
}

func DefaultRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("定位用户目录: %w", err)
	}
	return filepath.Join(home, ".local", "share", "nodebench", "tasks"), nil
}

func WriteState(root string, state State) error {
	taskDir := filepath.Join(root, state.ReportID)
	if err := os.MkdirAll(taskDir, 0o700); err != nil {
		return fmt.Errorf("创建任务目录: %w", err)
	}
	if err := os.Chmod(taskDir, 0o700); err != nil {
		return fmt.Errorf("限制任务目录权限: %w", err)
	}
	state.UpdatedAt = time.Now().UTC()
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("生成状态 JSON: %w", err)
	}
	return atomicWrite(filepath.Join(taskDir, "state.json"), payload, 0o600)
}

func ReadState(root, reportID string) (State, error) {
	if reportID == "" || filepath.Base(reportID) != reportID || reportID == "." {
		return State{}, fmt.Errorf("报告标识无效")
	}
	payload, err := os.ReadFile(filepath.Join(root, reportID, "state.json"))
	if err != nil {
		return State{}, fmt.Errorf("读取任务状态: %w", err)
	}
	var state State
	if err := json.Unmarshal(payload, &state); err != nil {
		return State{}, fmt.Errorf("解析任务状态: %w", err)
	}
	return state, nil
}

func LatestState(root string) (State, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return State{}, fmt.Errorf("读取任务目录: %w", err)
	}
	var latest State
	var latestTime time.Time
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		state, err := ReadState(root, entry.Name())
		if err != nil {
			continue
		}
		if state.UpdatedAt.After(latestTime) {
			latest, latestTime = state, state.UpdatedAt
		}
	}
	if latest.ReportID == "" {
		return State{}, fmt.Errorf("没有可读取的任务状态")
	}
	return latest, nil
}

func Write(root string, report model.Report, credentials model.Credentials, text string) (Paths, error) {
	taskDir := filepath.Join(root, report.ReportID)
	if err := os.MkdirAll(taskDir, 0o700); err != nil {
		return Paths{}, fmt.Errorf("创建任务目录: %w", err)
	}
	if err := os.Chmod(taskDir, 0o700); err != nil {
		return Paths{}, fmt.Errorf("限制任务目录权限: %w", err)
	}
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return Paths{}, fmt.Errorf("生成报告 JSON: %w", err)
	}
	if err := privacy.ScanJSON(reportJSON); err != nil {
		return Paths{}, err
	}
	credentialJSON, err := json.MarshalIndent(credentials, "", "  ")
	if err != nil {
		return Paths{}, fmt.Errorf("生成凭证文件: %w", err)
	}
	paths := Paths{
		TaskDir: taskDir, ReportJSON: filepath.Join(taskDir, "report.json"),
		ReportText:  filepath.Join(taskDir, "report.txt"),
		Credentials: filepath.Join(taskDir, "credentials.json"),
	}
	if err := atomicWrite(paths.ReportJSON, reportJSON, 0o600); err != nil {
		return Paths{}, err
	}
	if err := atomicWrite(paths.ReportText, []byte(text), 0o600); err != nil {
		return Paths{}, err
	}
	if err := atomicWrite(paths.Credentials, credentialJSON, 0o600); err != nil {
		return Paths{}, err
	}
	return paths, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, mode); err != nil {
		return fmt.Errorf("写入临时文件: %w", err)
	}
	if err := os.Chmod(temp, mode); err != nil {
		return fmt.Errorf("限制文件权限: %w", err)
	}
	if err := os.Rename(temp, path); err != nil {
		return fmt.Errorf("提交文件: %w", err)
	}
	return nil
}
