package scheduler

import (
	"context"
	"time"

	"github.com/nodebench/nodebench/internal/model"
)

type Result struct {
	Status     string
	Confidence string
	ErrorCode  string
	Message    string
}

type Task struct {
	ID  string
	Run func(context.Context) Result
}

func Run(ctx context.Context, tasks []Task, onStart func(index, total int, id string)) []model.Module {
	modules := make([]model.Module, 0, len(tasks))
	for index, task := range tasks {
		if onStart != nil {
			onStart(index+1, len(tasks), task.ID)
		}
		started := time.Now()
		result := task.Run(ctx)
		module := model.Module{
			ID: task.ID, Status: result.Status, Confidence: result.Confidence,
			DurationMS: time.Since(started).Milliseconds(),
		}
		if result.ErrorCode != "" {
			module.ErrorCode = stringPointer(result.ErrorCode)
		}
		if result.Message != "" {
			module.Message = stringPointer(result.Message)
		}
		modules = append(modules, module)
	}
	return modules
}

func stringPointer(value string) *string {
	return &value
}
