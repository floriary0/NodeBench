package identity

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/nodebench/nodebench/internal/model"
)

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("生成安全随机数: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func Generate() (string, model.Credentials, error) {
	reportToken, err := randomToken(18)
	if err != nil {
		return "", model.Credentials{}, err
	}
	uploadSecret, err := randomToken(32)
	if err != nil {
		return "", model.Credentials{}, err
	}
	return "nb_" + reportToken, model.Credentials{
		UploadSecret: uploadSecret,
	}, nil
}

func ReportURL(baseURL, reportID string) string {
	return fmt.Sprintf("%s/report/%s", baseURL, reportID)
}
