package middleware

import (
	"Mutating-sts/config"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"strconv"
	"time"
)

type DingTalkMessage struct {
	Msgtype  string `json:"msgtype"`
	Markdown struct {
		Title string `json:"title"`
		Text  string `json:"text"`
	} `json:"markdown,omitempty"`
	Text struct {
		Content string `json:"content"`
	} `json:"text,omitempty"`
}

// SendDingTalkNotification 发送通知到钉钉
func SendDingTalkNotification(message string) error {
	sign, timestamp := generateDingTalkSignature()
	log.Infof("generateDingTalkSignature执行成功,%s   ,  %s", sign, timestamp)
	msg := DingTalkMessage{}
	//var content string
	if config.AppConfig.DingTalkMessageType == "markdown" {
		msg.Msgtype = "markdown"
		msg.Markdown.Title = "Mutating Webhook Notification"
		msg.Markdown.Text = fmt.Sprintf("###Mutating Webhook Notification \n > %s", message)
	} else {
		msg.Msgtype = "text"
		msg.Text.Content = message
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	tokenDingTalkUrl := fmt.Sprintf("%s&timestamp=%s&sign=%s", config.AppConfig.DingTalkWebhookURL, timestamp, sign)
	resp, err := http.Post(tokenDingTalkUrl, "application/json", bytes.NewBuffer(msgBytes))
	if err != nil {
		return err
	}
	fmt.Printf(resp.Status, resp.Body)
	defer resp.Body.Close()
	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("发送钉钉消息失败, 状态吗: %s, 请求体: %s", resp.Status, string(body))
	}
	return nil
}

// generateDingTalkSignature 生成钉钉签名
func generateDingTalkSignature() (string, string) {
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)
	stringToSign := timestamp + "\n" + config.AppConfig.DingTalkSecret
	hash := hmac.New(sha256.New, []byte(config.AppConfig.DingTalkSecret))
	hash.Write([]byte(stringToSign))
	signData := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	return signData, timestamp
}
