package main

import (
	"Mutating-sts/config"
	"Mutating-sts/handle"
	"github.com/sirupsen/logrus"
	"net/http"
)

var log = logrus.New()

func init() {
	// 设置日志输出格式为 JSON
	log.SetFormatter(&logrus.JSONFormatter{})
}

func main() {

	http.HandleFunc("/mutate", handle.HandleMutate)
	log.Info("服务启动，监听端口", config.AppConfig.WebhookServerPort)
	// http.ListenAndServeTLS 是一个阻塞调用，持续运行直到发生错误
	log.Fatal(http.ListenAndServeTLS(config.AppConfig.WebhookServerPort, config.AppConfig.TLSCertPath, config.AppConfig.TLSKeyPath, nil))

}
