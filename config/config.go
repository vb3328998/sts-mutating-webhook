package config

// Config 结构体存储配置信息
type Config struct {
	WebhookServerPort      string // Webhook 服务器端口
	TLSCertPath            string // TLS 证书路径
	TLSKeyPath             string // TLS 密钥路径
	DingTalkWebhookURL     string // 钉钉机器人 Webhook URL
	DingTalkSecret         string // 钉钉机器人 Webhook Secret
	DingTalkMessageType    string // 钉钉消息类型
	PodAnnotationKey       string // Pod 注解键
	DefaultStatefulSetName string // 默认的 StatefulSet 名称，如果无法从 Pod ownerReferences 中获取

}

// AppConfig 是全局配置实例
var AppConfig = Config{
	WebhookServerPort:      ":8443",
	TLSCertPath:            "/etc/webhook/certs/tls.crt",
	TLSKeyPath:             "/etc/webhook/certs/tls.key",
	DingTalkWebhookURL:     "https://oapi.dingtalk.com/robot/send?access_token=xxx",
	DingTalkSecret:         "xxx",
	DingTalkMessageType:    "markdown",           // 可以是 "text" 或 "markdown"
	PodAnnotationKey:       "ab-build-different", // pod 打 annotations
	DefaultStatefulSetName: "my-custom-sts",      // 默认的 StatefulSet 名称，如果无法从 Pod ownerReferences 中获取
}
