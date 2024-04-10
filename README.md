# sts-mutating-webhook
---
title: 开发mutating webhook(修改statefulset的nodeselector)
date: 2024-04-09 15:08:36
tags: 'mutating webhook'
---

## 何为 Admission Webhook
**官网定义**
Admission webhook 是一种用于接收准入请求并对其进行处理的 HTTP 回调机制。可以定义两种类型的 admission webhook，即 validating admission webhook 和 mutating admission webhook。Mutating admission webhook 会先被调用。它们可以更改发送到 API 服务器的对象以执行自定义的设置默认值操作。

![](https://vb3328998.github.io/images/webhook-img.png)

接下来，本文将采用 Kubernetes 提供的 Mutating Admission Webhook 这一机制，来实现 statufulset 中修改或者新增 Pod NodeSelector 的，我们每次发送请求调用 API 创建 Pod 的时候，Pod 的 spec 信息会被先修改，再存储。如此一来，工作节点上的 Kublet 创建 Pod 的时候，将会预置NodeSelector。

### 需求
将 statufulset 中 索引是单数的 Pod 设置 NodeSelector 标签，标签的 key 为 "name"，value 为 "even"。双数的 Pod 设置 NodeSelector 标签，标签的 key 为 "name"，value 为 "odd"。 custom-node-selector: '{"key": "name", "even": "node1", "odd": "node2"}'

### 思路
不能影响到其他的服务，所以需要通过 Mutating Admission Webhook 机制，在创建 Pod 之前，通过 Pod 的 annotations 或者 labels 去判断是否经过 Mutating Admission Webhook，我们这里用 labels 去过滤是否启用 mutating 规则。 当 Pod 的 labels 中有 **"ab-build-different: 'true'"** 的时候才去执行

### 解决
部分代码解释
如果没有"ab-build-different: 'true'"标签，直接放行

```go
if pod.Labels[AppConfig.PodAnnotationKey] != "true" {
		log.Infof("Pod %s 没有注解 ab-build-different=true", pod.Name)
		resp.Allowed = true
		return nil
	}
```

解析 json，我们这里的 annotations 是 **custom-node-selector: '{"key": "name", "even": "node1", "odd": "node2"}'**
所以这段代码最后输出会是 name node1 或者 name node2，即是我们想要用来新增或修改的 Pod 的 nodeSelector

```go
func getNodeSelectorValue(pod *corev1.Pod, index int) (string, string, error) {
	selectorJSON, ok := pod.Annotations["custom-node-selector"]
	if !ok {
		return "", "", fmt.Errorf("注解 %s 不存在", "custom-node-selector")
	}
	log.Debugf("selectorJSON: %s", selectorJSON) // 打印查看实际的 JSON 字符串

	var customSelector CustomNodeSelector
	err := json.Unmarshal([]byte(selectorJSON), &customSelector)
	if err != nil {
		return "", "", fmt.Errorf("解析自定义 nodeSelector 注解失败: %v", err)
	}

	if index%2 == 0 {
		return customSelector.Key, customSelector.Even, nil
	}
	return customSelector.Key, customSelector.Odd, nil
}
```

**完整代码**
包含 具体逻辑实现， 钉钉通知

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
    "github.com/sirupsen/logrus"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"net/http"
	"strconv"
	"strings"
)
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

type CustomNodeSelector struct {
	Key  string `json:"key"`
	Even string `json:"even"`
	Odd  string `json:"odd"`
}

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

func init() {
	// 设置日志输出格式为 JSON
	log.SetFormatter(&logrus.JSONFormatter{})
}

func main() {
	http.HandleFunc("/mutate", handleMutate)
	log.Info("服务启动，监听端口", AppConfig.WebhookServerPort)
	// http.ListenAndServeTLS 是一个阻塞调用，持续运行直到发生错误
	log.Fatal(http.ListenAndServeTLS(AppConfig.WebhookServerPort, AppConfig.TLSCertPath, AppConfig.TLSKeyPath, nil))

}

// handleMutate 处理来自 Kubernetes API 的 HTTP 请求
func handleMutate(w http.ResponseWriter, r *http.Request) {
	log.Info("收到 mutate 请求")
	// 读取请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("无法读取请求体: %v", err)
		http.Error(w, fmt.Sprintf("无法读取请求体: %v", err), http.StatusInternalServerError)
		return
	}

	// 解析 AdmissionReview 请求
	var admissionReviewReq v1.AdmissionReview
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&admissionReviewReq); err != nil {
		log.Errorf("无法解析请求: %v", err)
		http.Error(w, fmt.Sprintf("无法解析请求: %v", err), http.StatusBadRequest)
		return
	}

	// 准备 AdmissionReview 响应
	admissionReviewResp := v1.AdmissionReview{
		TypeMeta: admissionReviewReq.TypeMeta,
		Response: &v1.AdmissionResponse{
			UID: admissionReviewReq.Request.UID,
		},
	}

	// 处理请求并设置响应
	if err := mutatePod(admissionReviewReq.Request, admissionReviewResp.Response); err != nil {
		log.Errorf("无法修改 Pod: %v", err)
		sendDingTalkNotification(fmt.Sprintf("无法修改 Pod: %v", err))
		http.Error(w, fmt.Sprintf("无法修改 Pod: %v", err), http.StatusInternalServerError)
		return
	}

	// 发送响应
	respBytes, err := json.Marshal(admissionReviewResp)
	if err != nil {
		log.Errorf("无法编码响应: %v", err)
		http.Error(w, fmt.Sprintf("无法编码响应: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
	log.Info("mutate 请求处理完成")
}

// 处理请求并设置响应
func mutatePod(req *v1.AdmissionRequest, resp *v1.AdmissionResponse) error {
	// 从请求中反序列化 Pod 对象
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		errorMsg := fmt.Sprintf("无法反序列化 Pod 对象: %v", err)
		log.Error(errorMsg)
		sendDingTalkNotification(errorMsg) // 发送钉钉通知
		return err
	}

	// 检查 Pod 是否有注解 "ab-build-different: 'true'"
	if pod.Labels[AppConfig.PodAnnotationKey] != "true" {
		log.Infof("Pod %s 没有注解 ab-build-different=true", pod.Name)
		resp.Allowed = true
		return nil
	}

	// 从 Pod 的 ownerReferences 中提取 StatefulSet 名称
	var statefulSetName string
	for _, ownerRef := range pod.OwnerReferences {
		if ownerRef.Kind == "StatefulSet" {
			statefulSetName = ownerRef.Name
			break
		}
	}
	if statefulSetName == "" {
		return fmt.Errorf("在 Pod 的 ownerReferences 中找不到 StatefulSet 名称")
	}

	// 从 Pod 的名称中提取索引
	indexStr := strings.TrimPrefix(pod.Name, statefulSetName+"-")
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		return fmt.Errorf("无法从 Pod 名称中提取索引: %w", err)
	}
	log.Infof("正在处理 Pod %s-%d 的 nodeSelector 修改请求", statefulSetName, index)
	// 获取自定义 nodeSelector 键和值
	nodeSelectorKey, nodeSelectorValue, err := getNodeSelectorValue(&pod, index)
	if err != nil {
		return err
	}
	// 创建 patch
	patch := createNodeSelectorPatch(pod.Spec.NodeSelector, nodeSelectorKey, nodeSelectorValue)

	// 序列化 patch 并将其设置在响应中
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("无法序列化 patch: %w", err)
	}
	resp.Patch = patchBytes
	resp.PatchType = new(v1.PatchType)
	*resp.PatchType = v1.PatchTypeJSONPatch

	resp.Allowed = true
	log.Infof("成功修改 Pod %s-%d 的 nodeSelector 为 %s:%s", statefulSetName, index, nodeSelectorKey, nodeSelectorValue)
	sendDingTalkNotification(fmt.Sprintf("成功修改 Pod %s-%d 的 nodeSelector 为 %s:%s", statefulSetName, index, nodeSelectorKey, nodeSelectorValue))
	return nil
}

func getNodeSelectorValue(pod *corev1.Pod, index int) (string, string, error) {
	selectorJSON, ok := pod.Annotations["custom-node-selector"]
	if !ok {
		return "", "", fmt.Errorf("注解 %s 不存在", "custom-node-selector")
	}
	log.Debugf("selectorJSON: %s", selectorJSON) // 打印查看实际的 JSON 字符串

	var customSelector CustomNodeSelector
	err := json.Unmarshal([]byte(selectorJSON), &customSelector)
	if err != nil {
		return "", "", fmt.Errorf("解析自定义 nodeSelector 注解失败: %v", err)
	}

	if index%2 == 0 {
		return customSelector.Key, customSelector.Even, nil
	}
	return customSelector.Key, customSelector.Odd, nil
}

func createNodeSelectorPatch(existingNodeSelector map[string]string, nodeSelectorKey, nodeSelectorValue string) []map[string]interface{} {
	var patch []map[string]interface{}
	if existingNodeSelector == nil {
		// NodeSelector 为空，直接添加新的 NodeSelector
		patch = append(patch, map[string]interface{}{
			"op":    "add",
			"path":  "/spec/nodeSelector",
			"value": map[string]string{nodeSelectorKey: nodeSelectorValue},
		})
	} else {
		// NodeSelector 非空，直接替换整个 NodeSelector
		newSelector := map[string]string{nodeSelectorKey: nodeSelectorValue}
		patch = append(patch, map[string]interface{}{
			"op":    "replace",
			"path":  "/spec/nodeSelector",
			"value": newSelector,
		})
	}
	return patch
}


// sendDingTalkNotification 发送通知到钉钉
func sendDingTalkNotification(message string) error {
	sign, timestamp := generateDingTalkSignature()
	log.Infof("generateDingTalkSignature执行成功,%s   ,  %s", sign, timestamp)
	msg := DingTalkMessage{}
	//var content string
	if AppConfig.DingTalkMessageType == "markdown" {
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

	tokenDingTalkUrl := fmt.Sprintf("%s&timestamp=%s&sign=%s", AppConfig.DingTalkWebhookURL, timestamp, sign)
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
	stringToSign := timestamp + "\n" + AppConfig.DingTalkSecret
	hash := hmac.New(sha256.New, []byte(AppConfig.DingTalkSecret))
	hash.Write([]byte(stringToSign))
	signData := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	return signData, timestamp
}

```

### 构建 Mutating 控制器镜像

```Dockerfile
# 使用官方的 Go 基础镜像
FROM golang:1.21 as builder
# 设置工作目录
WORKDIR /app
# 将 Go 模块文件复制到容器中
COPY go.mod go.sum ./
# 下载 Go 模块依赖
RUN go mod download
# 将源代码复制到容器中
COPY . .
# 编译 Go 应用
RUN CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -o webhook
FROM alpine:latest
# 有请求 https 请求必须安装
RUN apk --no-cache add ca-certificates
# 从构建阶段复制二进制文件和证书文件
COPY --from=builder /app/webhook /webhook
# 运行 webhook
ENTRYPOINT ["/webhook"]
```

```shell
docker buildx build --platform linux/amd64 -t xxx:v1 --load .
docker push xxx:v1
```

### 部署服务
Webhook API 服务器需要通过 TLS 方式通信。如果想将其部署至 Kubernetes 集群内，我们还需要证书
这是我们直接用生成证书的脚本，会保存在secret里面，然后再deployment里面去引用
需要注意的是 signerName，eks 的 signerName 是 beta.eks.amazonaws.com/app-serving

```shell
#!/bin/bash
set -e
usage() {
    cat <<EOF
Generate certificate suitable for use with an sidecar-injector webhook service.

This script uses k8s' CertificateSigningRequest API to a generate a
certificate signed by k8s CA suitable for use with sidecar-injector webhook
services. This requires permissions to create and approve CSR. See
https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster for
detailed explantion and additional instructions.

The server key/cert k8s CA cert are stored in a k8s secret.

usage: ${0} [OPTIONS]

The following flags are required.

       --service          Service name of webhook.
       --namespace        Namespace where webhook service and secret reside.
       --secret           Secret name for CA certificate and server certificate/key pair.
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case ${1} in
        --service)
            service="$2"
            shift
            ;;
        --secret)
            secret="$2"
            shift
            ;;
        --namespace)
            namespace="$2"
            shift
            ;;
        *)
            usage
            ;;
    esac
    shift
done
[ -z ${service} ] && service=admission-webhook-example-svc
[ -z ${secret} ] && secret=admission-webhook-example-certs
[ -z ${namespace} ] && namespace=default
if [ ! -x "$(command -v openssl)" ]; then
    echo "openssl not found"
    exit 1
fi
csrName=${service}.${namespace}
tmpdir=$(mktemp -d)
echo "creating certs in tmpdir ${tmpdir} "
cat <<EOF >> ${tmpdir}/csr.conf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${service}
DNS.2 = ${service}.${namespace}
DNS.3 = ${service}.${namespace}.svc
EOF
openssl genrsa -out ${tmpdir}/server-key.pem 2048
openssl req -new -key ${tmpdir}/server-key.pem -subj "/CN=${service}.${namespace}.svc" -out ${tmpdir}/server.csr -config ${tmpdir}/csr.conf
# clean-up any previously created CSR for our service. Ignore errors if not present.
kubectl delete csr ${csrName} 2>/dev/null || true
# create  server cert/key CSR and  send to k8s API
cat <<EOF | kubectl create -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ${csrName}
spec:
  groups:
  - system:authenticated
  request: $(cat ${tmpdir}/server.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - digital signature
  - key encipherment
  - server auth
EOF
# verify CSR has been created
while true; do
    kubectl get csr ${csrName}
    if [ "$?" -eq 0 ]; then
        break
    fi
done
# approve and fetch the signed certificate
kubectl certificate approve ${csrName}
# verify certificate has been signed
for x in $(seq 10); do
    serverCert=$(kubectl get csr ${csrName} -o jsonpath='{.status.certificate}')
    if [[ ${serverCert} != '' ]]; then
        break
    fi
    sleep 1
done
if [[ ${serverCert} == '' ]]; then
    echo "ERROR: After approving csr ${csrName}, the signed certificate did not appear on the resource. Giving up after 10 attempts." >&2
    exit 1
fi
echo ${serverCert} | openssl base64 -d -A -out ${tmpdir}/server-cert.pem
# create the secret with CA cert and server cert/key
kubectl create secret generic ${secret} \
        --from-file=key.pem=${tmpdir}/server-key.pem \
        --from-file=cert.pem=${tmpdir}/server-cert.pem \
        --dry-run -o yaml |
    kubectl -n ${namespace} apply -f -
```


```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sts-webhook
  namespace: custom-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sts-webhook
  template:
    metadata:
      labels:
        app: sts-webhook
    spec:
      containers:
        - name: sts-webhook
          image: xxx:v1
          ports:
            - containerPort: 8443
              name: http
              protocol: TCP
          volumeMounts:
            - name: webhook-certs
              mountPath: "/etc/webhook/certs"
              readOnly: true
      volumes:
        - name: webhook-certs
          secret:
            secretName: sts-webhook-certs
            items:
              - key: cert.pem
                path: tls.crt
              - key: key.pem
                path: tls.key
---
apiVersion: v1
kind: Service
metadata:
  name: sts-webhook
  namespace: custom-system
spec:
  ports:
    - name: http
      port: 8443
      protocol: TCP
      targetPort: http
  selector:
    app: sts-webhook
  type: ClusterIP
```

caBundle 获取 
**TODO。。。**
接着创建 MutatingWebhookConfiguration
这里解读下，webhooks 是我们的主要配置
在 clientConfig 中，指定我们的 sts-webhook 的配置信息
rule 是我们的过滤规则，当 pods 创建的时候触发，并且需要 pods 有 labels 匹配 ab-build-different: "true"

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: sts-mutating-webhook
webhooks:
  - name: sts-webhook
    clientConfig:
      service:
        name: sts-webhook
        namespace: custom-system
        path: "/mutate"
        port: 8443
      caBundle: "xxxxx"
    rules:
      - operations: ["CREATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail
    objectSelector:
      matchLabels:
        ab-build-different: "true"
```