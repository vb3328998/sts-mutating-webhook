package handle

import (
	"Mutating-sts/config"
	"Mutating-sts/middleware"
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"net/http"
	"strconv"
	"strings"
)

type CustomNodeSelector struct {
	Key  string `json:"key"`
	Even string `json:"even"`
	Odd  string `json:"odd"`
}

// handleMutate 处理来自 Kubernetes API 的 HTTP 请求
func HandleMutate(w http.ResponseWriter, r *http.Request) {
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
		middleware.SendDingTalkNotification(fmt.Sprintf("无法修改 Pod: %v", err))
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
		middleware.SendDingTalkNotification(errorMsg) // 发送钉钉通知
		return err
	}

	// 检查 Pod 是否有注解 "ab-build-different: 'true'"
	if pod.Labels[config.AppConfig.PodAnnotationKey] != "true" {
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
	middleware.SendDingTalkNotification(fmt.Sprintf("成功修改 Pod %s-%d 的 nodeSelector 为 %s:%s", statefulSetName, index, nodeSelectorKey, nodeSelectorValue))
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
