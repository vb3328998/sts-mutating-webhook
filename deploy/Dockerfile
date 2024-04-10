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
