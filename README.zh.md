# quickauth

一个反向代理服务, 带有简单的认证界面

## 安装

- 从源码构建

```bash
git clone https://github.com/yankeguo/quickauth.git
cd quickauth
go build -o quickauth
```

- 从 GitHub 下载

访问 <https://github.com/yankeguo/quickauth/releases> 获取最新版本。

- Docker

```bash
docker run -d -p 80:80 -e QUICKAUTH_TARGET=example.com yankeguo/quickauth
```

## 环境变量

- `QUICKAUTH_LISTEN`: 服务监听地址, 默认为 `:80`
- `QUICKAUTH_TARGET`: 代理目标地址, 比如 `http://myservice:8080`
- `QUICKAUTH_TARGET_INSECURE`: 如果代理目标是一个 `https` 服务, 是否忽略证书验证, 默认为 `false`
- `QUICKAUTH_USERNAME`: 账户
- `QUICKAUTH_PASSWORD`: 密码
- `QUICKAUTH_SECRET_KEY`: 用以加密 Cookie 的签名
- `QUICKAUTH_TITLE`: 登录页面标题, 默认为 `Protected By QuickAuth`

## Prometheus 指标

```
GET /__quickauth/metrics
```

- `quickauth_proxy_http_requests_total`: The total number of requests.
- `quickauth_proxy_http_requests_duration`: The duration of requests.

## 就绪检查

```
GET /__quickauth/ready
```

## 许可证

GUO YANKE, MIT License
