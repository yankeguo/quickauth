# quickauth

A basic reverse proxy featuring a simple authentication web interface

[中文文档](README.zh.md)

## Installation

- Build from source

```bash
git clone https://github.com/yankeguo/quickauth.git
cd quickauth
go build -o quickauth
```

- Download from GitHub

View <https://github.com/yankeguo/quickauth/releases> for the latest release.

- Docker

```bash
docker run -d -p 80:80 -e QUICKAUTH_TARGET=example.com yankeguo/quickauth
```

## Environment Variables

- `QUICKAUTH_LISTEN`: The listening address to listen on. Default is `:80`.
- `QUICKAUTH_TARGET`: The target address to proxy to.
- `QUICKAUTH_TARGET_INSECURE`: Whether to ignore the certificate verification of the target. Default is `false`.
- `QUICKAUTH_USERNAME`: The username for authentication.
- `QUICKAUTH_PASSWORD`: The password for authentication.
- `QUICKAUTH_SECRET_KEY`: The secret key for cookie signing.
- `QUICKAUTH_TITLE`: The title of the web page. Default is `Protected By QuickAuth`.

## Metics

```
GET /__quickauth/metrics
```

- `quickauth_proxy_http_requests_total`: The total number of requests.
- `quickauth_proxy_http_requests_duration`: The duration of requests.

## Ready

```
GET /__quickauth/ready
```

## Credits

GUO YANKE, MIT License
