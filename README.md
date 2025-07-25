# deploy-cert-python

## 启动

根据系统环境选择对应的启动文件，此处以ubuntu amd64为例

```bash
# 后台运行 异常正常日志分离
nohup ./deploy-cert-python-linux-amd64 --port=9527 --script="nginx -s reload" > runtime.log 2>error.log &
# 后台运行 异常正常日志合并输出
nohup ./deploy-cert-python-linux-amd64 --port=9527 --script="nginx -s reload" > runtime.log 2>&1 &
# 后台运行 丢弃日志输出
nohup ./deploy-cert-python-linux-amd64 --port=9527 --script="nginx -s reload" > /dev/null 2>&1 &
```

### 参数配置

| 参数名       | 参数类型   | 默认值       | 参数说明                               |
|-----------|--------|-----------|------------------------------------|
| port      | int    | 9527      | 监听端口                               |
| token     | string | 随机uuid    | 鉴权token，启动时注意固定否则每次生成新token        |
| log-level | string | INFO      | 日志等级                               |
| base-path | string | /data/ssl | ssl上传路径                            |
| script    | string |           | 重启执行的脚本,可以直接传入简单脚本内容,建议使用shell绝对路径 |

## 访问方式

请求方式1

``` bash
curl --request POST \
  --url http://localhost:9527/deploy-cert \
  --header 'content-type: application/json' \
  --header 'token: f519ec5c-f10d-4ef6-81bd-ee74228ef889' \
  --data '{
    "key": "-----BEGIN EC PRIVATE KEY-----",
    "cert":"-----BEGIN CERTIFICATE-----"
}'
```

请求方式2

``` bash
curl --request POST \
  --url http://localhost:9527/deploy-cert \
  --header 'content-type: multipart/form-data' \
  --header 'token: f519ec5c-f10d-4ef6-81bd-ee74228ef889' \
  --form key=@/data/ssl/example.com/privkey.pem \
  --form cert=@/data/ssl/example.com/fullchain.pem
```

### 参数描述

| 参数名  | 参数说明          |
|------|---------------|
| key  | 私钥信息          |
| cert | 公钥信息，需要完整的证书链 | 

## [Certd](https://github.com/certd/certd)插件

| 文件                                                               | 说明   |
|------------------------------------------------------------------|------|
| [DeployCertByHTTPAccess.yaml](certd/DeployCertByHTTPAccess.yaml) | 授权插件 |
| [DeployCertByHTTP.yaml](certd/DeployCertByHTTP.yaml)             | 部署插件 | 
