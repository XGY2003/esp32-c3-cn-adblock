# ESP32-C3 国内 DNS 拦截规则自动更新

基于 [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock) 的 4 MB ESP32-C3 版本。保留 Flash 中的 40-bit FNV-1a hash 表查询与双固件 OTA，增加国内 anti-AD 规则构建、校验和失败恢复。

## 自动更新地址

首次 Actions 构建成功后，开发板管理页的 Remote auto-update URL 填：

```text
https://github.com/XGY2003/esp32-c3-cn-adblock/releases/download/cn-rules/blocklist.bin
```

同目录的 `blocklist.bin.sha256` 为单行 SHA-256。开发板默认每 24 小时检查；启动联网后 60 秒首次尝试，失败后 15 分钟重试。HTTPS、NTP 或校验失败时保留现有规则。GitHub 在不同网络的可达性需要分别验证；可使用工作流中的可选 COS/S3 发布步骤切换到自有国内 HTTPS 托管。

## 规则构建

```sh
python tools/build_cn_rules.py --output-dir data
python -m unittest discover -s tools -p 'test_*.py' -v
```

默认主源 `https://anti-ad.net/domains.txt`，GitHub raw 为同源备用。官方源必须有匹配的 anti-AD 元数据与完整条数；域名严格验证后去重，删除被父域覆盖的冗余子域。输出为数值升序、5-byte 小端的 40-bit hash 表。

每表最多 110,000 个 hash / 550,000 bytes，超过限制时失败，不截断规则。原始文本由云端处理，开发板只下载二进制，不需要电脑保持开机。每日计划为北京时间 04:20，云端调度可能延迟；Actions 运行记录是实际执行依据。

## 编译与首次部署

使用 PlatformIO 6.2.0，项目固定 `espressif32@6.12.0` / Arduino 2.0.17。

1. 将 `src/secrets.example.h` 复制为 `src/secrets.h`，设置独立管理密码和 OTA 密码。Wi-Fi 可以通过板上配网页配置。
2. 执行规则构建，然后 `pio run -e c3`。
3. 先备份设备原有完整 Flash；首次需要同时烧录固件和 LittleFS：`pio run -e c3 -t upload`、`pio run -e c3 -t uploadfs`。
4. 配网后打开串口显示的 IP 或 `http://c3adblock.local`，配置自动更新地址并执行 Fetch now。

仅上传固件而不初始化 LittleFS，会导致规则文件系统不可用。`uploadfs` 会替换现有文件系统，不应当作日常规则更新方式。`src/secrets.h`、设备备份和管理密码均不得提交到仓库。

## 更新保护与网络行为

- 下载到 `.new`，验证长度、容量、严格排序和 SHA-256 后再切换；旧表通过 `.bak` 保留。启动恢复有效旧表，丢弃未提交的暂存文件。
- 文件系统挂载失败不会自动格式化。
- 只使用验证 CA 的 HTTPS；NTP 同步前不下载。原始订阅地址须为不带 query 的稳定 HTTPS URL；最多接受 3 次绝对 HTTPS 重定向。托管端须给出 Content-Length，禁用压缩和 chunked。
- 默认 DNS 上游 `223.5.5.5`，备用 `119.29.29.29`。板子自己的 DNS 配置独立使用上游，避免 DHCP 分发板子自身地址造成循环。
- 显式设置 WPA3 SAE PWE BOTH，提高与 H2E 网络的互通性。
- TLS 建连和响应头读取在临时任务中执行，等待期间及下载分块间继续处理 DNS。实际更新时的吞吐和延迟仍受 Wi-Fi、上游与设备负载影响。

## 白名单

编辑 `rules/allowlist.txt`，每行一个纯域名，重新运行工作流。为了放行被父域拦截的子域，构建器会移除相应父域规则；该父域下其他子域也可能因此放行。`manifest.json` 记录被移除的祖先规则。

DNS 域名拦截不能移除共用正常内容域名的广告、页面元素或 URL 路径。加密 DNS、HTTPDNS、硬编码 IP 可能绕过；当前服务以 UDP DNS 为主，没有实现 DNS-over-TCP。客户端 DNS 和 IPv6 DNS 需要自行正确接入。

## 可选国内托管

工作流支持腾讯 COS / S3 兼容接口。仓库 Actions Variables 设置 `S3_ENDPOINT`、`S3_REGION`、`S3_BUCKET`、`S3_PREFIX`、`S3_PUBLIC_BASE`，Secrets 设置 `S3_ACCESS_KEY_ID`、`S3_SECRET_ACCESS_KEY`。未设置 endpoint 时跳过。公开规则文件的匿名读取即可，发布身份仅需对应桶前缀的读写权限；写入密钥不进入固件。

发布按 binary → manifest → checksum 的顺序完成。三件文件的替换不具有跨文件原子性，板端必须校验 SHA 并在不一致时保留旧表重试。预检：

```sh
python tools/check_update_url.py https://your-host/rules/blocklist.bin
```

## 来源与许可

原固件使用 MIT，原项目提交 `238ef7b27097e8597f39e9a5ce07a958488572a2`。anti-AD 的 MIT 原文保留在 `LICENSES/anti-AD-MIT.txt`；所选 Mozilla CA 根证书的来源及 certifi 许可保留在 `ca-roots.json` 和 `LICENSES/`。SHA-256 用于完整性检查，发布者身份依赖 HTTPS，不等同于独立发布签名。
