# ESP32-S3 国内增强规则订阅

`strong` 将 anti-AD 与 Cats-Team/AdRules 的官方 DNS 规则合并、去重，
并移除已经被父域覆盖的子域。只接受域名后缀规则，不将浏览器元素、URL 路径或正则规则转换成整站拦截。

此订阅要求支持最多 300,000 条、1,500,000 字节规则包的增强版固件。
旧 C3 固件继续订阅 `cn-rules`，不要改用此地址。

- 增强规则：[cn-rules-s3 发布页](https://github.com/XGY2003/esp32-c3-cn-adblock/releases/tag/cn-rules-s3)
- 国内访问优先地址：`https://gh-proxy.org/https://github.com/XGY2003/esp32-c3-cn-adblock/releases/download/cn-rules-s3/blocklist.bin`
- 校验文件：在上述地址末尾追加 `.sha256`。
- 构建：`python tools/build_cn_rules.py --profile strong --output-dir dist-s3`
- 下载预检：`python tools/check_update_url.py --profile strong <订阅地址>`

GitHub Actions 每日北京时间 04:35 计划构建；调度可能延迟。
只有两个来源均通过下载和格式验证，才替换发布文件；容量超限会停止发布。
客户端必须核对 SHA-256，失败时保留现有规则；校验值只能检查一致性，不能代替独立签名。

发布资产包含可读域名、两份原始来源、转换清单及原始许可说明。
AdRules 输出继承其各上游许可，不能将生成规则整体标为脚本分支的 0BSD。
详见 `LICENSES/AdRules-NOTICE.md`。

若某应用误拦截，将必要域名加入 `rules/allowlist.txt` 后重建。
当前哈希表无法表示“封禁父域、仅放行某个子域”的例外，因此放行子域时还会移除封禁祖先；
请核对 manifest 的 `removed_blocked_ancestors` 字段。
DNS 规则只对经过该解析器的域名查询生效。
