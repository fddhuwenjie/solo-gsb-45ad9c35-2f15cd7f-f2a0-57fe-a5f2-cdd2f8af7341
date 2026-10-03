# TLS 证书无中断轮换规划 API

给定客户端信任锚、各 TLS 端点当前/目标证书链、必须保持的通信关系，以及一组
**增信 (add_trust)**、**换证 (replace_cert)**、**撤信 (remove_trust)** 动作
（每个动作带 `allowed_stages`），本服务计算**阶段数最少**的轮换计划，使得每个阶段
完成后所有通信关系仍存在有效的信任路径（从端点叶子到客户端某个信任锚的完整链）。
也支持逐阶段回放任意计划，定位首次失效的关系、阻塞动作与断开的证书链。
部署中断后可用 `/plans/reconcile` 结合部分现场观测枚举所有可能进度并给出
安全的下一步动作。计划**执行期间发现证书被撤销**（或出现 good/revoked
冲突证据）时，可用 `/plans/replan` 把已完成前缀视为不可回退，结合现场
当前链与每端点候选替代链的离线撤销证据，重算阶段最少的安全续策。
另提供**部署身份预检**：在规划前校验目标叶证书的 SAN 是否覆盖端点声明的
DNS/IP 身份，并沿链累计中间 CA 的名称约束（excluded 优先、permitted 取交集）。
以及 **OCSP 装订响应离线预检**：不上网、不连响应器，直接校验端点将装订的
OCSP 响应是否由签发者（或其授权响应证书）签名、状态为 good 且在有效期内。
还有**证书变体选择**：给定每个端点最多 12 条候选指纹链与异构客户端各自的
信任根、可接受叶公钥类型和签名算法 OID，为每个端点求出**覆盖全部必连
客户端关系的最小变体部署集合**（全局最优，非逐客户端贪心），并在无解时
按客户端、端点稳定列出每条候选链不兼容的原因。
另提供**链级撤销证据审查**：调用方一次提交 PEM 证书包、各端点目标叶指纹、
离线 OCSP 响应集合与 DER/PEM CRL 集合，以及统一的 `check_time` 与时钟偏差；
服务重建每条唯一证书链，对每张叶和中间证书分别核对 OCSP 的 CertID、签名者、
签名与时效，并核对 CRL 的签发者、签名、thisUpdate/nextUpdate 与撤销条目，
间接/增量 CRL 按不支持处理；只有链上每张非信任根证书在同一时刻都有有效且
一致的 good 证据时端点才 `eligible:true`，新鲜 revoked 优先，good/revoked
冲突、证据缺失或过期均为不合格，合格链可直接交给规划接口。
另有**证书用途与路径策略审查**：一次提交 PEM 证书包、允许的信任根指纹、
各端点当前/目标叶指纹及其 TLS 角色（`server` / `client`）与所需 EKU 和统一
`check_time`；服务复用签名链归一化重建当前、目标两条唯一链，并在该时刻
核对每条链上每张证书（含信任根）的有效期、各级 BasicConstraints/pathLen
与 CA/keyCertSign 权限、叶 KeyUsage/EKU 以及未知关键扩展；当前链或目标链
任一不合规即不放行，只有合格目标链可交给 `/plans`，链不唯一时返回结构化
422。

## 一键启动

```bash
docker compose up --build
```

- 端口：`http://localhost:8080`
- 交互式 API 文档：`http://localhost:8080/docs`
- 健康检查：`GET /health`

停止：`docker compose down`。

## 接口

### `POST /scenarios/normalize` — 乱序 PEM 包归一化

把一份**乱序、可能含重复 DER 副本**的 PEM 证书包，连同各端点当前/目标叶证书的
SHA-256 指纹、以及允许作为链终点的自签名根指纹，归一化为规划器可直接使用的数据。

```bash
curl -s http://localhost:8080/scenarios/normalize \
  -H 'Content-Type: application/json' \
  --data @examples/normalize_request.json
```

请求字段：

| 字段 | 说明 |
| --- | --- |
| `pem_certificates` | PEM 字符串列表；顺序任意，每个元素可含多个拼接的 PEM CERTIFICATE 块，按 DER 指纹去重 |
| `endpoints[].current_leaf_fingerprint` / `target_leaf_fingerprint` | 端点当前/目标叶证书的 SHA-256（十六进制，大小写不敏感，输出统一为小写） |
| `trust_roots` | 允许作为链终点的自签名根证书指纹列表 |

签发关系**只通过签名验证建立**——用候选签发者公钥验证子证书的签名
（支持 RSA PKCS#1 v1.5、RSA-PSS、ECDSA、DSA、Ed25519/Ed448），绝不仅比较
subject/issuer：同名不同密钥的「冒牌 CA」、交叉签名证书都会被正确区分。

随后对每张叶证书在「已验证签发边」构成的图上判定可信路径（leaf-first、
到达某个声明信任根的简单路径）的数目是**零条、恰好一条还是多条**——只有
恰好一条时才输出结果。该判定是**精确**的：通过一次路径搜索加上多项式复杂度的
「是否存在第二条不同路径」检查完成，**不枚举全部简单路径**（最坏情况下是阶乘级），
因此含环、共享中间证书、大量交叉签名分支的包都不会让判定超时或误判。

成功返回 `200`，`cert_id` 一律为小写 SHA-256，证书含现有模型所需的
`subject`、`issuer`、`not_valid_before`、`not_valid_after`，端点含还原好的
`current_chain`、`target_chain`（叶在前、根在后），可直接拼入 `/plans` 请求体：

```json
{
  "certificates": [
    {"cert_id": "0164c42f...", "subject": "CN=api.example.com",
     "issuer": "CN=Old Root CA",
     "not_valid_before": "2024-01-01T00:00:00Z",
     "not_valid_after": "2035-01-01T00:00:00Z"}
  ],
  "endpoints": [
    {"endpoint_id": "api.example.com",
     "current_chain": ["0164c42f...", "a6f01a66..."],
     "target_chain": ["4e822998...", "951ac9d4...", "6f5b46a2..."]}
  ]
}
```

以下情况返回 `422`，错误体在 `detail` 中给出机器可读 `error`、`message` 与逐条诊断
（`pem_issues` / `fingerprint_issues` / `chain_issues`）。`chain_issues` 会列出
无法确定链的**叶证书指纹**、签名真正通过的**候选签发者指纹** `candidate_issuers`，
以及**候选路径指纹** `candidate_paths`：

- `no_trust_path`：不存在从叶证书经签名验证到达信任根的路径（缺上级、签名不匹配、
  PEM 被篡改等）。
- `ambiguous_chain`：交叉签名导致存在多条都能到达信任根的有效路径，归一化拒绝替你
  猜测；典型场景与响应见
  [`examples/normalize_ambiguous_request.json`](examples/normalize_ambiguous_request.json)。
- `invalid_pem`：某个列表元素不是可解析的 PEM（附元素下标）。
- `invalid_fingerprint` / `unknown_fingerprint`：指纹不是 64 位十六进制 SHA-256，
  或包内没有任何证书与该指纹匹配。
- `trust_root_not_self_signed`：声明的信任根不是自签名证书
  （subject != issuer 或自签名验证失败）。

> **`candidate_paths` 只是有界诊断样本**：为避免阶乘级枚举，诊断遍历最多记录
> **64** 条候选路径，交叉签名极多的包中样本可能被截断。截断只影响展示，
> 不影响结论——`no_trust_path` / `ambiguous_chain` / 成功（200）的判定始终
> 基于完整的签发图精确计算，与样本大小无关。

注意：归一化只确认**密码学签发关系**，不检查有效期（没有规划时刻输入）；有效期校验
仍由 `/plans` 的 `plan_time` 负责。示例 PEM 可用
`examples/gen_normalize_example.py` 与 `examples/gen_normalize_ambiguous_example.py`
重新生成。

### `POST /deployments/precheck` — 目标证书部署身份预检

在把目标证书交给规划器之前，先验证它**真的为各端点声明的 DNS/IP 身份签名**，
并且整条链上的中间 CA 名称约束允许这些身份。输入与归一化接口相同的 PEM 包
（同样的解析、去重、签名验证链重建规则），外加每个端点的目标叶指纹和身份声明：

```bash
curl -s http://localhost:8080/deployments/precheck \
  -H 'Content-Type: application/json' \
  --data @examples/precheck_request.json
```

请求字段：

| 字段 | 说明 |
| --- | --- |
| `pem_certificates` / `trust_roots` | 与 `/scenarios/normalize` 相同 |
| `endpoints[].target_leaf_fingerprint` | 目标叶证书的 SHA-256 指纹（大小写不敏感） |
| `endpoints[].identities[]` | 端点声明的身份：`{"type": "dns", "value": "api.example.com"}` 或 `{"type": "ip", "value": "10.0.0.7"}` |

身份检查规则：

- **只认 SAN**：subject CN 不作为身份来源；声明的身份必须由叶证书同类型
  SAN 条目覆盖。
- **DNS 归一化**：统一小写、剥掉末尾单点、非 ASCII 标签转 IDNA A-label
  （`BÜCHER.example` 与 `xn--bcher-kva.example` 视为同一身份）。
- **通配符**：SAN 中的 `*` 只能占最左侧完整标签，且只匹配**一个**标签
  （`*.example.com` 覆盖 `api.example.com`，不覆盖 `example.com` 或
  `a.b.example.com`）；声明的身份里不允许出现通配符。
- **IP 精确匹配**：声明必须是字面 IPv4/IPv6 地址（不接受网段、zone id），
  与 iPAddress SAN 逐字节相等才算覆盖，v4/v6 互不混淆。
- **名称约束沿链累计**：只累计中间 CA（信任锚自身的约束不重复执行）；
  `excluded` 优先于 `permitted`，多个 CA 的 `permitted` 取**交集**
  （叶 SAN 必须落在每个施加了该类型约束的 CA 的允许集内）。DNS 约束按
  标签边界匹配（`example.com` 约束覆盖 `api.example.com`，不覆盖
  `evil-example.com`；`.example.com` 只覆盖子域）；IP 约束按地址+掩码
  网段判断。对每类声明的身份，**叶证书上全部同类 SAN 都会被校验**，
  不只是被声明引用的那些——任何一个同类 SAN 违反约束，端点即不合格
  （未声明的类型不参与判定）。**通配符 SAN 按其覆盖集合整体求值**
  （`*.example.com` 视为「`example.com` 下任意单个标签」的集合），不做
  字面名校验、也不抽样枚举：覆盖集合与任一 `excluded` 子树**相交**即拒
  （如 `excluded: blocked.example.com` 会命中 `*.example.com`，而
  `.blocked.example.com` 只排除更深层名字、与之不相交）；同时该集合必须
  被每级 CA 的 `permitted` 并集**完整容纳**（`permitted: api.example.com`
  这类窄许可容不下整个通配集合）。
- **不支持的约束类型**（rfc822Name、URI、directoryName、otherName 等，或
  畸形的 iPAddress 约束）一律按失败关闭处理，返回
  `unsupported_constraint_type`，绝不静默放行。

成功返回 `200`，`results` 按 `endpoint_id` 稳定排序；每个结果给出
`eligible`、机器可读 `reason`、重建好的叶在前 `chain`（即规划接口的
`target_chain`）、归一化后的 `dns_sans` / `ip_sans`、逐身份覆盖结果
`identities` 和稳定排序的 `violations`：

```json
{
  "results": [
    {
      "endpoint_id": "api.example.com",
      "target_leaf_fingerprint": "e72201b1...",
      "eligible": true,
      "reason": "ok",
      "chain": ["e72201b1...", "acd82986...", "4c9094c3..."],
      "dns_sans": ["*.svc.example.com", "api.example.com"],
      "ip_sans": ["10.0.0.7"],
      "identities": [
        {"type": "dns", "value": "api.example.com", "covered": true},
        {"type": "dns", "value": "grpc.svc.example.com", "covered": true},
        {"type": "ip", "value": "10.0.0.7", "covered": true}
      ],
      "violations": []
    }
  ]
}
```

`reason` 取值（同时是 violations 的稳定排序优先级）：

- `unsupported_constraint_type`：链上存在无法对 DNS/IP 身份求值的约束类型。
- `excluded_by_name_constraint`：某个 SAN（通配符按其覆盖集合）与
  excluded 子树相交。
- `not_within_permitted_subtree`：某个 SAN（通配符按其覆盖集合）未落入
  每级 CA 的 permitted 交集。
- `identity_not_covered`：声明的身份没有任何存活的同类型 SAN 覆盖。

每条 violation 携带 `identity_type` / `identity_value` / `san` /
`constraint` / `ca_fingerprint` 字段定位原因。**只有 `eligible: true` 的
结果才应交给 `/plans`**；其 `chain` 可直接作为端点的 `target_chain` 拼入
规划请求（示例见 [`examples/precheck_request.json`](examples/precheck_request.json)，
可用 `examples/gen_precheck_example.py` 重新生成）。

请求级错误返回 `422`，结构与归一化接口一致（`error`、`message`、
`pem_issues` / `fingerprint_issues` / `chain_issues`），并额外提供
`identity_issues`（非法 DNS/IP 身份、重复身份，错误码 `invalid_identity`）；
链无法唯一解析时同样返回 `no_trust_path` / `ambiguous_chain`。

### `POST /deployments/ocsp-precheck` — OCSP 装订响应离线预检

在端点装订（staple）OCSP 响应之前，离线验证该响应届时是否可被客户端接受：
全程不访问网络，只用与归一化接口相同的 PEM 包（同样的解析、去重、签名验证
规则；**不需要信任根**，装订响应只对叶证书的直接签发者求值）：

```bash
curl -s http://localhost:8080/deployments/ocsp-precheck \
  -H 'Content-Type: application/json' \
  --data @examples/ocsp_precheck_request.json
```

请求字段：

| 字段 | 说明 |
| --- | --- |
| `pem_certificates` | 与 `/scenarios/normalize` 相同的 PEM 包；必须包含叶证书及其签发者 |
| `leaf_fingerprint` | 叶证书的 SHA-256 指纹（十六进制，大小写不敏感） |
| `ocsp_response` | Base64 编码的 DER OCSP 响应（即端点将装订的原文；内部空白字符会被忽略） |
| `check_time` | 校验时刻（ISO-8601；裸时间按 UTC 处理） |
| `max_skew_seconds` | 时钟偏差容忍秒数，**最多 300**，缺省 0 |

校验按固定优先级依次进行，首个失败即决定返回的 `reason`：

1. **解析**：`ocsp_response` 必须是可解析的 Base64 DER OCSP 响应
   （否则 `invalid_ocsp_response`）。
2. **响应状态**：必须为 `successful`（否则 `response_not_successful`，
   此类响应不携带任何证书状态字段）。
3. **签发者**：PEM 包内必须存在**经签名验证**确实签发了叶证书的证书
   （否则 `issuer_not_found`）。
4. **CertID 核对**：响应 CertID 的序列号必须等于叶证书序列号，且
   `issuerNameHash` / `issuerKeyHash` 必须用响应自带的哈希算法对签发者的
   DER Name 与 subjectPublicKey 位串重算吻合（否则 `cert_id_mismatch`）。
5. **签名者选定**：按 `responderName` 或 `responderKeyHash`（对
   subjectPublicKey 位串的 SHA-1）在「签发者 + 响应内嵌证书」中选定签名者
   （否则 `responder_not_found`）；签名者必须是**签发者本身**，或是
   **签发者直接签发、在 `check_time` 有效、且含 `id-kp-OCSPSigning` 扩展
   密钥用途**的响应证书（否则 `unauthorized_responder`）。
6. **验签**：用选定签名者的公钥验证响应签名（否则 `signature_invalid`）。
   支持 RSA PKCS#1 v1.5、RSASSA-PSS、ECDSA、DSA、Ed25519/Ed448。对
   RSASSA-PSS 响应，服务自行从原始 DER 的 `signatureAlgorithm` 解析
   `RSASSA-PSS-params`（显式参数，或按 RFC 4055 取默认值：SHA-1、
   MGF1/SHA-1、盐长 20、trailerFieldBC），因为 cryptography 44.0.3 无法
   读取 OCSP 响应的 PSS 参数；未知 OID、非法 TLV、重复或越界字段一律
   拒绝，参数非法与签名不匹配都返回稳定的 `signature_invalid`，绝不
   泄露内部异常。
7. **证书状态**：必须为 `good`；`revoked` 返回 `certificate_revoked` 并附
   `revocation_time` / `revocation_reason`，`unknown` 返回
   `certificate_unknown`。
8. **时效**：`producedAt` 不得晚于 `check_time + max_skew_seconds`
   （否则 `produced_at_in_future`）；响应**必须携带 `nextUpdate`**
   （否则 `next_update_missing`）；`check_time` 必须落在
   `[thisUpdate − skew, nextUpdate + skew]` 窗口内（过早
   `response_not_yet_valid`，过期 `response_stale`）。

全部通过才返回 `eligible: true`。失败一律返回 `200` + `eligible: false` +
稳定机器可读 `reason`（另附人类可读 `message` 与已查明的上下文字段
`response_status` / `certificate_status` / `responder_id_type` /
`signer_type` / `signer_fingerprint` / 各时间戳）：

```json
{
  "leaf_fingerprint": "2a8b29ba...",
  "issuer_fingerprint": "8c60ddc7...",
  "eligible": true,
  "reason": "ok",
  "message": "the stapled response is authentic, timely and certifies the leaf as good at check_time",
  "response_status": "successful",
  "certificate_status": "good",
  "responder_id_type": "key_hash",
  "signer_type": "responder_certificate",
  "signer_fingerprint": "8a18cc66...",
  "produced_at": "2026-09-27T00:35:23Z",
  "this_update": "2024-01-01T00:00:00Z",
  "next_update": "2035-01-01T00:00:00Z",
  "revocation_time": null,
  "revocation_reason": null
}
```

请求级错误（指纹格式非法、叶指纹不在包内、PEM 无法解析）返回 `422`，
结构与归一化接口一致（`invalid_fingerprint` / `unknown_fingerprint` /
`invalid_pem`）。示例见
[`examples/ocsp_precheck_request.json`](examples/ocsp_precheck_request.json)，
可用 `examples/gen_ocsp_precheck_example.py` 重新生成（响应窗口
2024–2035、`check_time` 固定为 2030-01-01，重新生成后多年内保持
`eligible: true`）。

### `POST /deployments/revocation-review` — 链级离线撤销证据审查

在把**整条链**交给规划器之前，对链上每张非信任根证书（叶 + 所有中间 CA）
统一审查其撤销证据。调用方提交与归一化接口相同的 PEM 包（同样的解析、去重、
签名验证与唯一链重建规则——多条信任路径仍按 `ambiguous_chain` 返回 422）、
信任根、各端点目标叶指纹，外加**离线 OCSP 响应集合**与 **CRL 集合**（DER 或
PEM 均可，顺序任意），以及一个统一的校验时刻 `check_time` 和时钟偏差
`max_skew_seconds`（最多 300）：

```bash
curl -s http://localhost:8080/deployments/revocation-review \
  -H 'Content-Type: application/json' \
  --data @examples/revocation_review_request.json
```

请求字段：

| 字段 | 说明 |
| --- | --- |
| `pem_certificates` / `trust_roots` | 与 `/scenarios/normalize` 相同；包需包含叶、全部中间证书与信任根 |
| `endpoints[].target_leaf_fingerprint` | 各端点目标叶证书的 SHA-256 指纹（大小写不敏感）；`endpoint_id` 不得重复 |
| `ocsp_responses` | Base64 DER OCSP 响应列表（即装订原文，内部空白忽略）。响应**按 CertID 全局匹配**，与提交顺序无关 |
| `crls` | CRL 列表，每个元素可以是 PEM（单个 `BEGIN CRL` 块）或 Base64 DER |
| `check_time` | 统一校验时刻（ISO-8601；裸时间按 UTC）。所有证据必须在**同一时刻**有效 |
| `max_skew_seconds` | 时钟偏差容忍秒数，同时作用于 OCSP 与 CRL 的时间窗口，**最多 300**，缺省 0 |

**OCSP 证据**逐条按 CertID 绑定到「某张证书 + 其经签名验证的链上签发者」
这一条确切签发边：序列号必须吻合，`issuerNameHash`/`issuerKeyHash` 用响应
自带哈希算法对签发者 DER Name 与 subjectPublicKey 位串重算；签名者必须是
签发者本身，或其直接签发、在 `check_time` 有效且含 `id-kp-OCSPSigning` 的
委派响应证书；签名、`producedAt`（不得晚于 check_time+skew）、必备的
`nextUpdate` 与 `[thisUpdate−skew, nextUpdate+skew]` 窗口全部校验（规则与
`/deployments/ocsp-precheck` 完全一致，含 RSASSA-PSS 参数解析）。

**CRL 证据**按签发者绑定：

- **间接 CRL**（`issuingDistributionPoint.indirectCRL`）与**增量 CRL**
  （`id-ce-deltaCRLIndicator`）一律返回 `indirect_or_delta_crl`，**不评估**；
- CRL 的签发者 DN 必须能在包内找到主体，且该主体公钥必须验签通过；找不到
  返回 `signer_not_found`，DN 匹配但签名不通过返回 `signature_invalid`；
  绑定以**密钥**唯一——同一 CA 密钥的重发/交叉签名 DER 副本（同 DN 同密钥）
  在密码学上是同一签发者，确定性绑定，不会造成歧义；
- 签名者必须是允许签发 CRL 的 CA（basicConstraints CA；存在 keyUsage 时须含
  `cRLSign`），否则 `signer_not_ca`；
- 必须携带 `nextUpdate`，且 `check_time` 落在
  `[lastUpdate−skew, nextUpdate+skew]`（过期 `stale`、过早 `not_yet_valid`、
  无 nextUpdate `next_update_missing`）。

只有**新鲜且真实**（fresh authentic）的证据参与结论：

- **新鲜 revoked 优先**：任一新鲜真实证据说 revoked，证书即
  `certificate_revoked`（陈旧 good 不能抵消新鲜 revoked）；
- **新鲜 good 与新鲜 revoked 同时存在**为 `conflicting_evidence`（两份 revoked
  一致不算冲突）；
- **证据缺失**（没有任何真实证据，或只有 unknown/验签失败的响应）为
  `evidence_missing`；证据真实但不在窗口内为 `evidence_stale`；
- 链末的**信任根不审查**（`trust_root`，恒 `eligible: true`）——它的撤销状态
  无法从链内部建立。

**每张非信任根证书都有同一时刻有效且一致的 good 证据**时端点才
`eligible: true`；端点级 `reason` 按 revoked → 冲突 → stale → missing → ok
汇总。成功返回 `200`，`results` 按 `endpoint_id` 稳定排序，每个端点给出
重建好的叶在前 `chain`（合格时即可作为 `target_chain` 交给 `/plans`）以及
按链顺序排列的逐证书结果；每条证据携带来源下标 `source_index`、`fresh`、
时间戳与上下文字段（OCSP 的响应状态/签名者信息、CRL 的签发者/`crl_number`/
全部与命中的撤销序列号等），并按 `(kind, source_index)` 稳定排序：

```json
{
  "check_time": "2030-01-01T00:00:00Z",
  "max_skew_seconds": 300,
  "results": [
    {
      "endpoint_id": "api.example.com",
      "target_leaf_fingerprint": "7cfe475a...",
      "eligible": true,
      "reason": "ok",
      "chain": ["7cfe475a...", "0ffede99...", "2bc09a3a..."],
      "certificates": [
        {"certificate_fingerprint": "7cfe475a...", "issuer_fingerprint": "0ffede99...",
         "role": "leaf", "serial_number": "1A2B...", "eligible": true,
         "reason": "ok", "revocation_time": null, "revocation_reason": null,
         "evidence": [
           {"kind": "crl", "source_index": 0, "reason": "good", "fresh": true,
            "issuer_fingerprint": "0ffede99...", "covered_serial_numbers": []},
           {"kind": "ocsp", "source_index": 0, "reason": "good", "fresh": true,
            "certificate_fingerprint": "7cfe475a...", "certificate_status": "good",
            "signer_type": "issuer", "this_update": "2024-01-01T00:00:00Z",
            "next_update": "2035-01-01T00:00:00Z"}
         ]},
        {"certificate_fingerprint": "0ffede99...", "role": "intermediate",
         "eligible": true, "reason": "ok", "evidence": [ ]}
      ]
    }
  ],
  "unattributed_evidence": [
    {"kind": "crl", "source_index": 2, "reason": "indirect_or_delta_crl",
     "fresh": false, "is_delta": true, "is_indirect": false}
  ]
}
```

**提交的每份证据都会出现在审计结果里**：无法绑定到任何被审查链证书的证据
（CertID 不匹配任何已验证签发边、CRL 签发者不在链上、间接/增量 CRL、无法解析
的 blob 等）统一进入 `unattributed_evidence`（按 `(kind, source_index)` 排序），
绝不静默丢弃。请求级错误（坏指纹、未知指纹、PEM 无法解析、链不唯一/不可达、
端点 id 重复）返回 `422`，结构与归一化接口一致。示例见
[`examples/revocation_review_request.json`](examples/revocation_review_request.json)，
可用 `examples/gen_revocation_review_example.py` 重新生成（窗口 2024–2035、
`check_time` 固定为 2030-01-01；其中一个端点是良好全 good，另一个端点的叶被
中间 CA 的新鲜 CRL 撤销，另有一个增量 CRL 演示不支持路径）。

### `POST /deployments/policy-review` — 证书用途与路径策略审查

在把证书交给规划器之前，对每个端点**当前正在服务**与**轮换后将服务**的两条链
做统一的 RFC 5280 路径策略审查：当前链已不合规的端点不得放行，只有合格的
目标链才能交给 `/plans`。请求与归一化接口共用同一份 PEM 包（同样的解析、
DER 指纹去重、签名验证与唯一链重建规则——多条信任路径仍按 `ambiguous_chain`
返回 422）、允许的信任根指纹，外加每端点的当前/目标叶指纹、TLS 角色、
所需 EKU 与统一校验时刻：

```bash
curl -s http://localhost:8080/deployments/policy-review \
  -H 'Content-Type: application/json' \
  --data @examples/policy_review_request.json
```

请求字段：

| 字段 | 说明 |
| --- | --- |
| `pem_certificates` / `trust_roots` | 与 `/scenarios/normalize` 相同；包需包含两条链的叶、全部中间证书与信任根 |
| `endpoints[].current_leaf_fingerprint` / `target_leaf_fingerprint` | 当前/目标叶 SHA-256 指纹（大小写不敏感）；`endpoint_id` 不得重复 |
| `endpoints[].role` | 端点 TLS 角色：`server`（隐式要求 `id-kp-serverAuth` 1.3.6.1.5.5.7.3.1）或 `client`（隐式要求 `id-kp-clientAuth` 1.3.6.1.5.5.7.3.2） |
| `endpoints[].required_ekus` | 除角色 EKU 外叶证书必须携带的额外 EKU 点分 OID（可空，重复项折叠） |
| `check_time` | 统一校验时刻（ISO-8601；裸时间按 UTC）。两条链上的**每张证书（含信任根）**都必须在该时刻处于有效期内 |

每条链按下列固定规则逐级审查，**当前链与目标链都合规**端点才
`eligible: true`：

1. **有效期（含边界）**：`notBefore <= check_time <= notAfter`，过早
   `certificate_not_yet_valid`、过期 `certificate_expired`；信任根同样校验。
2. **BasicConstraints**：每个 CA 位置（中间 CA 与信任根）必须携带
   basicConstraints 且 `cA=TRUE`——缺扩展 `missing_basic_constraints`、
   `cA=FALSE` 为 `not_ca`；叶证书不得是 CA（`leaf_marked_ca`）。
3. **pathLenConstraint**：对每个声明 pathLen 的 CA，统计本链中其**下方**
   （朝叶方向）的**非自颁发**中间 CA 数量（自颁发 = 主体 DN 等于签发者 DN，
   不消耗 pathLen 额度；RFC 5280 的计数包含锚与叶之间的所有中间证书，
   即 `pathLen=0` 的根下不允许任何中间 CA），超限为 `path_len_violation`，
   响应给出该 CA 的 pathLen 与实际下级 CA 数。
4. **CA/keyCertSign**：CA 位置证书**存在 KeyUsage 扩展时**必须含
   `keyCertSign`，否则 `missing_key_cert_sign`（无 KeyUsage 扩展不额外限制）。
5. **叶 KeyUsage**：叶存在 KeyUsage 时必须具备角色可用位——`client` 需要
   `digitalSignature`；`server` 接受 `digitalSignature` 或 `keyEncipherment`
   （后者对应传统 RSA 密钥交换叶），都不满足为 `leaf_key_usage_mismatch`。
6. **叶 EKU / 中间 CA EKU 链接**：叶必须断言角色 EKU 与全部 `required_ekus`；
   中间 CA 若带 EKU 扩展，则其允许的用途必须能**沿链下放**每个必需 EKU
   （`anyExtendedKeyUsage` 2.5.29.37.0 满足全部用途）；**信任根自身的 EKU
   不重复执行**。叶完全没有 EKU 扩展即不认证任何具体用途，按
   `required_eku_missing` 拒绝，响应给出所缺 OID 与证书实际 EKU 列表。
7. **未知关键扩展**：每张证书上任何标记为 critical 但不在验证器识别目录
   （完整 RFC 5280 扩展集及广泛部署的 PKIX/CT/Netscape OID）内的扩展一律
   失败关闭：`unknown_critical_extension`，响应给出扩展 OID。

成功返回 `200`，`results` 按 `endpoint_id` 稳定排序。每个端点给出
`eligible`、跨两条链的**首个冲突规则** `reason`（当前链优先于目标链；
链内按上述原因优先级、再按链位置稳定排序）、以及 `current_chain` /
`target_chain` 两条审查结果；每条链列出**参与证书**（叶在前，含
`is_ca` / `path_length_constraint` / `key_usages` / `extended_key_usages` /
`critical_extension_oids` 等定位信息）、链级 `eligible` / `reason` 与完整
`conflicts` 列表（机器可读原因 + 冲突证书指纹、链位置与该原因的上下文字段）：

```json
{
  "check_time": "2030-01-01T00:00:00Z",
  "results": [
    {
      "endpoint_id": "billing.example.com",
      "role": "server",
      "current_leaf_fingerprint": "9a1c...",
      "target_leaf_fingerprint": "c77e...",
      "eligible": false,
      "reason": "required_eku_missing",
      "current_chain": {
        "chain_role": "current",
        "chain": ["9a1c...", "2bc0..."],
        "eligible": false,
        "reason": "required_eku_missing",
        "certificates": [
          {"cert_id": "9a1c...", "subject": "CN=billing.example.com",
           "issuer": "CN=Billing Root CA", "chain_position": 0, "role": "leaf",
           "is_ca": false, "path_length_constraint": null,
           "key_usages": ["digital_signature"],
           "extended_key_usages": ["1.3.6.1.5.5.7.3.2"],
           "critical_extension_oids": ["2.5.29.15", "2.5.29.19"]}
        ],
        "conflicts": [
          {"reason": "required_eku_missing",
           "certificate_fingerprint": "9a1c...", "chain_position": 0,
           "required_eku": "1.3.6.1.5.5.7.3.1",
           "present_ekus": ["1.3.6.1.5.5.7.3.2"],
           "message": "server leaf 'CN=billing.example.com' does not assert ..."}
        ]
      },
      "target_chain": {"eligible": true, "reason": "ok", "conflicts": []}
    }
  ]
}
```

原因优先级（也是 `conflicts` 的稳定排序优先级）：
`certificate_expired` → `certificate_not_yet_valid` →
`missing_basic_constraints` → `not_ca` → `path_len_violation` →
`missing_key_cert_sign` → `leaf_marked_ca` → `leaf_key_usage_mismatch` →
`required_eku_missing` → `unknown_critical_extension`。

**只有 `target_chain.eligible: true` 的目标链可作为 `target_chain` 交给
`/plans`**；端点当前链不合规时（如叶已过期、角色 EKU 不符）整体
`eligible: false`，不得放行。请求级错误返回 `422`，结构与归一化接口一致
（`error`、`message`、`pem_issues` / `fingerprint_issues` /
`chain_issues`），另提供 `eku_issues`（`required_ekus` 中非法点分 OID，
错误码 `invalid_oid`，定位到端点与下标）；链不唯一/不可达、信任根非自签名
同样返回 `ambiguous_chain` / `no_trust_path` /
`trust_root_not_self_signed`。示例见
[`examples/policy_review_request.json`](examples/policy_review_request.json)，
可用 `examples/gen_policy_review_example.py` 重新生成（窗口 2024–2035、
`check_time` 固定为 2030-01-01；七个端点分别演示合格 server/client、
keyEncipherment-only server 叶、角色 EKU 不符、pathLen 超限、当前叶已过期
与未知关键扩展）。

### `POST /deployments/variants` — 异构客户端最小证书变体选择

端点面对**异构客户端**（不同 TLS 栈：信任不同根、只接受某些叶公钥类型、
只接受某些证书签名算法）时，可能要同时部署多条证书链（变体）。本接口为
每个端点选出**必须部署的最少变体集合**，使每条「必须连通」的 client →
endpoint 关系至少被集合中的一条链覆盖。请求包含一份 PEM 证书包（与
`/scenarios/normalize` 相同的解析与 DER 指纹去重规则）、每端点最多
**12** 条候选 leaf-first 指纹链、每个客户端的信任根/密码学策略，以及必连
关系：

```bash
curl -s http://localhost:8080/deployments/variants \
  -H 'Content-Type: application/json' \
  --data @examples/variant_request.json
```

请求字段：

| 字段 | 说明 |
| --- | --- |
| `pem_certificates` | 与 `/scenarios/normalize` 相同的 PEM 包 |
| `clients[]` | `client_id` + `trust_roots`（该客户端信任的自签名根指纹）+ `acceptable_leaf_key_types`（`rsa` / `ec` / `dsa` / `ed25519` / `ed448`）+ `acceptable_signature_oid`（可接受的**证书签名算法**点分 OID，如 PKCS#1 v1.5 SHA-256 为 `1.2.840.113549.1.1.11`、RSA-PSS 为 `1.2.840.113549.1.1.10`、ECDSA-SHA256 为 `1.2.840.10045.4.3.2`、Ed25519 为 `1.3.101.112`） |
| `endpoints[].candidate_chains` | 每端点 1..12 条候选链，每条均 leaf-first、末位为自签名根；完全相同的链折叠为同一个变体 |
| `relationships[]` | 必须连通的 `{client_id, endpoint_id}` 对，不得重复 |

一条候选链**覆盖**某个 (client, endpoint) 关系，当且仅当**同时**满足
（复用归一化接口的逐级签名验证，绝不只比对 subject/issuer）：

1. **链逐级验签通过**：链中每张证书的签名都能用下一张证书的公钥验证
   （支持 RSA PKCS#1 v1.5、RSA-PSS、ECDSA、DSA、Ed25519/Ed448），否则记
   `chain_signature_invalid`；
2. **末端受客户端信任**：链末位指纹属于该客户端的 `trust_roots`，否则记
   `root_untrusted`；
3. **叶公钥类型匹配**：叶证书公钥属于客户端可接受类型，否则记
   `leaf_key_type_incompatible`；
4. **签名算法被接受**：除信任根外**每张**证书的签名算法 OID 都在客户端
   接受列表内（信任根自身的签名算法不做策略检查，与 TLS 验证方对锚证书
   的处理一致），否则记 `signature_algorithm_incompatible`。

四类检查互相独立，一条链同时违反多条时全部列出。

**优化是全局精确的**：每个端点的「最少变体覆盖全部必连关系」是最小集合
覆盖问题；由于每端点至多 12 条候选链，接口通过**穷举所有链子集**（至多
4096 个）按集合大小递增求全局最优——**不会用逐客户端贪心冒充最优**
（贪心可能多部署本可省去的变体）。多解时把集合内各条**完整指纹链排序**
后取字典序最小的集合，因此结果与输入顺序无关。成功返回 `200`，
`selections` 按 `endpoint_id` 排序、集合内变体按链字典序排列并带
`variant_index`；`assignments` 把每条关系映射到所选集合中**排序最先的
兼容变体**（按 `(client_id, endpoint_id)` 排序）：

```json
{
  "status": "ok",
  "selections": [
    {"endpoint_id": "api.example.com", "variant_index": 0,
     "chain": ["3b8c4cb3...", "6196de6a..."]},
    {"endpoint_id": "api.example.com", "variant_index": 1,
     "chain": ["4734e0f9...", "0326d8ea..."]}
  ],
  "assignments": [
    {"client_id": "api-gateway", "endpoint_id": "api.example.com",
     "variant_index": 0, "chain": ["3b8c4cb3...", "6196de6a..."]},
    {"client_id": "legacy-java-8", "endpoint_id": "api.example.com",
     "variant_index": 1, "chain": ["4734e0f9...", "0326d8ea..."]},
    {"client_id": "modern-go", "endpoint_id": "api.example.com",
     "variant_index": 0, "chain": ["3b8c4cb3...", "6196de6a..."]}
  ]
}
```

**任一关系无法覆盖时返回 `409`**（`reason: uncoverable_relationship`），
`incompatibilities` 按 `(client_id, endpoint_id, chain, reasons)` 稳定列出
每个无法覆盖的关系上每条候选链的全部不兼容原因，并附叶证书实际公钥类型
`leaf_key_type`、链上除根外各证书的签名 OID `signature_oids` 以及该客户端
的 `trusted_roots` 便于诊断：

```json
{
  "status": "conflict",
  "reason": "uncoverable_relationship",
  "message": "one or more required client -> endpoint relationships cannot be covered ...",
  "incompatibilities": [
    {"client_id": "legacy-java-8", "endpoint_id": "api.example.com",
     "chain": ["e5b681a1...", "d8e62e66..."],
     "reasons": ["root_untrusted", "leaf_key_type_incompatible",
                 "signature_algorithm_incompatible"],
     "leaf_key_type": "ec",
     "signature_oids": ["1.2.840.10045.4.3.2"],
     "trusted_roots": ["d8e62e66..."]}
  ]
}
```

请求级错误返回 `422`，`detail` 中给出机器可读 `error`、`message` 与逐条
诊断：`invalid_pem`（附元素下标）、`invalid_fingerprint` /
`unknown_fingerprint`（指纹位置在 `referred_by` 中给出，如
`clients['c'].trust_roots` 或 `endpoints['e'].candidate_chains[0][1]`）、
`invalid_oid`（`oid_issues` 定位到具体客户端与下标）、`invalid_chain`
（空链 `empty_chain` / 含重复证书的成环链 `chain_cycle`）、
`trust_root_not_self_signed`（客户端声明的信任根必须是 subject == issuer
且自签名验证通过的证书）、`unknown_client` / `unknown_endpoint`（关系引用
了未声明的 id）以及 id 重复类 `invalid_request`。示例请求见
[`examples/variant_request.json`](examples/variant_request.json)，可用
`examples/gen_variant_example.py` 重新生成。

### `POST /plans` — 求最优计划

请求体见 [`examples/plan_request.json`](examples/plan_request.json)：

```bash
curl -s http://localhost:8080/plans \
  -H 'Content-Type: application/json' \
  --data @examples/plan_request.json
```

成功返回 `200`：

```json
{
  "status": "ok",
  "stage_count": 2,
  "stages": [
    {"stage": 1, "action_ids": ["a1-add-new-root"]},
    {"stage": 2, "action_ids": ["a2-serve-new-leaf", "a3-remove-old-root"]}
  ]
}
```

说明：

- 计划阶段数最少（经典根轮换即「先增信 → 换证与撤信并行」两步）。
- 存在多个最优解时，按动作的 `action_id` 排序后取各动作所在阶段号向量的
  字典序最小解，保证结果稳定、与输入顺序无关；每个阶段内的动作也按
  `action_id` 升序输出。
- 阶段内的动作视为并行生效；对同一信任锚同时增信与撤信是未定义的，会被禁止
  排到同一阶段。
- 阶段号是**绝对阶段号**：动作最早可能只能在较晚的阶段执行（例如唯一允许的
  阶段是 2）。此前的空阶段作为 **no-op（空操作）阶段**显式保留——信任状态
  原样跨过空档，每个阶段结束后仍校验全部信任关系。响应中以真实阶段号输出，
  空阶段形如 `{"stage": 1, "action_ids": []}`。

无解时返回 `409`，指出**首个无法维持的关系**与**阻塞动作**：

```json
{
  "status": "infeasible",
  "stage": 1,
  "relationship": {"client_id": "billing-service", "endpoint_id": "api.example.com"},
  "blocking_action": "a3-remove-old-root",
  "reason": "untrusted_root",
  "chain": [
    {"cert_id": "leaf-old", "subject": "CN=api.example.com", "issuer": "CN=Old Root CA"},
    {"cert_id": "root-old", "subject": "CN=Old Root CA", "issuer": "CN=Old Root CA"}
  ],
  "trusted_anchors": ["root-new"],
  "message": "stage 1: relationship billing-service -> api.example.com loses its trust path; ..."
}
```

若初始状态本身就不满足约束，`status` 为 `invalid`、`stage` 为 `0`、
`blocking_action` 为 `null`。

### `POST /plans/verify` — 逐阶段回放任意计划

在同一场景负载上附加一个 `plan` 字段（见
[`examples/verify_request.json`](examples/verify_request.json)）：

```bash
curl -s http://localhost:8080/plans/verify \
  -H 'Content-Type: application/json' \
  --data @examples/verify_request.json
```

计划合法返回 `200 {"status": "valid", ...}`；否则在**第一个失效阶段**返回
`409`，包含失效关系、阻塞动作、断开的证书链（leaf-first）以及该客户端此刻的
信任锚，便于定位是「换证太早」「撤信太早」还是「动作排到了未授权的阶段」。

回放逐阶段进行：`action_ids` 为空的阶段是合法 no-op（空档），回放会信任状态
原样带入该阶段并在阶段结束后**继续校验全部信任关系**，因此空档无法掩盖此前
已发生的失效；响应会保留真实阶段号并原样回显空阶段。

计划结构要求：阶段从 1 开始连续编号（编号中允许 no-op 空档）；每个动作必须
且只能出现一次。

### `POST /plans/reconcile` — 中断后安全恢复点判断

部署在中途中断（编排器重启、部分动作结果未知）后，把**原始 PlanRequest**、
`/plans` **已生成的 stages**，以及对现场的**部分观测**一起提交，接口枚举所有
符合计划顺序、且与观测一致的可达进度，并给出在每个可能进度下都安全的下一步动作。
示例见 [`examples/reconcile_request.json`](examples/reconcile_request.json)：

```bash
curl -s http://localhost:8080/plans/reconcile \
  -H 'Content-Type: application/json' \
  --data @examples/reconcile_request.json
```

请求在场景字段之外额外携带：

| 字段 | 说明 |
| --- | --- |
| `stages` | 已生成的计划（与 `/plans` 输出同构）：阶段从 1 连续编号，每个动作恰好出现一次，允许 no-op 空阶段 |
| `anchor_observations` | 对客户端信任锚的部分观测：`{client_id, anchor_cert_id, present}`。`present: true/false` 表示**确实观测到**该信任边存在/不存在；**未上报的对象一律保持未知，绝不当作「未执行/不存在」** |
| `chain_observations` | 对端点当前链的部分观测：`{endpoint_id, chain}`（leaf-first）。未列出的端点保持未知 |

进度状态按以下规则枚举（至多 12 个动作，状态空间有界）：

- **已结束阶段必须完整执行**：第 1..p 阶段的全部动作都已生效；
- **当前阶段允许任意动作子集**：第 p+1 阶段的动作
  可能执行了任意子集（含空集），其中每个动作还必须在该绝对阶段号被允许、
  子集内不得有同锚的增信/撤信矛盾；
- **后续阶段不得提前执行**：更晚阶段的动作在当前状态中一律未执行；
- 剔除**已破坏通信关系**的状态（任何 required 关系失去信任路径即不可作为恢复点），
  以及**与观测不符**的状态。no-op 空阶段是真实的已结束阶段：推进
  `completed_stages` 计数但不改变信任状态。

进度的完整身份是 **(已完成动作集合, 已结束阶段数)** 二元组，而非动作集合
本身：空阶段原样跨过信任状态，因此同一组已完成动作可能处在空档两侧的不
同阶段位置（尚未跨过空阶段 / 已跨过空阶段 / 处于连续空档之间，含计划以
空阶段开头与尾部空阶段的情形）。这些位置是**不同的可达进度**，接口分别
保留——观测永远无法证明一个什么都没做的空阶段已被跨过，只保留较大的
`completed_stages` 会凭空引入确定性。观测过滤、完成态（`current_stage`
是否为 `null`）与冲突判断都使用该完整身份。唯一的归并例外是观测上等价
的情形：**非空**当前阶段的动作全部执行完，与「该阶段已结束、下一阶段尚
未开始」是同一个记账点，规范位置取后者。

成功返回 `200`，`possible_progress` 按
`(completed_stages, completed_action_ids)` 稳定排序，逐条给出已结束阶段数、
`current_stage`（全部完成时为 `null`）以及该进度下已完成的全部
`completed_action_ids`；`safe_next_actions` 只包含在**每一个**可能进度中都
①属于当前阶段、②尚未完成、③在该绝对阶段号被允许、且④**单独执行**后全部
通信关系仍有有效信任路径的动作（按 `action_id` 排序）：

```json
{
  "status": "ok",
  "safe_next_actions": ["a2-serve-new-leaf"],
  "possible_progress": [
    {"completed_stages": 1, "current_stage": 2,
     "completed_action_ids": ["a1-add-new-root"]}
  ]
}
```

例如观测到「新根已被信任、端点仍在提供旧叶」时，阶段 1 必然已结束、阶段 2
尚未开始；此时单独换证安全（新链由新根验证），但单独撤信会让旧叶失去信任路径，
因此 `safe_next_actions` 只推荐换证。计划全部完成时 `current_stage` 为 `null`、
`safe_next_actions` 为空。

当计划含 no-op 空阶段时，`possible_progress` 可能列出
`completed_action_ids` 相同但 `completed_stages` / `current_stage` 不同的
多条进度（空档两侧各一条）；`current_stage` 为 `null` 仅表示**所有阶段**
（含尾部空阶段）都已结束，而非仅所有动作已执行。推论：只要某个保留进度
的当前阶段仍是未跨过的空阶段，任何动作都不属于该进度的当前阶段，
`safe_next_actions` 即为空——此时唯一安全的做法是先让编排器推进
（跨过）空阶段，接口不会推荐任何动作。

**未知不等于未执行**：不带任何观测时，从「尚未开始」到「已全部完成」的所有
健康进度都会列出；观测到 `present: false`（锚确实不存在）才会排除「该增信已
执行」的状态——两者语义截然不同。

无任何兼容的健康进度时返回 `409`：

- `reason: "no_safe_reachable_state"`：与观测无关，符合计划顺序的状态本身全都
  破坏了某条关系（含初始状态即无效），无安全恢复点；
- `reason: "observation_conflict"`：观测联合排除了全部健康状态。`conflicts`
  按固定顺序（先锚 `(client_id, anchor_cert_id)` 后端点 `endpoint_id`）给出
  **首个不兼容的观测切片**（贪心：每个与此前幸存状态全部矛盾的观测都会列出），
  每条含 `kind`、定位字段、机器可读 `reason`
  （`anchor_present_mismatch` / `anchor_absent_mismatch` /
  `endpoint_chain_mismatch`）与 `message`：

```json
{
  "status": "conflict",
  "reason": "observation_conflict",
  "message": "the observations rule out every plan-ordered healthy state; ...",
  "conflicts": [
    {"kind": "endpoint_chain", "client_id": null, "anchor_cert_id": null,
     "present": null, "endpoint_id": "api.example.com",
     "chain": ["leaf-new", "root-new"],
     "reason": "endpoint_chain_mismatch", "message": "..."}
  ]
}
```

计划结构错误（阶段不连续、动作缺失/重复/未知、动作排在 `allowed_stages` 之外、
同阶段矛盾增撤信）或观测引用未知 id 时返回 `422`。

### `POST /plans/replan` — 撤销发现后的安全续策重规划

计划在**执行期间**发现证书被撤销（或出现 good/revoked 冲突证据）时，原计划
的目标链可能已不再可部署。本接口在**不可回退的已完成前缀**之上重新计算
阶段最少的安全续策。请求携带原始 PlanRequest、已完成的 `action_ids`、各端点
**现场当前链**、每端点最多 **12** 条候选替代链，以及每张证书的**离线撤销
证据**（可直接来自 `/deployments/revocation-review` 的逐证书结论）：

```bash
curl -s http://localhost:8080/plans/replan \
  -H 'Content-Type: application/json' \
  --data @examples/replan_request.json
```

请求在场景字段之外额外携带：

| 字段 | 说明 |
| --- | --- |
| `completed_action_ids` | 已确定执行完成的动作；其效果（增信/撤信/换证）视为不可回退，先应用到恢复点状态再规划。同一信任边的增信与撤信都已完成时按撤信生效后的净状态计算 |
| `live_chains` | 各端点当前实际提供的链（叶在前）。未上报的端点按已完成前缀推断（已完成换证的端点提供 `target_chain`，否则提供 `current_chain`）；与已完成换证相矛盾的上报返回 422 |
| `candidates` | 每端点最多 12 条候选替代链（叶在前、自签名根结尾；完全相同的链折叠为同一选项） |
| `revocation_evidence` | 逐证书离线证据 `{cert_id, status, fresh}`，`status ∈ good / revoked / unknown`；只有 `fresh: true` 的 good/revoked 参与结论，陈旧与 unknown 一律忽略 |

证据与过滤规则：

- 某张证书存在**新鲜 revoked** 证据即被污染；同时存在新鲜 good 与新鲜
  revoked 为 `conflicting_evidence`（同样污染）。
- 含污染证书的**当前链**必须被轮换走，**目标链与候选链**永不部署；
  响应的 `excluded_chains` 按 `(endpoint_id, chain)` 稳定列出每条被剔除的
  链、链上首个污染证书 `blocking_certificate` 与原因。
- 每个剩余 `replace_cert` 动作在「`target_chain` ∪ 候选链」的**干净**子集中
  重新选定部署链，`chain_selections` 给出每个换证动作最终选定的完整链；
  其余剩余动作按原声明执行。续策阶段**从 1 重新编号**，剩余动作的
  `allowed_stages` 按续策编号解释；稀疏阶段号同样产生显式 no-op 空阶段
  （与 `/plans` 一致）。调用方若希望某动作在续策中立即执行，应让它的
  `allowed_stages` 包含 1。

多解裁决与 `/plans` 同源：先比阶段数，再比按 `action_id` 排序的逐动作阶段
向量，最后比按端点排序的**完整链指纹**序列，结果与候选提交顺序无关。每个
阶段结束后所有通信关系仍须保持有效——撤信永远不会排在仍在使用对应锚的
链之前。信任行为完全等价的候选链（对全部相关客户端命中相同锚集合）只在
指纹裁决时比较一次，取字典序最小者为代表。

成功返回 `200`（示例见
[`examples/replan_request.json`](examples/replan_request.json)：原计划
`a1` 已完成，随后 `leaf-new` 被新鲜撤销、候选 `leaf-alt2` 也被撤销，续策
把换证动作重定向到干净的 `leaf-alt`；由于 `a2` 声明的 `allowed_stages`
不含续策第 1 阶段，阶段 1 为显式 no-op）：

```json
{
  "status": "ok",
  "stage_count": 2,
  "stages": [
    {"stage": 1, "action_ids": []},
    {"stage": 2, "action_ids": ["a2-serve-new-leaf", "a3-remove-old-root"]}
  ],
  "chain_selections": [
    {"endpoint_id": "api.example.com", "action_id": "a2-serve-new-leaf",
     "chain": ["leaf-alt", "root-new"]}
  ],
  "excluded_chains": [
    {"endpoint_id": "api.example.com", "role": "candidate",
     "chain": ["leaf-alt2", "root-new"],
     "blocking_certificate": "leaf-alt2", "reason": "certificate_revoked"},
    {"endpoint_id": "api.example.com", "role": "target",
     "chain": ["leaf-new", "root-new"],
     "blocking_certificate": "leaf-new", "reason": "certificate_revoked"}
  ]
}
```

无可行续策返回 `409`：`status: "infeasible"` 并给出**首个无法维持的关系**、
**阻塞证书** `blocking_certificate`（被新鲜撤销/冲突证据污染的证书，或信任
游走断开的链上证书）与机器可读 `reason`（`certificate_revoked` /
`conflicting_evidence` / `untrusted_root` / `issuer_mismatch` /
`contradictory_actions_same_stage` 等），另附断开的链、客户端当前信任锚
`trusted_anchors` 与人类可读 `message`；恢复点状态本身已破坏关系时
`status` 为 `"invalid"`、`stage` 为 0、`blocking_action` 为 `null`：

```json
{
  "status": "infeasible",
  "stage": 0,
  "relationship": {"client_id": "billing-service", "endpoint_id": "api.example.com"},
  "blocking_action": "a2-serve-new-leaf",
  "blocking_certificate": "leaf-new",
  "reason": "certificate_revoked",
  "chain": [
    {"cert_id": "leaf-new", "subject": "CN=api.example.com", "issuer": "CN=New Root CA"},
    {"cert_id": "root-new", "subject": "CN=New Root CA", "issuer": "CN=New Root CA"}
  ],
  "trusted_anchors": ["root-new", "root-old"],
  "message": "every deployable chain for endpoint 'api.example.com' is tainted: ..."
}
```

结构错误返回 `422`：未知或重复的已完成动作、未知端点、候选链超过 12 条、
空链/成环/签发关系不吻合/未以自签名根结尾的链、证据引用未知证书、现场链
与已完成换证矛盾等（场景字段本身的校验与 `/plans` 完全相同）。

## 请求模型

| 字段 | 说明 |
| --- | --- |
| `certificates` | 全部证书：`cert_id`、`subject`、`issuer`、`not_valid_before`、`not_valid_after`（ISO-8601 时间，建议带时区；裸时间按 UTC） |
| `trust_anchors` | 计划开始前各客户端信任的锚证书 |
| `endpoints` | 每个端点的 `current_chain` 与 `target_chain`，**叶子在前、根在后**，末位必须是自签名根 |
| `relationships` | 必须始终保持有效信任路径的 client → endpoint 关系 |
| `actions` | 至多 **12** 个动作，每个动作声明 `allowed_stages`（可执行的阶段号集合） |
| `plan_time` | 计划时刻；缺省取当前 UTC。该时刻已过期或尚未生效的证书一律拒绝 |

动作类型：

- `add_trust`：`client_id` + `anchor_cert_id`
- `remove_trust`：`client_id` + `anchor_cert_id`
- `replace_cert`：`endpoint_id` + `new_chain`（必须等于该端点声明的 `target_chain`）

## 校验规则（422）

- 最多 12 个动作；`allowed_stages` 为正整数且不重复。
- 证书链不得成环（重复证书即视为成环）、签发关系必须逐跳吻合
  （issuer == 下一张证书的 subject）、必须以自签名根结束。
- 所有声明的证书在 `plan_time` 必须处于有效期内。
- 所有 id 引用必须存在；关系、信任锚、动作 id 不得重复。

## 本地开发

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

运行测试（含与暴力枚举的差分测试，120+ 用例）：

```bash
pip install pytest httpx
pytest -q
```
