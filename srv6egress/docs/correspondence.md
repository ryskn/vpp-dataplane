# 対応表(フル)— srv6egress / BGP-driven SRv6 Egress Path Steering

研究のスライド・設計章(issue #5)・実装・PR/issue・実機検証・標準(RFC)を横断で対応づけた一覧。

- 設計 issue: **ryskn/vpp-dataplane-research #5**
- 実装ブランチ: `srv6egress/agent-hook`(PR #15 → #16 → #17 を stack)
- 検証環境: AlmaLinux 10.1 / Kubernetes 1.36.1 / CRI-O 1.32.1、IPv6 single-stack(fd00:1::/64)

凡例: ✅ 実装+実機検証済 / ⚙ stub・skeleton(本番化前) / ⬜ 未実装(予定)

---

## A. スライド ↔ 設計章 ↔ 成果物 対応表

`motivation_simple.pptx`(10 枚)を軸に、各スライドが issue #5 のどの章・どの成果物に対応するか。

| # | スライドタイトル | 区分 | issue #5 章 | 主な裏付け(PR / issue / 実機) | 状態 |
|---|---|---|---|---|---|
| 1 | タイトル | 導入 | 概要 | issue #5 概要 | — |
| 2 | 研究概要 ― ひとことで | 概要 | 概要 / §3 | PR #15〜#17、issue #5 §6 アーキ図 | — |
| 3 | 社会課題 ― k8s から経路を選べない | Motivation | §0.1 | issue #5 §0.1 | — |
| 4 | 既存手法との違い | Motivation | §0.2 | issue #5 §0.2 比較表 + 4 差別化 | — |
| 5 | なぜ SID でなく color か | Motivation | §0.3 | RFC 9256 §2.1/§6/§8.4, 9012, 8402 | — |
| 6 | どう実現するか | アプローチ | §0.4 / §3 / §6 | PR #15/#16/#17、issue #5 §6 | ✅/⚙ |
| 7 | 評価 ― 社会課題と一対一 | 評価 | §0.5 | issue #9 / #10 / #14 | ✅/⬜ |
| 8 | 何ができるようになるか | 効果 | §0.1 ↔ §5.x | issue #10 color 分岐 pcap | ✅ |
| 9 | どこまで実装したか | 進捗 | §9 | PR #15〜#17、issue #6〜#10、#14 | ✅/⚙ |
| 10 | 今後の実装予定 | 予定 | §8.5 / §9 | issue #14、各 stub の TODO | ⬜ |

> リッチ版 `motivation_sections.pptx`(§0.1〜§0.6 + 概要/効果/実装/予定 = 10 枚)も同じ章に対応。

---

## B. 実装コンポーネント ↔ PR/issue ↔ 状態 ↔ 検証 対応表

| コンポーネント | パス | 役割 | PR | 関連 issue | 状態 | 検証方法 |
|---|---|---|---|---|---|---|
| EgressPolicy CRD | `srv6egress/apis/v1alpha1/` `config/crd/` | color 等を宣言する API | #15 | #11 | ✅ | `kubectl apply` / printer列 / color=0・空pool reject(実機) |
| RBAC | `srv6egress/config/rbac/role.yaml` | controller/agent 権限 | #15(+#17 fix) | #11 | ✅ | finalizer 用 update/patch を実機で確認 |
| bgp-controller | `srv6egress/cmd/bgp-controller/` `internal/controller/` | EgressPolicy reconcile | #16 | #12 | ✅ | reconcile / status / finalizer teardown(実機) |
| controller config | `srv6egress/internal/config/` | color→upstream→SID 解決 | #16(+#4 fix) | #12 | ✅ | segmentList 終端=SID 検証 + IPv6 正規化(unit) |
| VIP allocator | `srv6egress/internal/vipalloc/` | per-tenant VIP 払い出し | #16(+#1 fix) | #12 | ⚙ | in-memory stub。restart 再登録は unit+実機。本番=Calico IPAM ⬜ |
| BGP distributor | `srv6egress/internal/bgp/` | SR Policy を BGP 配布 | #16(+#3 ガード) | #12 | ⚙ | logging stub(起動時 WARNING)。本番=gobgp Color Ext-Community ⬜ |
| agent hook | `calico-vpp-agent/srv6egress/` | headend で SR steering install | #17 | #13 | ⚙ | manager/watcher は unit test 済。agent 本体への wire-up ⬜ |
| vpp-route-sync | `srv6egress/cmd/vpp-route-sync/` `internal/routesync/` | gobgp RIB → VPP VRF FIB | #17(d0bd3d6a/3bb6dc20) | #9 | ✅ | SRv6 decap→VRF→ISP ping + withdraw/failover(実機)、stateless(unit) |

### B-1. SPECA / Codex 指摘の修正コミット対応

| 指摘 | finding | 修正コミット | 内容 |
|---|---|---|---|
| segmentList 終端が upstream SID と不一致でも通る | SPECA #4 | `663b57ea` | Validate に cross-check 追加 |
| SID 検証が文字列のみ | Codex | `19072981` | `net.ParseIP` で IPv6 正規化比較 |
| `<color,endpoint>` 重複 | SPECA #2 | `b165697f` | reconciler に cluster-wide uniqueness |
| restart で VIP 再発行衝突 | SPECA #1 | `b165697f`+`075dd09c` | Register + 起動時 rehydrate(順序非依存) |
| egressIPPool の allowedUses 未検証 | SPECA #5 | `b165697f` | IPPool を読み `[Tunnel]` 必須 |
| stub が BGP UPDATE 送らない | SPECA #3 | `b165697f` | 設計通り、起動時 WARNING |
| RBAC で finalizer 更新不可 | Codex | `e3808674` | egresspolicies に update/patch |
| route-sync が restart で state 喪失 | Codex | `3bb6dc20` | VPP FIB を source of truth に(stateless 化) |

---

## C. 社会課題(§0.1)↔ 既存の限界 ↔ 本研究の解 ↔ 評価(§0.5)↔ 状態（フル）

| 社会課題(§0.1) | 既存手法の限界(§0.2) | 本研究の解 | 評価での立証(§0.5) | 状態 |
|---|---|---|---|---|
| (a) tenant 単位 path intent ギャップ | egress GW は IP を選ぶだけ、経路を選べない | color で per-tenant に経路クラスを宣言 | color 分岐の pcap(tenant A→ISP-A / B→ISP-B、issue #10) | ✅ |
| (b) compliance / sovereignty の宣言的強制 | k8s API で宣言・validation・GitOps する手段が無い | EgressPolicy CRD + apiserver validation + finalizer | EgressPolicy lifecycle(selector+検証+適用、PR #16 実機) | ✅ |
| (c) 障害耐性の k8s 側制御不能 | static 設定で片肺障害に追従できない | per-VRF eBGP + vpp-route-sync で経路自動同期 | eBGP withdraw → 自動切替を pcap 立証(issue #9/#10) | ✅ |
| (d) 5G/telco SR-TE backbone 統合の欠如 | pod は backbone の path class を意識できない leaf | color を backbone まで連続させる BR 化 | v1alpha2 roadmap(§8.5)で proposed extension(issue #14) | ⬜(PoC: L3VPN まで ✅) |

---

## D. RFC/標準 ↔ 本研究実装 対応表(§0.3)

| 主張 | 根拠(出典強度) | 本研究での実装箇所 | 状態 |
|---|---|---|---|
| color = 経路の intent | RFC 9256 §2.1(Tier1 RFC) | `EgressPolicy.spec.egress.color`(CRD field) | ✅ |
| color extended community で SR Policy を steer | RFC 9256 §8.4 + RFC 9012 §3.4.2(Tier1) | bgp-controller の BGP 配布(本番は gobgp) | ⚙(stub) |
| BSID が network opacity を提供 | RFC 9256 §6(Tier1) | v1alpha2 backbone 一体化で BSID | ⬜ |
| color の意味付けは operator scope | RFC 9012(Tier1) | `controller-config.yaml`(operator が color→upstream 定義) | ✅ |
| per-flow state は ingress(headend)に限定 | RFC 8402(Tier1) | pod ノード = headend で SR steering install(agent) | ⚙(skeleton) |
| BSID が domain churn を source から隠す(運用例示) | draft-filsfils-…-considerations(Tier2) | §6 の illustration として引用 | — |
| Data Sovereignty / Multi-Tenant の use case | draft-hr-…-intentaware-routing-using-color(Tier3) | §0.1 (b)(d) の傍証として引用 | — |
| SRv6 services を BGP で配布(backbone 統合) | RFC 9252 | v1alpha2、PoC で L3VPN-v6(SAFI 128)まで実機確認 | ⬜(PoC ✅) |

---

## E. 検証環境(lab)対応表

| ノード | VMID | IPv4 | ULA / peering | 役割 | SRv6 / BGP |
|---|---|---|---|---|---|
| master.ryskn.k8s | 103 | 192.168.1.10 | fd00:1::10 | control-plane | — |
| worker-1.ryskn.k8s | 101 | 192.168.1.11 | fd00:1::11 | worker | — |
| worker-2.ryskn.k8s | 102 | 192.168.1.12 | fd00:1::12 | worker | — |
| srte-egress-1.ryskn.k8s | 105 | 192.168.1.14 | fd00:1::14 / eth1 fda1::14 / eth2 fda2::14 | **egress GW**(role=egress) | VRF100 End.DT6 `fcff:0:0:e0:a::` / VRF200 `fcff:0:0:e0:b::`、host gobgp AS 64512(:50052) |
| sim-isp-a | 106 | 192.168.1.20 | fda1::1 | 疑似 ISP-A | gobgp AS 64500、`2001:db8:a::/64` 広告 |
| sim-isp-b | 107 | 192.168.1.21 | fda2::1 | 疑似 ISP-B | gobgp AS 64600、`2001:db8:b::/64` 広告 |

### E-1. color / upstream / VRF / SID マッピング

| color | upstream | VPP VRF table | End.DT6 SID | peer(next-hop) | 出口 prefix |
|---|---|---|---|---|---|
| 100 | isp-a(低遅延) | 100 | `fcff:0:0:e0:a::` | fda1::1 | `2001:db8:a::/64` |
| 200 | isp-b(低コスト) | 200 | `fcff:0:0:e0:b::` | fda2::1 | `2001:db8:b::/64` |

per-tenant egress VIP プール: `2001:db8:e::/64`(IPPool `tenant-egress-pool`、`allowedUses: [Tunnel]`)

### E-2. 完全 packet path(実機確認済み)

```
Pod(color=100) → headend SRv6 encap → [outer dst = fcff:0:0:e0:a::]
  → srte-egress-1 VPP: End.DT6 decap → VRF 100 lookup
  → 2001:db8:a::/64 via fda1::1(vpp-route-sync が gobgp RIB から install)
  → sim-isp-a 着  ✅ (localsid Good カウンタ + tcpdump + ping で立証)
```

---

## F. タスク issue 対応表

| issue | タスク | 対応 PR/コンポーネント | 状態 |
|---|---|---|---|
| #6 | srte-egress-1 node 構築・join | (インフラ) | ✅ |
| #7 | per-upstream VRF + End.DT6 SID | (VPP 設定) | ✅ |
| #8 | sim-ISP-A/B(gobgp eBGP speaker) | (インフラ) | ✅ |
| #9 | per-VRF eBGP + VIP advertise + dataplane | vpp-route-sync | ✅ |
| #10 | E2E pcap(color 分岐 + failover) | (実機検証) | ✅ |
| #11 | EgressPolicy CRD types | PR #15 | ✅ |
| #12 | bgp-controller skeleton | PR #16 | ✅(stub) |
| #13 | calico-vpp-agent hook | PR #17 | ⚙(skeleton) |
| #14 | (optional) v1alpha2 PoC(backbone) | (実機 L3VPN-v6) | ⬜(PoC ✅) |
