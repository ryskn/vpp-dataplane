# GUA migration 手順書 — pod prefix ULA(fd20::/16)→ per-tenant GUA

> issue #5 v24 §14.1 の実装(lab)。documentation prefix `2001:db8::/32` を「GUA 役」として使用(closed testbed の代役、論文に一文断る)。
> 本線コード前提: PR #39/#40/#41 反映済み(`dev/srv6egress-v1` @ `50cb9d7c`)= controller は `backbone.tenants` + AdvSet 導出 + validation(4) を持つ。
> 作成 2026-07-21。実行前に §0.3 のコード確認 2 点を必ず潰すこと。

---

## 0. 設計判断とアドレスプラン

### 0.1 スコープの限定(blast radius 最小化)

- **migrate するのは tenant namespace の pod だけ**。`kube-system` / `calico-system` 等の system pod は **fd20 default pool に残す**。
  - 理由: egress steering / NAT-less return の対象は tenant workload のみ。system pod を巻き込むと coredns pin・calico-apiserver 等の壊れ物(既知の cross-node ClusterIP 問題)に触る。ULA pool と GUA pool の共存は Calico 的に何の問題もない。
- node アドレス(fd00:1::/64)・service CIDR(fd30::/…)・SID/locator pool(`allowedUses: [Tunnel]` の cafe/fcff 系)は **一切触らない**。

### 0.2 アドレスプラン

| 用途 | prefix | 備考 |
|---|---|---|
| cluster pod GUA block | `2001:db8:2000::/40` | 2001:db8::/32 内。既存利用と衝突しない位置 |
| tenant-a pool | `2001:db8:2000::/48` | namespace `tenant-a` |
| tenant-b pool | `2001:db8:2001::/48` | namespace `tenant-b`(居れば) |
| (予約)追加 tenant | `2001:db8:2002::/48`〜 | /48 単位 = 実 Internet の filter 慣行と相似形(§14.1) |

**衝突チェック済みの既存利用**(触らない/避ける): `2001:db8:a::/64` = sim-isp-a loopback(`2001:db8:a::1`)、`2001:db8:100::/64` = テストの destCIDR、旧 VIP pool `2001:db8:e::/64`(廃止済み・残骸に注意)。

### 0.3 実行前の確認事項(2026-07-21 コード確認済みの分を反映)

1. **[確認済] GW agent の戻り集約は単一 CIDR のみ**: `GatewayManager.SetClusterReturn(podCIDR, clusterVRF)`(`calico-vpp-agent/srv6egress/gateway.go:144`)で受けた 1 本を、`gateway_vpp.go:165` が InstallGateway 時に upstream VRF へ冪等 install(**teardown 時は残置** — 他 tenant が共有するため。掃除は手動)。**per-tenant の dataplane return route は未実装 → PR D 確定**(§10)。
   - **[残确認] SetClusterReturn の呼び出し元**(agent main のどの env/config が podCIDR を渡すか)。migration 中の選択肢: (a) agent 設定は fd20::/16 のまま、GUA は §4 の手動 route で並置(推奨・最小変更)、(b) agent 設定値を GUA 集約 `2001:db8:2000::/40` に変更(agent 再起動要 = calico-vpp pod 再作成 + VM reboot 手順に注意。旧 fd20 route は残置仕様なので手で消す)。
   - 注: VPP の bounce route は /40 集約 1 本でも機能する(per-tenant 粒度が本質的に要るのは **BGP 広告側** = PR C 実装済み)。§5.3 の「exclusive tenant は主権集合外の VRF に戻り route を持たない」の dataplane 側厳密化が PR D の役割。
2. **controller config の現物**: bgp-ctrl VM 上の `controller-config.yaml` に `backbone.clusterPodCIDR: fd20::/16` が居るか、colors の candidate upstream が全部 `backbone.peers` に居るか(**validation(4) は tenants 設定時に fail-fast する** — peers 不足だと controller が起動しない)。

---

## 1. 事前監査(チェックリスト)

```bash
# (1) ★ node の stale SLAAC 監査 — worker-1 240b 事故の再発防止。
#     GUA(global)を fabric に増やす migration は再発条件そのもの。
for n in master worker-1 worker-2 srte-egress-1; do
  ssh $n 'ip -6 addr show scope global | grep -v fd00'   # fd00 以外の global が出たら要調査
done
#     fabric の RA 設定(radvd / uplink ルータ)に global prefix の RA が無いこと。
#     calico node annotation の v6 が fd00:1::x であること:
kubectl get nodes -o custom-columns='NAME:.metadata.name,V6:.metadata.annotations.projectcalico\.org/IPv6Address'

# (2) IPPool 棚卸し(calico-apiserver は 0/1 の既知問題があるため v3 API でなく CRD 直読み)
kubectl get ippools.crd.projectcalico.org -o yaml > /tmp/ippools-backup-$(date +%F).yaml
#     確認: fd20 pool / SID pool(allowedUses: [Tunnel])の構成。SID pool は以後触らない。

# (3) ベースライン health
kubectl get nodes; kubectl -n calico-vpp-dataplane get pods   # 全 2/2
kubectl get egresspolicies -o wide                            # Ready 状態を記録

# (4) バックアップ
kubectl get egresspolicies -o yaml > /tmp/egp-backup-$(date +%F).yaml
scp bgp-ctrl:/etc/srv6egress/controller-config.yaml /tmp/controller-config-backup-$(date +%F).yaml

# (5) GW スナップショット(後で diff するため)
ssh srte-egress-1 'vppctl show sr localsids; vppctl show sr policies; vppctl show ip6 fib table 100 summary'
```

---

## 2. 順序の設計(なぜこの順か)

**制約**: PR C の validation で `clusterPodCIDR` と `tenants` は**排他**。`tenants` に切り替えた瞬間、fd20::/16 の cluster-wide 広告は消える。
**帰結**: 「旧 ULA pod の backbone return」と「新 GUA pod の backbone return」は**同時には広告できない**。→ tenant pod が数個の lab では「切替ウィンドウ中、tenant egress は一時停止」を受け入れるのが最も単純(§7 に rollback あり)。

```
① GUA pool 追加(additive、無停止)
② 新 pool の疎通 smoke(canary pod、egress 以外)
③ GW に per-tenant return route 追加(additive、無停止)
④ controller config を tenants に切替 + 再起動   ← ここが切替点(fd20 広告消滅)
⑤ tenant pod rolling 再作成(fd20→GUA)
⑥ e2e 検証
⑦ 残骸掃除(fd20 の tenant 分)
```

---

## 3. GUA IPPool 追加と namespace 紐付け(手順 ①②)

```yaml
# tenant-a-pool.yaml(kubectl apply。apiVersion は CRD 直: apiserver 0/1 対策)
apiVersion: crd.projectcalico.org/v1
kind: IPPool
metadata:
  name: tenant-a-gua-pool
spec:
  cidr: 2001:db8:2000::/48
  blockSize: 122            # v6 default に合わせる
  natOutgoing: false        # NAT-less(§14.1)。true は自己矛盾
  nodeSelector: all()
  allowedUses: ["Workload"] # SID pool(Tunnel)と役割分離を維持
```

```bash
kubectl apply -f tenant-a-pool.yaml   # (tenant-b も同様)
kubectl annotate ns tenant-a "cni.projectcalico.org/ipv6pools=[\"tenant-a-gua-pool\"]" --overwrite

# canary: tenant-a に pod を 1 個立て、GUA 払い出しと cluster 内疎通だけ確認(egress はまだ)
kubectl -n tenant-a run canary --image=busybox --restart=Never -- sleep 3600
kubectl -n tenant-a get pod canary -o jsonpath='{.status.podIP}'   # 2001:db8:2000:… であること
# cross-node ping / DNS(kube-dns は DSR)を確認 → OK なら canary 削除
```

- ⚠️ v6 単独クラスタは image live-pull 不可 → busybox は各ノードに pre-load 済み(skopeo)のものを使う。
- Calico BGP mesh が新 pool の block route を配るのは自動。headend SRv6 encap は pod prefix 非依存(node SID 宛)なので、intra-cluster は値の変更だけで動くはず — canary で裏取り。

---

## 4. GW の per-tenant return route(手順 ③、additive)

§0.3-1 の確認結果に従い、agent 未対応なら手動(既存の fd20 集約と**並置** — この時点では消さない):

```bash
ssh srte-egress-1
# ⚠️ vppctl の fib 引数は table-id と fib INDEX の混同で crash 歴あり。必ず show で確認してから。
vppctl show ip6 fib table 100 summary
# upstream VRF(table100)に per-tenant return を追加(cluster VRF = table 0 へ返す):
vppctl ip route add 2001:db8:2000::/48 table 100 via ip6-lookup-in-table 0
vppctl ip route add 2001:db8:2001::/48 table 100 via ip6-lookup-in-table 0
vppctl show ip6 fib table 100   # 反映確認
```

- sim-isp-a 側にも戻り static(BGP で広告が届くなら不要): `2001:db8:2000::/48 via fda1::14` 等。§6 の RIB 確認で判断。
- ⚠️ next-hop は **egress IF 明示が必須**の経路もある(過去に `fib:0` recursion → `dpo-drop`)。追加後に必ず `show ip6 fib` で resolved を確認。

---

## 5. controller config 切替(手順 ④ = 切替点)

```yaml
# controller-config.yaml の backbone 節を書き換え
backbone:
  # clusterPodCIDR: fd20::/16     ← 削除(tenants と排他。両方あると Validate() が reject)
  tenants:
    tenant-a: {namespace: tenant-a, podCIDR: "2001:db8:2000::/48"}
    tenant-b: {namespace: tenant-b, podCIDR: "2001:db8:2001::/48"}
  returnPrependASN: <自 ASN>      # backup 劣後を使うなら。0/省略 = prepend なし
  # returnPrependCount: 3         # 既定 3
  peers: (既存のまま — colors の全 candidate upstream をカバーしていること = validation(4))
```

```bash
# ⚠️ 既知の結合: controller が落ちると EgressPolicy Ready:False → GW agent が provisioning を撤去する。
#    restart は「速やかに」。切替後、Ready が True に戻るまで GW の localsid/route を watch する。
ssh bgp-ctrl 'systemctl restart srv6egress-bgp-controller'   # (デプロイ形態に合わせる)
ssh bgp-ctrl 'journalctl -u srv6egress-bgp-controller -n 50'
# 期待ログ: "advertised tenant return reachability to backbone" が tenant × AdvSet 分。
# validation(4) で起動失敗したら peers 不足 — config を直す(これが fail-fast の意図どおりの挙動)。
kubectl get egresspolicies -o wide   # Ready が True に戻ること
```

**RBAC 注意**: controller の ServiceAccount に namespaces get/list/watch が要る(PR C で `config/rbac/role.yaml` 更新済み)。**cluster に適用済みの ClusterRole が古いままだと namespace read で失敗**する — 適用を忘れない:
```bash
kubectl apply -f srv6egress/config/rbac/role.yaml
```

---

## 6. tenant pod 再作成と検証(手順 ⑤⑥)

```bash
# tenant の pod を rolling 再作成(deployment なら rollout restart、裸 pod なら delete→再 apply)
kubectl -n tenant-a delete pod --all   # IPPool annotation 済みなので GUA で再払い出し

# 検証マトリクス:
# (a) pod IP が 2001:db8:2000:… であること
# (b) intra-cluster: cross-node pod-to-pod / DNS / pod-backed ClusterIP(DSR)
# (c) 広告: sim-isp-a / sim-isp-b の gobgp RIB に per-tenant /48 が居ること
#     - primary 側 = 素、backup 側 = AS-path prepend 付き(設定時)を RIB の AS_PATH で確認
#     - exclusive tenant が居るなら、主権集合外の ISP の RIB に「無い」ことを確認(経路レベル不達)
ssh sim-isp-a 'gobgp global rib -a ipv6 | grep 2001:db8:2000'
# (d) forward e2e: tenant pod → 2001:db8:a::1(sim-isp-a lo)ping/TCP。
#     GW trace で End.DT6 decap 後の inner src = pod GUA のまま(SNAT 無し)を確認
# (e) return e2e: 応答が per-tenant return route(table100 → table0)経由で pod へ。source 保持を L7 で確認
# (f) ★ invariant の実地確認(bogon/uRPF A/B 実験の前哨):
#     candidate に isp-b が居る color の tenant について、isp-b の RIB にも tenant prefix が居ること
#     (= 「failover しても行きが落ちない」の広告面の裏取り)
```

---

## 7. Rollback(各段階から)

| 段階 | 手順 |
|---|---|
| ③まで | 追加分(pool / annotation / VPP route)を消すだけ。無停止 |
| ④の後 | controller-config を backup から戻して restart(fd20 広告復活)。GW の per-tenant route は残しても無害 |
| ⑤の後 | namespace annotation を外す → pod 再作成で fd20 に戻る → ④ の rollback |

判断基準: §6 (b) が壊れたら即 rollback(intra-cluster は migration で壊れないはずの領域 = 想定外)。(c)〜(e) の失敗は前進デバッグ(広告/route の設定ミスの可能性が高い)。

---

## 8. 残骸掃除(手順 ⑦、soak 後)

- GW table100 の `fd20::/16 → lookup-in-table 0`(tenant 用途分)を削除 ※ system pod が GW 経由の何かに依存していない事を確認してから
  - PR D 以降の agent は upgrade 時にこの stale 共有集約を upstream VRF から**自動 sweep** する(watcher の初回 List 完了後、ReconcileAll 1 周期以内)。手動 `ip route del` は不要 — legacy mode の policy が残る upstream VRF だけは温存される
- sim-ISP 側の fd20 static/学習経路の削除
- fd20 pool は **default pool として存続**(system pod 用)。tenant 専用 fd20 pool が別にあれば `disabled: true` → 全 pod 退去確認 → 削除
- 旧 VIP 残骸(`2001:db8:e::/64` 関連の route/steering)が VPP に残っていないか `vppctl show sr steering-policies` で最終確認(過去に dangling steering の実績あり)

---

## 9. 既知の地雷(memory からの持ち込み)

1. **stale SLAAC**(§1-(1))— 本 migration 最大の再発条件。必ず最初に。
2. **calico-apiserver 0/1** — IPPool 操作は CRD 直(`crd.projectcalico.org/v1`)で。
3. **controller 死亡 → GW 撤去**(§5)— restart は速やかに、Ready を watch。
4. **vppctl の fib INDEX vs table-id**(§4)— 混同で crash 歴。
5. **v6 単独クラスタは image live-pull 不可** — canary は pre-load 済み image で。
6. **cross-node ClusterIP(host-backed)の既知障害** — migration と無関係に元から壊れている。検証で混同しない。

## 10. Follow-up(migration 完了後に起票)

- **PR D(確定)**: agent の per-tenant return route。内容: (1) `GatewayRequest.ReturnCIDR` の単数を per-tenant 化(controller の `backbone.tenants` と同じ tenant→prefix を agent に配る経路の設計込み — env 1 本では足りない)、(2) **exclusive tenant の主権集合外 upstream VRF には route を張らない**(§5.3 の dataplane 厳密化。現状は共有集約が全 upstream VRF に入る)、(3) teardown 残置仕様の見直し(per-tenant 化すると「他 tenant が共有」前提が崩れるため参照カウント or 導出 sweep)。
- **bogon/uRPF A/B 実験**(§14.1/§14.3 の実証): sim-ISP に ACL(`fd00::/8 deny` + strict uRPF 相当)→ ULA pod で行き drop / GUA pod で pass、exclusive 広告を絞った状態での failover blackhole 再現 → AdvSet 導出で解消、の before/after
- `::/0` steering → catch-all EgressPolicy(§14.6)
- NPTv6 compose spike(§14.7)
