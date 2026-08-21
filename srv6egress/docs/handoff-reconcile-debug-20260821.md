# 引き継ぎ: srv6egress の BGP→VPP reconcile が動かない件のデバッグ

作成 2026-08-21 / 対象: Calico-VPP エージェント (`calico-vpp-agent/srv6egress` + `calico-vpp-agent/routing/bgp_watcher.go`)

> **2026-08-21 解決済み。** 以下の 1〜10 節は調査開始時点の記録として残す。確定した根因、修正、テスト、実機 E2E 結果は 11 節以降を参照。

## 1. 何が起きているか (症状)

コントローラは EgressPolicy を解決して BGP に SR Policy 経路を広告するところまで正常に動く。しかし **エージェントがその経路を VPP に反映しない**。結果として VPP には SR policy も steering も 1 件も入らない。

確認済みの事実:

| 項目 | 状態 |
|---|---|
| EgressPolicy (2件) の `READY` | `True` (COLOR/UPSTREAM/ENDPOINT も期待どおり) |
| コントローラのログ | `announced via gobgp ... bsid=cafe::64 / cafe::c8` が出る |
| エージェントの EgressPolicy watcher | `EgressPolicy watcher started` まで到達、仕様エラーなし |
| `vppctl show sr policies` | **空** |
| `vppctl show sr steering-policies` | **空** |
| エージェントログの `injectSRv6Policy` / `Path SRv6` | **1 行も出ない** |

つまり BGP のパス更新がエージェントの SRv6 処理に到達していない。

## 2. アーキテクチャ (どこで切れているか)

```
EgressPolicy (CRD)
  → bgp-controller が color を候補経路へ解決          [OK]
  → gobgp へ SR Policy 経路を注入 (SAFI 73)          [OK]
  → agent の BGP watcher が WatchEvent で受信         [★ここが怪しい]
  → injectSRv6Policy() → common.SRv6PolicyAdded 発火  [未到達]
  → cmd/calico_vpp_dataplane.go の goroutine が受信
  → egressManager.OnSRPolicyAdded(bsid) で BSID を live 化
  → steering install (Manager が BSID の live を条件にする)
```

重要な設計: **steering は BSID が live になるまで入らない**。`srv6egress/manager.go` の `OnSRPolicyAdded` / `OnSRPolicyDeleted` が gate になっている (`manager_test.go` の `TestManager_SRPolicyLiveness` 参照)。なので SR policy が入らなければ steering も入らないのは仕様どおりで、**根本原因は BGP 側**。

## 3. 最有力の仮説

`calico-vpp-agent/routing/bgp_watcher.go` の `WatchEvent` コールバック内、SR Policy 分岐の**手前**に次のガードがある。

```go
if path.GetNeighborIp() == "<nil>" || path.GetNeighborIp() == "" { // Weird GoBGP API behaviour
    s.log.Debugf("Ignoring internal path")
    continue
}
if *config.GetCalicoVppFeatureGates().SRv6Enabled && path.GetFamily().GetSafi() == bgpapi.Family_SAFI_SR_POLICY {
    err := s.injectSRv6Policy(path)
    ...
}
```

今回の構成では **bgp-controller をエージェントと同じノードに置き、`--gobgp-addr=127.0.0.1:50051` でエージェント自身の GoBGP に gRPC で直接注入している**。ローカル注入されたパスは peer から学習したものではないため `NeighborIp` が空になり、SR Policy 分岐に到達する前に `continue` で捨てられている可能性が高い。

### 検証方法 (最優先)

1. エージェントのログレベルを debug にして `Ignoring internal path` が出るか見る。出ていれば仮説確定。
   - 現状のログは info のため `Debugf` が出ない。`CALICOVPP_LOG_LEVEL` 等で debug にすること。
2. または `bgp_watcher.go` のガードを一時的に「SAFI が SR_POLICY のときは NeighborIp が空でも通す」に変えて挙動を見る。

### 注意: 別環境でも同じ症状が出ている

memory `research_natless_e2e_forward_verified` によれば、**4 VM クラスタ (コントローラを別 VM の bgp-ctrl に置き、eBGP peer として接続した構成) でも** コントローラの SR policy が worker の agent に install されず、手動 `sr policy add` で代替していた。そちらでは `NeighborIp` は入るはずなので、**原因が 2 つある可能性がある**。ローカル注入の件を直しても解決しない場合は、次の 4 節を順に潰すこと。

## 4. 仮説が外れた場合に見る場所 (優先順)

1. **`getSRPolicy(path)` のパース失敗** — `injectSRv6Policy` の冒頭で呼ばれる。失敗すると `cannot inject SRv6: ...` が Error で出るはずなので、まずこのログの有無を確認。`errSRPolicyMixedBehavior` の分岐にも注意。
2. **feature gate** — `*config.GetCalicoVppFeatureGates().SRv6Enabled` が false だと SR Policy 分岐に入らない。今回は ConfigMap で `srv6Enabled: true` と `srv6EgressEnabled: true` を設定済みなので条件は満たすはずだが、パース経路を確認する価値はある。
3. **WatchEvent のフィルタ** — `WatchEventRequest_Table_Filter_BEST` で best path のみ購読している。SR Policy 経路が best として選出されているか (`gobgp global rib` で確認したいが、**エージェント同梱の gobgp CLI は SAFI 73 を知らず `unsupported address family` になる**。gRPC で直接引くか、新しい gobgp バイナリを持ち込むこと)。
4. **nodeIP4/nodeIP6 のガード** — SR Policy 分岐の手前に `nodeIP6 == nil` で ipv6 パスを捨てるガードがある。単一ノード IPv6 クラスタでノード IP が取れているかを確認。
5. **エンコーディング不一致** — コントローラは `--bgp-encoding=sr-policy` (SAFI 73) が既定。エージェント側が期待する NLRI 形式と一致しているか。`srv6egress/config/controller/controller-config.example.yaml` のコメントに「`bsid` per color is REQUIRED when running with --bgp-encoding=sr-policy」とある。今回の設定では両 color に `bsid` を入れてある。

## 5. 再現環境 (そのまま残してある)

**ホスト**: Proxmox `192.168.1.100` → VM 120 `gns3-mtu` (`192.168.1.120`, root で ssh 可)。
pve 経由で入る: `ssh root@192.168.1.100` してから `ssh root@192.168.1.120`。

**クラスタ**: 単一ノード kubeadm (`KUBECONFIG=/root/.kube/config`, ノード名 `gns3-mtu`)

現在デプロイされているもの:

- エージェント: `calicovpp/agent:srv6egress` (`imagePullPolicy: Never`、ローカルビルド)
  - `v3.32.0-srv6egress` と表示される。srv6egress のシンボルを 418 件含む
- コントローラ: `calicovpp/bgp-controller:srv6egress` (namespace `srv6egress-system`, hostNetwork, `--gobgp-addr=127.0.0.1:50051`)
- CRD / RBAC: `srv6egress/config/crd/bases/...` と `srv6egress/config/rbac/role.yaml` を適用済み
  - **注意**: `role.yaml` は ClusterRole を定義するだけで **ClusterRoleBinding は含まれていない**。`srv6egress-agent` ClusterRole を `calico-vpp-node-sa` に、`srv6egress-controller` を `srv6egress-controller` SA に手動で bind してある。ここが抜けると `egresspolicies ... is forbidden` で watcher が 5 秒ごとに再起動し続ける
- feature gates: ConfigMap `calico-vpp-config` の `CALICOVPP_FEATURE_GATES` に `{"srv6Enabled":true,"srv6EgressEnabled":true}`
- ノードラベル: `gns3-mtu` に `srv6egress.ryskn.io/role=egress`
- EgressPolicy: `tenant-a-via-isp-a` (color 100) / `tenant-b-via-isp-b` (color 200)、いずれも `destinationCIDRs: ["2001:db8:c::/64"]`
  - **`destinationCIDRs` は必須**。空だとコントローラが `InvalidDestinationCIDRs` で Ready にせず、エージェントも `no usable IPv6 destinationCIDRs ... skipping` を出す
- テナント Pod: namespace `tenant-a` / `tenant-b` に `app` (image `mtu-test:local`)。namespace に `tenant=a` / `tenant=b` ラベル

**コントローラ設定** (ConfigMap `srv6egress-controller-config`): テストベッドの BR に合わせた値

```yaml
upstreams:
  isp-a: { sid: "fcbb:bbbb:4:a1::", vrf: upstream-a }
  isp-b: { sid: "fcbb:bbbb:4:b1::", vrf: upstream-b }
colors:
  100: { bsid: "cafe::64", candidatePaths: [{ upstream: isp-a, segmentList: ["fcbb:bbbb:4:a1::"], preference: 200 }] }
  200: { bsid: "cafe::c8", candidatePaths: [{ upstream: isp-b, segmentList: ["fcbb:bbbb:4:b1::"], preference: 200 }] }
```

**GNS3 側 (データプレーンの受け皿)**: プロジェクト `ipsj-mtu-eval`。leaf/spine/dci-1/BR は zebra-rs コンテナ。BR に手動で peering SID を入れてある。

```
fcbb:bbbb:4:a1::  = End.DX6 nh6 2001:db8:a::1 (eth1 → isp-a)
fcbb:bbbb:4:b1::  = End.DX6 nh6 2001:db8:b::1 (eth2 → isp-b)
```

isp-a と isp-b の lo にどちらも `2001:db8:c::1/128` を付与済み (同一宛先で出口だけ変える検証用)。
コンテナ ID は `source /root/cidmap.sh` で `$C_leaf` `$C_br` `$C_isp_a` 等に入る (GNS3 API から生成)。

## 6. 期待する最終状態 (これが出れば成功)

```
vppctl show sr policies          → BSID cafe::64 と cafe::c8 の 2 本
vppctl show sr steering-policies → 2001:db8:c::/64 が各テナントの VRF (fib-table) 単位で 2 行
kubectl exec -n tenant-a app -- ping -6 2001:db8:c::1   → isp-a のキャプチャにのみ出る
kubectl exec -n tenant-b app -- ping -6 2001:db8:c::1   → isp-b のキャプチャにのみ出る
```

キャプチャの取り方:

```bash
source /root/cidmap.sh
docker exec -d $C_isp_a sh -c 'timeout 12 tcpdump -i eth0 -n -l "icmp6 && ip6[40]==128" > /tmp/capA.txt 2>&1'
docker exec -d $C_isp_b sh -c 'timeout 12 tcpdump -i eth0 -n -l "icmp6 && ip6[40]==128" > /tmp/capB.txt 2>&1'
# ping 後
docker exec $C_isp_a grep -oE "fd20::[0-9a-f:]+ > 2001:db8:c::1" /tmp/capA.txt | sort | uniq -c
```

この結果自体は **手動で VPP に SR policy と steering を入れた状態で取得済み** (テナントごとに出口が分かれることは実証できている)。今回直したいのは「同じ状態をエージェントが自動で作れるようにする」こと。

## 7. 手動での代替手順 (比較・切り分け用)

エージェントが入れるのと同じ内容を vppctl で直接入れる手順。デバッグ中に「VPP 側は正しいのか」を切り分けるのに使える。

```bash
POD=$(kubectl -n calico-vpp-dataplane get pods -o name | head -1 | cut -d/ -f2)
v() { kubectl -n calico-vpp-dataplane exec $POD -c vpp -- vppctl "$@"; }
v set sr encaps source addr fd00:1::10
v sr policy add bsid cafe::64 next fcbb:bbbb:4:a1:: encap
v sr policy add bsid cafe::c8 next fcbb:bbbb:4:b1:: encap
# Pod の VRF table-id を調べてから steering
v show interface addr | grep -B2 "<podIP>/128"     # → "ip6 table-id NNNN fib-idx MM"
v sr steer l3 2001:db8:c::/64 via bsid cafe::64 fib-table <TABLE-ID>
```

**⚠️ `fib-table` には fib-index ではなく table-id を渡すこと。** fib-index を渡すと **VPP が即クラッシュする** (実際に踏んだ。`fib-table 29` で落ちて DaemonSet が再起動した)。cnat の fib 引数が index なのと逆なので混同しやすい。

## 8. コード側の該当箇所

| ファイル | 役割 |
|---|---|
| `calico-vpp-agent/routing/bgp_watcher.go` | `WatchEvent` コールバック (L448〜)、`injectSRv6Policy` (L397〜)、`getSRPolicy`。**最初に見るべき場所** |
| `calico-vpp-agent/cmd/calico_vpp_dataplane.go` | L293〜 srv6egress の配線。L360〜 が `egressSRPolicyChan` → `OnSRPolicyAdded/Deleted` の goroutine。L392〜 に 30 秒周期の再 reconcile ticker |
| `calico-vpp-agent/srv6egress/manager.go` | `OnSRPolicyAdded` / `OnSRPolicyDeleted` (L118〜)。BSID の liveness gate |
| `calico-vpp-agent/srv6egress/steering.go` | `podDestPairs` (L51〜)。`destinationCIDRs` 必須のガードと、`MatchingLocalPodIPs` によるローカル Pod 解決 |
| `calico-vpp-agent/srv6egress/watcher.go` | EgressPolicy の watch |
| `calico-vpp-agent/srv6egress/resolver.go` | Pod/namespace informer |
| `calico-vpp-agent/common/common.go` | L238〜 `BgpFamilySRv6IPv4` / `BgpFamilySRv6IPv6` (SAFI_SR_POLICY) |
| `srv6egress/cmd/bgp-controller/` | コントローラ本体。フラグは `--config` `--gobgp-addr` `--bgp-backend` `--bgp-encoding` |

既存テスト: `calico-vpp-agent/srv6egress/manager_test.go` (BSID liveness)、`gateway_test.go`、`calico-vpp-agent/common/srv6_policy_test.go`。
**回帰テストを足すなら**、bgp_watcher の「ローカル注入パス (NeighborIp 空) でも SAFI 73 なら処理する」ケースが最優先。

## 9. ビルド手順 (今回使ったもの)

Mac (arm64) からクロスコンパイルして VM に持ち込むのが速い (エージェント本体で 36 秒)。

```bash
cd ~/project/vpp-dataplane
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/agentbuild/calico-vpp-agent ./calico-vpp-agent/cmd
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/agentbuild/bgp-controller ./srv6egress/cmd/bgp-controller
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/agentbuild/felix-api-proxy ./calico-vpp-agent/cmd/api-proxy
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/agentbuild/gobgp github.com/osrg/gobgp/v3/cmd/gobgp/
# calico-vpp-agent/Dockerfile は bin/ 配下の成果物を ADD するだけ
```

VM 側で `docker build` → `docker save | ctr -n k8s.io images import -` で kubelet から見えるようにする (レジストリ不要、`imagePullPolicy: Never`)。
エージェントを入れ替えると **VPP も再起動し、手動で入れた SR 設定は全部消える**ので注意。

## 10. やってはいけないこと / 注意

- **LXC には触らない** (pve 上の 109/110/200-203)。VM は停止してよい。
- VM 114 (fpga-sim) はメモリ確保のため停止したまま。
- VPP を再起動すると GNS3 側の手動設定 (BR の peering SID、isp の `2001:db8:c::1`) は残るが、**VPP 内の SR policy / steering は消える**。
- テストベッド全体を作り直す場合は `/root/bringup-testbed.sh` がある (GNS3 起動 → zebra-rs 設定 → kind 配線 → VPP SR 設定 → smoke test)。ただし手動 SR 設定込みなので、自動 reconcile を試すときは該当部分を飛ばすこと。
- この件は情報処理学会 IOT75 の原稿 (`srv6egress/paper/ipsj-iot75/`) に関係する。原稿では「コントローラが解決して BGP 広告するところまで」と「転送がテナントごとに分かれること」を**別々の確認結果**として書いてあり、両者を繋ぐ自動反映は主張していない。直ったら原稿側も更新する余地がある。

## 11. 確定した根因

原因は 1 個ではなく、次の 4 点が直列に重なっていた。

1. **ローカル GoBGP API 注入パスを internal path として捨てていた。**
   組み込み GoBGP を使った再現テストで、`AddPath` した SR Policy は global RIB と BEST watcher には入る一方、`Path.NeighborIp` が文字列 `"<nil>"` になることを確認した。旧 `bgp_watcher.go` は SR Policy SAFI の判定前にこの値を見て `continue` していた。
2. **BGP watcher 開始前に入った best path を replay していなかった。**
   `WatchEventRequest_Table_Filter` の `Init` が未指定だったため、controller の広告が先行すると次の更新まで見えない startup race があった。
3. **API 注入パスは GoBGP 再起動で消える。**
   controller の広告状態は相手側 GoBGP のメモリ内にしかなく、agent/GoBGP 再起動後に EgressPolicy の Kubernetes event がなければ再広告されなかった。
4. **SR Policy を受信しても、通常の node prefix がないと VPP へ policy を入れなかった。**
   `SRv6Provider.AddConnectivity()` は候補を `nodePolices` に保存した後 `installNode()` を呼ぶが、同関数は `nodePrefixes[nodeip] == nil` なら即 return する。srv6egress は policy の BSID に対する per-pod-VRF steering を別途作るため、通常の node prefix を持たない。このため BGP event は届くようになっても `cafe::64` / `cafe::c8` の実体が VPP に入らなかった。

加えて、egress manager は raw `SRv6PolicyAdded` event を VPP install 成功とみなしていた。connectivity provider と egress consumer は別 goroutine なので順序保証がなく、policy 不在の BSID に steering を先行させて `VPPApiError: Invalid sw_if_index (-2)` を出していた。`SwIfIndex=~0` と `FibTable=pod VRF table-id` の要求自体は正しく、エラー表示は policy 不在時に現れた二次症状だった。

## 12. 入れた修正

| ファイル | 修正内容 |
|---|---|
| `calico-vpp-agent/routing/bgp_watcher.go` | SR Policy SAFI を `NeighborIp` より先に分類。SRv6 有効時はローカル注入 SR Policy を処理し、ローカル unicast は従来どおり無視。BEST watcher に `Init: true` を追加。 |
| `calico-vpp-agent/connectivity/srv6.go` | RFC 9256 の `<endpoint,color>` ごとに候補を選択し、`nodePrefixes` がなくても各 color の policy を VPP へ install。成功済み状態を追跡して同一再広告で `AddMod` を繰り返さず、候補切替・withdraw を reconcile。 |
| `calico-vpp-agent/common/pubsub.go` | raw BGP intent と区別する `SRv6PolicyInstalled` / `SRv6PolicyUninstalled` dataplane acknowledgment event を追加。 |
| `calico-vpp-agent/cmd/calico_vpp_dataplane.go` | egress BSID liveness を raw Added/Deleted ではなく provider の Installed/Uninstalled で更新。 |
| `calico-vpp-agent/cni/cni_srv6egress.go` | 既に消えた steering の削除 (`NO_SUCH_INNER_FIB` / `UNSPECIFIED`) を成功扱いにして、候補切替後に manager の追跡状態が残らないようにした。 |
| `srv6egress/internal/controller/egresspolicy_controller.go` | 正常な EgressPolicy を 30 秒ごとに再 reconcile / 再広告し、agent/GoBGP 再起動後を自己修復。 |

設計上の要点は、候補選択を endpoint+behavior 全体ではなく **SR Policy のキーである endpoint+color 内**で行うことと、BSID の live 判定を「BGP で見えた」ではなく「VPP API 操作が成功した」にしたこと。今回のように同じ endpoint・同じ End.DT6 behavior に color 100/200 が共存しても、`cafe::64` と `cafe::c8` の両方が入る。

## 13. 追加した回帰テストと結果

- `srv6egress/internal/bgp/gobgp_srpolicy_test.go`
  - 組み込み GoBGP へローカル `AddPath` した SR Policy が global RIB と BEST watcher に入り、`NeighborIp == "<nil>"` になる境界を固定。
- `calico-vpp-agent/routing/srpolicy_parse_test.go`
  - ローカル SR Policy、SRv6 無効時、ローカル unicast、peer unicast の分類を固定。
- `calico-vpp-agent/connectivity/srv6_test.go`
  - node prefix なしで同一 endpoint の color 100/200 を両方 install。
  - VPP install 失敗時は liveness event を出さない。
  - 同一再広告は成功 heartbeat を出すが policy を再構築しない。
  - standalone policy の候補 failover は `Installed -> Uninstalled -> Installed` となり、survivor を VPP へ入れる。
- `srv6egress/internal/controller/egresspolicy_controller_test.go`
  - 正常 reconcile が 30 秒後の再広告を予約することを固定。

実行結果:

```text
Linux/amd64 connectivity test binary on VM 120: PASS (全テスト)
go test ./srv6egress/... ./calico-vpp-agent/srv6egress -count=1: PASS
Linux/amd64 calico-vpp-agent full build: PASS
git diff --check: PASS
```

macOS 上では `netlink.FAMILY_ALL` を使う Linux 専用 package のため connectivity/routing を直接実行できない。両 package は Linux/amd64 test binary をクロスビルドし VM 120 で実行した。routing の `TestGetSRPolicy_*` とローカル SR Policy 分類テストも PASS 済み。

## 14. VM 120 への反映状態

2026-08-21 07:27 UTC 頃に `calico-vpp-node` DaemonSet を rollout した。手動の `vppctl sr policy add` / `sr steer` は一切使っていない。

| 項目 | 値 |
|---|---|
| agent binary SHA-256 | `e3c8b359ac6e9660288b37bfc6fc1d95741bf185c75423737cf194525922c9b0` |
| containerd agent image | `docker.io/calicovpp/agent:srv6egress` → `sha256:5f56f2e260766fae734b241fedfff1a8fa8201ac0c98478052309ee96b5f4021` |
| controller image | `docker.io/calicovpp/bgp-controller:srv6egress` → `sha256:75c042bad4352f36ba64910db47f5a5d2e9c09dba4e5c13f0e3c13e52d3c8a4f` |
| 現 agent Pod | `calico-vpp-node-s2mc6`、2/2 Ready、restart 0 (最終確認時) |
| 直前 agent backup | `/root/agentbuild-backups/calico-vpp-agent.bgp-watcher-only-20260821` |
| 調査開始前 backup | `/root/agentbuild-backups/calico-vpp-agent.pre-reconcile-20260821` |
| controller backup | `/root/agentbuild-backups/bgp-controller.pre-reconcile-20260821` |

controller は 30 秒周期で両 policy を再広告している。rollout で VPP と GoBGP が空になった後も Kubernetes object の編集なしで自動復元し、その後 10 分以上、agent/VPP restart 0、`InstallSteering failed`、`Invalid sw_if_index`、SR Policy add error は 0 件だった。

## 15. 最終 E2E 結果

自動 reconcile 後の `vppctl show sr policies` の関連部分:

```text
BSID: cafe::64  -> fcbb:bbbb:4:a1::  weight 1
BSID: cafe::c8  -> fcbb:bbbb:4:b1::  weight 1
```

同じ一覧には通常の LocalSID 広告から作られた `cafe::194` / `cafe::195` も存在する。これは期待どおりで、egress 用 2 本とは別物。

`vppctl show sr steering-policies`:

```text
L3 2001:db8:c::/64  cafe::64
L3 2001:db8:c::/64  cafe::c8
```

同一 prefix が 2 行あるのは重複ではなく、tenant-a Pod VRF と tenant-b Pod VRF の別 table に入っているため。実パケットで table 分離まで確認した。

| 送信元 | Pod IPv6 | ping | isp-a echo request | isp-b echo request |
|---|---|---:|---:|---:|
| `tenant-a/app` | `fd20::965:e35a:ca30:921b` | 3/3、loss 0% | 3 | 0 |
| `tenant-b/app` | `fd20::965:e35a:ca30:921c` | 3/3、loss 0% | 0 | 3 |

宛先は両方とも `2001:db8:c::1`。GNS3 の isp-a / isp-b `eth0` で送信元 IP まで指定した `tcpdump` を同時実行した。capture は各コンテナの次のファイルに残してある。

```text
/tmp/verify-tenant-a.txt
/tmp/verify-tenant-b.txt
```

したがって、当初別々にしか確認できていなかった次の一連の経路が、今回は手動 VPP 設定なしで E2E 接続された。

```text
EgressPolicy -> controller resolve -> local GoBGP SR Policy SAFI
  -> agent BEST watcher -> SRv6Provider VPP policy install acknowledgement
  -> per-pod-VRF steering -> tenant ごとの GNS3 ISP 出口
```

## 16. 現在の結論と残作業

この不具合については **解決・実機確認済み**。VM 120 は修正版を稼働させたまま残してある。LXC 109/110/200-203 には触れていない。

コードを commit / PR 化する場合は、作業ツリーに元からある `srv6egress/config/controller/controller-config.example.yaml` の変更や大量の untracked 論文・build artifact を今回の修正へ混ぜないこと。この文書自身も現時点では untracked。IOT75 原稿で「BGP 広告」と「tenant 別転送」を別々の結果としている記述は、今回の自動 E2E 成功を反映して更新できる。
