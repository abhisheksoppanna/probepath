# probepath — DESIGN.md

**The single source of truth for probepath v1.** It works through the design from five angles — AWS networking, the red-team false-negative hunt, Terraform internals, Python architecture, and validation strategy — and where those angles pulled in different directions, the resolution and its reasoning are called out inline under **Resolution:** notes.

---

## The product promise

> Your security scanner screams about 47 misconfigurations. probepath proves 46 are unreachable — and shows the ONE real path from the internet to your database, hop by hop, before you ever run `terraform apply`.

probepath statically analyzes Terraform for AWS and decides whether a network path from an untrusted source (`0.0.0.0/0`, `::/0`, or any CIDR covering public address space) to a sensitive sink (RDS, ElastiCache, sensitive S3, etc.) is **possible under AWS's documented VPC routing and filtering semantics**. It suppresses scanner findings that are provably unreachable, and renders the real path hop-by-hop with the exact rule that allows each hop.

This is a **configuration/intent reachability** claim, not a data-plane claim — the same scope AWS VPC Reachability Analyzer operates in ("builds a model of the network configuration… does not send packets or analyze the data plane"), except probepath runs **pre-apply** on the Terraform plan.

### The five non-negotiable principles

1. **A false negative is fatal.** Marking a genuinely reachable sensitive path "unreachable" destroys all trust and is worse than a false positive. When an input is unknown / uncomputable / ambiguous / out-of-model, treat the path as **potentially reachable**, never silently suppress.
2. **Fully offline + reproducible.** No AWS account, no API keys, no live network calls. Input is Terraform plan JSON and/or `.tfstate` and/or raw HCL. Demo fixtures ship committed. Re-running on the same input yields the identical verdict and hop trace.
3. **Defensible.** Every claim must survive a skeptical senior security engineer's 5-minute grilling. We invent no accuracy percentages and claim no validation we did not perform.
4. **Python-native core.** Real graph construction + constrained pathfinding (`networkx`), not glue.
5. **Flagship quality.** This is a portfolio project for a senior DevOps/SRE engineer. The quality bar is extremely high.

---

## 1. Scope

### 1.1 The three-valued verdict (the heart of the trust model)

A two-state (reachable / unreachable) engine **will** ship false negatives. probepath is ternary. The verdict vocabulary is fixed before any code is written:

| Verdict | Meaning | When emitted | Suppresses a scanner finding? |
|---|---|---|---|
| `REACHABLE` | A concrete path from an untrusted source to the sink exists under modeled semantics. | At least one path has **all** hops provably open. | No — surfaced as a confirmed real path (red). |
| `POTENTIALLY_REACHABLE` | Cannot prove unreachable; conservative fallback. | Any required input on an otherwise-open path is unknown, uncomputable, ambiguous, or out-of-model. | **No** — surfaced (yellow). |
| `UNREACHABLE` | No path can exist. | **Every** candidate path is provably blocked at a modeled hop, **with all relevant inputs fully known**. | **Yes** — this is the only verdict that suppresses. |

**The cardinal rule, mechanized:** `UNREACHABLE` is emitted **only** when the model has complete, known information proving closure. Unknowns never downgrade a verdict toward `UNREACHABLE`. To *wrongly* suppress, the engine would have to prove closure on a path that is actually open — a model bug, which §6's property tests hunt — not an unknown-handling slip.

A path's verdict is its **weakest link** on the lattice `UNREACHABLE < POTENTIALLY_REACHABLE < REACHABLE`. If any hop is `POTENTIALLY_REACHABLE`, the whole path is at best `POTENTIALLY_REACHABLE`.

Internally, `POTENTIALLY_REACHABLE` carries a reason class so messaging and metrics stay honest:
- `UNKNOWN_INPUT` — value not known until apply / unparseable (`after_unknown`, unresolved var, `count`/`for_each` cardinality, managed prefix-list contents, remote-state/cross-account reference).
- `OUT_OF_MODEL` — a feature we deliberately don't model is on the path (third-party appliance, Network Firewall, full TGW route-table propagation).

> **Resolution (Pass 1 used `POTENTIALLY_REACHABLE`; Pass 2 used `UNDETERMINED`; Pass 4/5 used `POTENTIALLY_REACHABLE`).** We standardize on **`POTENTIALLY_REACHABLE`** as the verdict enum value (clearer to a reader of the report), with the `UNKNOWN_INPUT` / `OUT_OF_MODEL` reason split from Pass 5 carried as a sub-reason. `UNDETERMINED` is rejected as user-facing copy because it reads as "tool failed" rather than "conservatively flagged."

### 1.2 v1 modeled vs out-of-scope

The governing rule for everything in the right column: **if a path could traverse it, the path is `POTENTIALLY_REACHABLE` and is never suppressed.** Out-of-scope ≠ ignored; out-of-scope = "we don't prove it safe."

| MODELED PRECISELY in v1 | OUT OF SCOPE v1 → conservatively `POTENTIALLY_REACHABLE` / flagged |
|---|---|
| Route tables, subnet→RT association, main-RT fallback, `is_public` derivation | VPC peering far-side trust, full Transit Gateway route-table propagation (assume reachable if a route to the connector exists) |
| Security groups: stateful, CIDR + SG-to-SG + `self`, all-protocol `-1` | Custom NAT *instances* / `source_dest_check=false` forwarders (flag as `OUT_OF_MODEL`) |
| NACLs: stateless, ordered (rule-number ascending, first-match-wins), ephemeral return-path | AWS Network Firewall / Gateway Load Balancer inline inspection |
| IGW (inbound), NAT GW (egress-only, never inbound), egress-only IGW (IPv6 outbound only) | Route 53 / DNS-based exposure, L7 / WAF rules, application-layer auth, IAM identity policies, TLS/mTLS |
| ALB + NLB (incl. SG-less NLB, client-IP preservation), listener→target-group→target | API Gateway → Lambda L7 *invoke* (if a Lambda is publicly wired, conservatively treat it as reachable for its egress to sinks) |
| EC2 / ENI public IP / EIP / `map_public_ip_on_launch` | Host firewalls (iptables/OS), target health, actual listening processes |
| RDS (direct + in-VPC; `publicly_accessible` as necessary-not-sufficient) | Global Accelerator, CloudFront origin paths (flag), Direct Connect / VPN ingress (flag if gateway present) |
| ElastiCache, Redshift (`publicly_accessible`), OpenSearch (access policy) — configurable sink set | Cross-account assume-role / data-plane IAM, runtime drift after apply |
| S3 (Block Public Access + bucket policy + ACL, separate non-network evaluator) | Interface-endpoint PrivateLink provider side, org SCPs, VPC-endpoint authorization nuances |
| Gateway VPC endpoints (for S3 `aws:SourceVpce` policy logic) | IPv6 NACL edge cases beyond `::/0` |
| IPv4 **and** IPv6 (`::/0`) untrusted sources | — (note: we exceed RA here; RA is IPv4-only) |

### 1.3 The conservative-default cheat sheet (encode as ONE policy table)

| Unknown / unresolved input | v1 behavior |
|---|---|
| Route table / main RT unresolved | `is_public = true` |
| Route target `(known after apply)` | could be IGW ⇒ public |
| NACL association unknown | treat as default NACL ⇒ ALLOW |
| Custom NACL, empty | DENY — but **only** if we are certain it is custom (not default) |
| SG rule dynamic / unexpanded / known-after-apply | ALLOW for the affected ports, tag `UNKNOWN_INPUT` |
| NLB SG presence unknown | assume no SG ⇒ open |
| `publicly_accessible` unknown | assume `true` |
| Sink port unknown | test **all** ports the relevant SG opens |
| S3 BPA / policy / ACL field unknown | assume public |
| Customer-managed prefix list contents not in plan | `POTENTIALLY_REACHABLE` (`UNKNOWN_INPUT`) |
| Reference to remote-state / cross-account / unmodeled type | placeholder node, edges `POTENTIALLY_REACHABLE` (`UNKNOWN_INPUT`/`OUT_OF_MODEL`) |
| Path traverses peering / TGW / out-of-scope feature | `POTENTIALLY_REACHABLE`, never suppress |
| Ephemeral return port (statically unknown) | allow if **any** port in `1024–65535` is open |

Every assumption emits a tagged note so the output can say *why* a path is "potentially" rather than "definitely" reachable. There is no fourth "default to safe" state.

---

## 2. Reachability model

### 2.1 Confirmed AWS semantics (the load-bearing facts)

These are the facts the engine encodes. Getting any wrong produces a false negative. Citations in §8.

1. **Security groups are STATEFUL.** Inbound allow ⇒ return traffic auto-allowed. For a forward L4 reachability question, evaluate **only inbound** SG rules on the destination. SGs are allow-only (no deny). [SG/NACL, SG rules]
2. **NACLs are STATELESS and ordered.** Rules evaluated lowest-rule-number-first, **first match wins** (allow or deny), no further rules; implicit final `*` DENY. A forward flow needs an **inbound ALLOW** on the destination subnet's NACL **AND** an **outbound ALLOW on the ephemeral return range** (statelessness). [NACL docs]
3. **Default NACL allows all** in and out. A **custom NACL denies all** until allow rules are added, and always ends with the un-removable `*` DENY. [NACL docs]
4. **An SG rule whose source is another SG** means "allow from the private IPs of ENIs carrying the referenced SG," scoped same-VPC/peering/TGW — *not* a CIDR. The internet (`0.0.0.0/0`) can enter **only** via an IP-CIDR rule covering public space, **never** via an SG-reference. [SG rules]
5. **NLB security groups:** an NLB can have an SG **only if assigned at creation**. An **SG-less NLB enforces no SG — all client traffic reaches the listeners** (the critical conservative case). [ELB NLB SG docs]
6. **NLB client-IP preservation** (default for instance + TCP/TLS/UDP targets): the **target sees the original client IP**, so the target's SG must allow the client CIDR (or reference the NLB's SG). ALBs always proxy (target sees the ALB). [ELB target-group docs]
7. **RDS `publicly_accessible = true` is NECESSARY but NOT SUFFICIENT.** Internet reachability also requires the DB subnet group's subnet to be public (route `0.0.0.0/0 → igw`), an IGW on the VPC, DNS resolution, and a permissive SG. `publicly_accessible = false` ⇒ no public IP ⇒ not directly internet-reachable (still reachable via an in-VPC hop). [RDS VPC docs, Config rule]
8. **Internet-facing vs internal ALB differ only in ingress source.** Internet-facing accepts `0.0.0.0/0` on the listener port; internal accepts only VPC CIDR. A LB is a **relay node**. [ELB SG docs]
9. **S3 is not VPC-based.** Reachability is governed by Block Public Access (account + bucket), bucket policy, and ACL — never by route tables/SGs/NACLs. A separate evaluator. [S3 BPA docs]
10. **VPC peering is NOT transitive; Transit Gateway IS transitive** (subject to TGW route-table associations/propagations). [TGW docs]
11. **Ephemeral return-port ranges vary** (Linux 32768–60999/61000, Windows 49152–65535, **ELB/NLB 1024–65535**). AWS's own NACL examples recommend opening `1024–65535`. We use the **widest superset `1024–65535`** for the conservative return-path check. [ephemeral-ports docs]

### 2.2 Node / edge model

**Core invariant:** an edge `A --P--> B` exists iff a packet with destination port/proto `P` originating at `A` can be delivered to `B` (and, for the NACL stateless check, the return packet can get back). The graph is a `networkx.MultiDiGraph` (two nodes may be joined by multiple distinct rules). Reachability of a sink = "does a constrained path exist from an internet source node to the sink such that the port/protocol constraint is satisfiable along the path."

**Nodes** (one per *expanded* resource instance, keyed by Terraform `address`):

| Node | Represents | Key attributes |
|---|---|---|
| `InternetSource` | untrusted source `0.0.0.0/0` + `::/0` | synthetic singleton, id `__internet__` |
| `InternetGateway` | `aws_internet_gateway` | attached `vpc_id` |
| `NatGateway` | `aws_nat_gateway` | subnet; **egress-only, never an inbound edge** |
| `Vpc` / `Subnet` | `aws_vpc` / `aws_subnet` | subnet: vpc, cidr, route_table_id, nacl_id, `is_public` (derived), `map_public_ip_on_launch` |
| `RouteTable` | `aws_route_table` (+assoc) | ordered `routes` |
| `SecurityGroup` | `aws_security_group` | ingress/egress rules, vpc |
| `NetworkAcl` | `aws_network_acl` | ordered ingress/egress rules |
| `Eni` / `Instance` | ENI / EC2 / ECS task / Lambda-in-VPC | subnet, SG set, public IP/EIP |
| `LoadBalancer` | ALB/NLB/CLB | scheme (internet-facing/internal), type, subnets, SG set (may be empty), listeners |
| `TargetGroup` | `aws_lb_target_group` | protocol, port, target_type, preserve_client_ip, targets |
| `RdsInstance` | `aws_db_instance`/`aws_rds_cluster` | db_subnet_group→subnets, vpc SG set, port, `publicly_accessible` |
| `ElastiCacheNode` / `RedshiftCluster` / `OpenSearchDomain` | sensitive sinks | SG set, subnet group, port / access policy |
| `S3Bucket` | `aws_s3_bucket` (+ policy/PAB/ACL) | BPA flags, policy-allows-anon, ACL — **evaluated out-of-band, no VPC edges** |
| `VpcEndpoint` | `aws_vpc_endpoint` | type (gateway/interface), service, SG, policy |

A **sink** is any node tagged sensitive (RDS, ElastiCache, Redshift, OpenSearch, sensitive S3, plus user-configurable types/tags/name-regex).

**Edges** carry an `EdgeConstraint` (`port_set`, `source_cidrs` or `source_sg`, `stateful`, `direction`), a `rationale` string, a `SourceLocation`, and a `confidence`. The `confidence` of an edge is the `min()` of its contributing inputs (a single `after_apply` input downgrades the edge and caps any path through it at `POTENTIALLY_REACHABLE`).

| Edge | Gate (all AND unless noted) |
|---|---|
| `InternetSource → InternetGateway` | IGW attached to a VPC (always; filtering is downstream). |
| `InternetGateway → Eni` (public-IP instance) | subnet `is_public` AND ENI has public IP/EIP (or `map_public_ip_on_launch`) AND subnet NACL allows in `P` + out ephemeral AND ENI SG set allows internet-covering CIDR on `P`. |
| `InternetGateway → LoadBalancer` (internet-facing) | scheme `internet-facing` AND ≥1 LB subnet `is_public` AND subnet NACL allows AND (LB has no SG → pass) OR (LB SG allows internet CIDR on a listener port). |
| `LoadBalancer → TargetGroup target` | a listener matches incoming `P` and forwards to the tg on `P'` AND the target SG gate passes (see §2.7). |
| `Eni → any in-VPC node` | intra-VPC `local` route implicit AND dst SG allows src (CIDR or SG-ref) AND both subnets' NACLs allow (skip NACL if same subnet). |
| `InternetGateway → RdsInstance` (direct) | RDS `publicly_accessible == true` AND ≥1 DB-subnet-group subnet `is_public` AND vpc-SG allows internet CIDR on the engine port AND NACL allows. |
| `NatGateway → InternetSource` | **egress only** — modeled for exfil findings (§2.9), never an inbound ingress edge. |

Each edge stores a `reason`/`rationale` so the output renders the path hop-by-hop with the *exact* allowing rule (SG rule id, NACL rule number, route, listener).

### 2.3 Evaluation order (the pipeline)

Strict order so `is_public`, SG resolution, and NACL resolution are computed once and reused:

```
1. Parse → normalized resources (plan JSON preferred; tfstate; HCL fallback)        → §3
2. Resolve references (sg ids, subnet ids, rt assoc, nacl assoc, tg attach, listeners) by REFERENCE not value
3. Derive subnet.is_public (route-table analysis)                                    → §2.4
4. Build SG allow-matrix (CIDR + SG-to-SG, inbound)                                  → §2.5
5. Build NACL evaluators per subnet (ordered, stateless)                             → §2.6
6. Instantiate nodes + inject InternetSource singleton
7. For each candidate edge, run the gate (AND/OR of steps 3–5 + construct rule); widen + tag on unknown
8. Constrained pathfinding InternetSource → each sink                                → §2.10
9. Emit reachable/potential paths (hop trace) + suppressed findings (blocked-path proof)
```

### 2.4 Routing & `is_public` derivation

`subnet.is_public` is **true** iff the route table effectively associated with the subnet has a route to an **Internet Gateway** for internet space (`0.0.0.0/0 → igw-…`, or any route covering public space). Classification is **route-table-based, never name/tag-based** (a subnet named "public" with no IGW route is private; a subnet named "private" with an IGW route is public).

- **Effective route table:** explicit `aws_route_table_association` for the subnet, else the VPC **main** route table (`aws_main_route_table_association`). If the main RT cannot be resolved → **`is_public = true`** (conservative).
- `0.0.0.0/0 → nat-…` ⇒ **private** (egress only). `0.0.0.0/0 → igw-…` ⇒ **public**.
- No default route ⇒ **isolated** from the internet (intra-VPC `local` route still applies for in-VPC hops).
- Route target unresolved / interpolation / `(known after apply)` ⇒ **could be IGW ⇒ `is_public = true`.**
- **IPv6:** `::/0 → igw` is treated analogously. **Egress-only IGW provides outbound IPv6 only and creates NO inbound edge.**
- **Default VPC:** if resources sit in a default VPC/subnet (`aws_default_vpc`/`aws_default_subnet`, or `default_for_az`/`is_default`), assume the **full default-VPC internet posture** (IGW present, subnet public, default SG/NACL allow). Do **not** require explicit IGW resources to exist in the plan.
- **Secondary CIDRs:** enumerate all `aws_vpc_ipv4_cidr_block_association` / IPv6 associations; bind subnets to VPC by `vpc_id`, never by CIDR-containment inference.

### 2.5 Security groups (stateful) — exact algorithm

Evaluate **inbound** rules on the destination's SG set only (statefulness guarantees return). A flow `src → dst:P/proto` passes iff the **union** of all SGs attached to `dst` (OR across SGs, OR across rules) contains a matching inbound rule:

```
allowed(dst, src, P, proto):
  for sg in dst.security_groups:           # OR across SGs
    for rule in sg.ingress:                # OR across rules
      if proto_match(rule, proto) and port_in_range(P, rule):
        if rule.cidr_blocks and src_cidr ⊆ rule.cidr: return True
        if rule.ipv6_cidr_blocks and src is v6 and ⊆: return True
        if rule.prefix_list_ids and P matches an entry: return True   # see prefix-list note
        if rule references SG X and src is/behind X:    return True   # SG-to-SG
        if rule.self and src in same SG:                return True
  return False
```

- **SG-to-SG references are first-class graph edges**, resolved by **SG membership**, not CIDR — this is how intra-VPC pivots chain (web→app→db). The internet source can never satisfy an SG-reference rule.
- **Collect rules from all four sources** keyed by SG id: inline `aws_security_group { ingress/egress }`, legacy `aws_security_group_rule`, and current `aws_vpc_security_group_ingress_rule` / `aws_vpc_security_group_egress_rule`. Missing one source = a false negative.
- **Port/proto normalization:** `protocol = "-1"`/`"all"` ⇒ all ports, all protocols. `from_port=0, to_port=0, protocol="-1"` ⇒ full range (the all-traffic idiom, **not** literal port 0). A rule opens a sink iff `from_port ≤ sink_port ≤ to_port` (range containment, not exact-equality).
- **Untrusted source detection is CIDR math**, not string match: `0.0.0.0/1` + `128.0.0.0/1` covers all IPv4; `"0.0.0.0/0 "` with whitespace must normalize. Use `ipaddress` containment against public space.
- **Customer-managed prefix lists:** resolve entries from `aws_ec2_managed_prefix_list`. AWS-managed (opaque) or computed prefix lists ⇒ `POTENTIALLY_REACHABLE` (`UNKNOWN_INPUT`).
- **Conservative defaults:** unresolved SG set / `(known after apply)` rule / unexpandable dynamic block ⇒ assume **ALLOW** for the affected ports, tag `UNKNOWN_INPUT`. Default SG (intra-SG allow-all) modeled as permissive unless explicitly restricted.

### 2.6 NACLs (stateless, ordered) — exact algorithm

For a forward flow `src_cidr → dst:P/proto` crossing into `dst`'s subnet, **two** checks must both pass (statelessness):

**Inbound (on dst subnet's NACL):**
```
for rule in sorted(inbound_rules, by rule_number asc):
    if proto matches and P in rule.port_range and src_cidr ⊆ rule.cidr:
        return rule.action      # ALLOW or DENY — first match wins
return DENY                     # implicit final * deny
```

**Return / outbound (on dst subnet's NACL), on the EPHEMERAL range:**
```
for rule in sorted(outbound_rules, by rule_number asc):
    if proto matches and ephemeral_port ∈ rule.port_range and src_cidr ⊆ rule.dst_cidr:
        return rule.action
return DENY
```

- **Ephemeral range tested = `1024–65535`** (widest superset). The forward path is "reachable" if **any** ephemeral port in this range is allowed out. Never narrow this (narrowing is a false-negative vector).
- Evaluate at **each** subnet boundary a path crosses; intra-subnet flow skips NACL.
- **Conservative defaults:** no NACL resolvable / default NACL / unresolved association ⇒ **ALLOW**. Custom NACL with no rules ⇒ **DENY** — but only if we are sure it is custom; if we can't tell default vs custom → treat as default (ALLOW). Any NACL decision depending on `(known after apply)` ⇒ **ALLOW**, tag `UNKNOWN_INPUT`.
- A NACL is one of the few places we may legitimately downgrade toward `UNREACHABLE` (an explicit, fully-known DENY, or a fully-known absence of the ephemeral return rule) — but **only when the NACL is fully known**.

### 2.7 ALB / NLB

Two segments, both must pass: **INTERNET→LB** and **LB→target**.

**INTERNET → LB:** `scheme == "internet-facing"` AND ≥1 LB subnet `is_public` (an `internal` LB is **not** an internet entry point, but is a valid hop on an internal path).
- **ALB** (always ≥1 SG): passes iff ALB SG allows internet CIDR on a listener port AND a listener exists on that port AND subnet NACL allows.
- **NLB with an SG:** same as ALB.
- **NLB without an SG:** **all client traffic reaches the listeners** — passes for any listener port, gated only by NACL.
- **NLB SG presence unknown** ⇒ assume **no SG ⇒ open**.

**LB → target:**
- **ALB:** target always sees the **ALB**. Target SG must allow the **ALB's SG** (SG-to-SG) or the ALB subnet CIDRs on the tg port. Target-subnet NACL must allow.
- **NLB, `preserve_client_ip` enabled** (default for instance/TCP): target sees the **original client IP** → target SG must allow `0.0.0.0/0` on the tg port **OR** reference the NLB SG **OR** (NLB has no SG and target allows the NLB subnet/private IPs).
- **NLB, `preserve_client_ip` disabled** (or `target_type == "ip"`): target sees NLB private IPs → target SG must allow NLB subnet CIDRs / NLB SG.
- **NLB ephemeral source range = `1024–65535`** (ELB range) for NACL checks on the target subnet.
- `target_type == "alb"` (NLB→ALB chaining): recurse into the ALB. `target_type == "lambda"`: LB→Lambda edge.
- **Health-check note:** NLB SG health checks are subject to *outbound* rules only — irrelevant to ingress; ignore for the forward path (do not let it cause a false negative).
- Unresolved listener/target wiring ⇒ assume the forward edge exists, tag `UNKNOWN_INPUT`.

### 2.8 RDS, ElastiCache, Redshift, OpenSearch

**RDS — two ways to reach, OR them:**
1. **Direct from internet:** `publicly_accessible == true` AND ≥1 DB-subnet-group subnet `is_public` AND a vpc-SG allows internet CIDR on the engine port AND NACL allows. (All three beyond the flag are required — the flag alone is **not** a path.)
2. **Via an in-VPC hop:** `InternetSource → … → Eni → RdsInstance`, where the RDS vpc-SG allows the hop's SG (SG-to-SG) or its private CIDR on the DB port, and NACLs at the RDS subnet boundary allow.

**Engine port defaults** when not explicit: Postgres 5432, MySQL/Aurora-MySQL 3306, SQL Server 1433, Oracle 1521. ElastiCache: Redis 6379, Memcached 11211. If the sink port is unknown ⇒ test **all** ports the relevant SG opens. `publicly_accessible` unknown ⇒ assume `true`. Aurora: evaluate the cluster instances' subnets/SGs; cluster + reader endpoints share the subnet group.

**Redshift:** `publicly_accessible` modeled like RDS. **OpenSearch:** evaluate the domain access policy for anonymous/open access (analogous to S3's policy evaluator). ElastiCache, Redshift, OpenSearch are in the default sink registry; an unknown datastore-shaped type degrades to a `POTENTIALLY_REACHABLE` sink rather than being silently ignored.

### 2.9 S3 (separate non-network evaluator — no VPC edges)

S3 is **not** in the VPC graph; its "reachability" is an IAM/policy class (`ReachabilityClass.IDENTITY`), evaluated by a dedicated predicate. A bucket is **internet-exposed** iff **Block Public Access does not fully block it** AND (a public bucket policy OR a public ACL grants anonymous access):

- **BPA (account + bucket):** flags `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`. Treat BPA as closing the public surface **only when all four flags are explicitly `true` AND known**. Any flag `false`, missing, or computed ⇒ do **not** suppress; evaluate policy/ACL on merits. S3 enforces the **most restrictive** of account- and bucket-level — but **account-level BPA is usually not in the Terraform under analysis**; never assume it exists. (Documented blind spot, §6.)
- **Bucket policy:** a statement with `Effect:Allow`, `Principal:"*"` or `{"AWS":"*"}`, no fixed `aws:SourceIp`/`aws:SourceVpc`/account scoping ⇒ public. A broad `aws:SourceIp` (even `0.0.0.0/1`) is public. A `Condition` restricting to a VPCE or specific narrow IP ⇒ not anonymous-internet-public (flag if broad).
- **ACL:** grant to `AllUsers` **or** `AuthenticatedUsers` group URIs ⇒ public (treat `AuthenticatedUsers` = any AWS account = public). Resolve `aws_s3_bucket_acl` as a separate resource.
- Any field unknown/unresolved ⇒ **assume public**, tag `UNKNOWN_INPUT`.
- **VPC-endpoint-only access** (gateway endpoint + `aws:SourceVpce`) ⇒ reachable only from inside the VPC, **not** the internet → suppress for the internet-source question. An interface/gateway endpoint does **not** make a public bucket private.

> **Honesty caveat baked into copy:** an S3 finding is a **network/policy exposure**, not an IAM-authorization verdict. We model who can *reach* the bucket via anonymous policy/ACL, not identity-based access.

### 2.10 Transitive pivots & pathfinding

**Transitive pivots are why this must be graph search, not per-resource checks.** The headline false negative is "RDS is private, only reachable from a bastion's SG" → a per-resource "is there a *direct* internet→RDS edge?" says no. The real path is `internet → bastion(22) → app(SG-ref) → RDS(SG-ref)`. **Never short-circuit on "no direct edge."**

- **VPC peering:** model `aws_vpc_peering_connection` as an edge **only between the two peered VPCs** (non-transitive) and **only for route-table routes pointing at the peering connection**, plus cross-peering SG references (same region/account).
- **Transit Gateway:** **transitive**, subject to TGW route tables. If TGW route tables aren't fully specified / are computed ⇒ `POTENTIALLY_REACHABLE` (`OUT_OF_MODEL`) for cross-attachment reachability. **Never assume isolation** — under-connecting TGW is a fatal false negative.

**Algorithm (constrained pathfinding, not vanilla shortest path):**
1. **Subgraph filtering** — build a `networkx.subgraph_view` containing only edges whose static constraint could ever admit the internet source (port∩, cidr∩, direction=forward, not SG-ref-from-internet). Polynomial; no path explosion.
2. **Verdict pass** — `nx.has_path(view, INTERNET, sink)` for a fast boolean. Because port-set narrows along the path (port-translation at LB hops), a single edge filter is necessary-but-not-sufficient, so:
3. **Constrained BFS** — custom cycle-safe (visited-set) BFS threading `path_state` (admissible port-set, originating internet CIDR, statefulness ledger) through `edge_admits`, pruning when the port-set goes empty. First success → `REACHABLE`. Exhaustion with **all** branches blocked by *known* constraints → `UNREACHABLE`. Any branch blocked only by an `unknown`/`after_apply`/out-of-model edge → `POTENTIALLY_REACHABLE`.
4. **Explanation pass** — only if reachable/potential: `nx.shortest_simple_paths(view, …)` lazily yields candidates shortest-first; take the first that passes `edge_admits` end-to-end and stop (k-bounded, default k=3 for alternate paths). Lazy generation avoids the `all_simple_paths` O(n!) trap.

**Output per sink:** `REACHABLE` + full hop trace with each hop's allowing rule (the "ONE real path, hop by hop" deliverable); or `UNREACHABLE` + the **blocked** path showing which gate closes it ("here's *why* it's safe"); or `POTENTIALLY_REACHABLE` + the open-but-unknown hop and its reason class.

**Suppression report:** map each scanner finding to a node/edge. If the node is on no reachable/potential path → mark **suppressed (unreachable)** **with the blocked-path proof** (e.g., "subnet private, no `0.0.0.0/0→igw` route" or "no SG ingress from any internet-reachable hop"). A suppression always carries proof so the skeptic reads *why*, not "trust us."

### 2.11 Data-egress / exfil (secondary, distinct finding class)

NAT GW and egress-only IGW close inbound but leave **outbound** open. Model two reachability questions: (a) inbound `internet→sink` (the pitch), and (b) data-egress `sink/processor→internet`. EIGW closes (a) for IPv6 but leaves (b) open. Surface exfil edges as a **distinct finding**, never silently drop them. NAT GW is **never** an inbound edge but **does** enable egress from private subnets.

---

## 3. Input handling

### 3.1 Source-of-truth tiering

| Source | Command | Gives | Trust tier |
|---|---|---|---|
| **Plan JSON** | `terraform show -json plan.out` | `planned_values` (resolved) + `resource_changes` (`after`/`after_unknown`) + `configuration` (raw expressions/references) | **PRIMARY** |
| **State JSON** | `terraform show -json` / raw `.tfstate` | fully-resolved attributes for *applied* infra; no `after_unknown` | **Secondary** (the past, not the change) |
| **Raw HCL** | `python-hcl2` | literal source; `count`/`for_each`/`dynamic` **unexpanded**, vars/locals **unevaluated** | **Degraded / best-effort** |

**Why plan JSON is primary:** it is the only artifact carrying *both* resolved values *and* a machine-readable marker of what is not-yet-known (`after_unknown`). Distinguishing "concrete and provably closed" from "unknown" is the entire job. Plan JSON also pre-expands `count`/`for_each`/`dynamic` and flattens modules. Pin and check `format_version`.

**State and HCL are fallbacks, not equals.** State is concrete but describes applied reality (the promise is pre-apply); use it to augment a plan and for demo fixtures of existing infra. **HCL is honestly labeled "degraded / maximally conservative"**: it is parsed, not evaluated, so it marks almost everything `UNKNOWN_INPUT` and over-reports. We never pretend HCL gives plan-equivalent fidelity — that would manufacture false negatives.

**Multiple inputs → UNION of edges (most permissive), never intersection.** Plan/state edges (higher confidence) outrank HCL. Report which source each edge came from (provenance).

### 3.2 Walking the plan JSON (exact paths)

- **`planned_values.root_module.resources[]`** + recursive `child_modules[]` — the resolved value tree. Each resource: `address` (canonical node key, fully module-qualified + indexed), `mode`, `type`, `name`, `index`, `values`. Walk recursively; use `address` as-is.
- **`resource_changes[]`** — flat array (module path in `module_address`+`address`). Join to `planned_values` on `address`. `change.actions`: `["delete"]` ⇒ exclude from post-apply graph; `create`/`update`/`no-op`/replace ⇒ include, read `after`/`after_unknown` (never `before`).
- **`configuration.root_module.resources[].expressions`** — the topology/reference oracle. `{ "constant_value": … }` for literals; `{ "references": [...] }` for symbolic refs. **Config addresses are un-indexed** (`aws_instance.web`, not `aws_instance.web[0]`).

### 3.3 `after_unknown` — the conservative linchpin

`after_unknown` mirrors the shape of `after`, with `true` at any leaf "known after apply"; known leaves are **omitted** (not `false`). A dedicated, fuzz-tested helper:

```python
def is_unknown(after_unknown, path: tuple) -> bool:
    """path e.g. ("vpc_security_group_ids",) or ("ingress", 1, "cidr_blocks").
    Returns True if the value at path is computed/known-after-apply, OR any descendant is."""
    node = after_unknown
    for key in path:
        if node is True:                      # ancestor entirely unknown
            return True
        if isinstance(node, dict):
            if key not in node:               # omitted == known
                return False
            node = node[key]
        elif isinstance(node, list):
            if not isinstance(key, int) or key >= len(node):
                return False
            node = node[key]
        else:
            return False
    return node is True or _contains_unknown(node)   # leaf unknown, or any descendant unknown
```

Asking about a whole list (`vpc_security_group_ids`) when only element `[1]` is unknown must report **UNKNOWN** for membership purposes (conservative) — hence `_contains_unknown` recursing on descendants. This is the single most important extractor function; unit/fuzz-test it on scalar, nested-block, list-of-objects, and whole-list-unknown cases.

### 3.4 Reference-based resolution (not value-based)

At plan time, a security group's `id` is almost always `(known after apply)`, so `vpc_security_group_ids` in `planned_values` is `[null]` — you **cannot** match SGs to a DB by id value. A value-only tool sees `[null]` and (fatally) decides "no path." probepath resolves topology from **`configuration.references`**:

1. Build **nodes** from `planned_values` (∪ state) — every post-apply resource instance, keyed by `address`.
2. Build **edges from `configuration.references`.** When `aws_db_instance.main`'s config has `vpc_security_group_ids = [aws_security_group.db.id]`, the `references` array contains `"aws_security_group.db"` (multi-step refs are unwrapped + duplicated; take the longest entry resolving to a resource address, strip `.id`/`.arn`). That symbolic reference *is* the edge — it survives unknown ids.
3. **Fan out** config-level (un-indexed) edges across expanded instances. When per-index wiring isn't determinable (the common case), **conservatively connect all source instances to all target instances**. Over-connecting is safe; under-connecting risks a false negative.
4. **Concrete values** (hardcoded CIDR, explicit port) read from `planned_values`/`after` give edge *constraints*.
5. **Value-based ID matching is a fallback** used only for state-only input (real `sg-…` ids, no config).

### 3.5 Hard Terraform features

- **`count`/`for_each`:** plan/state already expanded (each instance has `index`) — the killer argument for plan JSON. HCL: unexpanded → single representative node flagged `EXPANSION_UNKNOWN`, over-connect refs. Never assume `count=0`/empty unless the value is known and literally empty.
- **Modules:** plan/state flatten into `child_modules` / `module_address`-prefixed `address`; module boundaries don't matter for the graph. Resolve cross-module refs (`module.net.sg_id`) by chaining through module **output expressions** to the real resource. HCL cross-module edges that can't be resolved ⇒ refuse `UNREACHABLE`, degrade to `POTENTIALLY_REACHABLE`.
- **`dynamic` blocks:** plan/state already materialized into concrete repeated blocks. HCL: a template, not rules → treat the SG as `UNKNOWN_INPUT` ingress unless every `content` field is a literal.
- **Default VPC / SG:** `data.aws_vpc {default=true}` and `aws_default_*` adopt existing defaults; the AWS default SG allows all intra-SG traffic. Unknown id / data-source ⇒ assume reachable. `aws_default_security_group` **removes all rules then applies only what's specified** — read its rules like any SG.
- **Data sources** (`mode:"data"`): include as nodes so refs resolve; attributes very often `(known after apply)` → liberal `UNKNOWN_INPUT` tagging.
- **External/cross-account/remote-state refs** (`terraform_remote_state`, hardcoded `sg-xxxx` not in plan, ARN in a different account) ⇒ **placeholder node, edges `POTENTIALLY_REACHABLE`**, never a missing edge.

### 3.6 The extractor contract

Each attribute resolves to exactly one of three states feeding the conservative rule — **there is no fourth "default to safe" state:**

| State | When | Pathfinder treatment |
|---|---|---|
| **KNOWN(value)** | present in `planned_values`/`after` AND `is_unknown()` is `False` | hard constraint from the real value |
| **UNKNOWN** | `is_unknown()` True; OR `null` with no resolvable ref; OR HCL-only; OR ref to an unmodeled target; OR undeterminable expansion; OR `format_version` newer than tested | constraint **satisfiable** → edge traversable → caps path at `POTENTIALLY_REACHABLE` |
| **ABSENT** | attribute legitimately unset with a known AWS default | apply the **conservative** AWS default |

> The extractor's contract (state it in the README and the module docstring): **it never returns "this attribute is restrictive" without positive, concrete evidence. Absence of evidence is `UNKNOWN`, and `UNKNOWN` always widens reachability.** Parse failures and unevaluated HCL functions (`cidrsubnet`, `merge`, `coalesce`) on gating attributes ⇒ `UNKNOWN`, **fail loud**, never silently closed. Track parser coverage as a first-class metric.

---

## 4. Package architecture

### 4.1 Layout (src layout, layering enforced by `import-linter`)

```
probepath/
├── pyproject.toml                # hatchling; console_scripts entrypoint
├── README.md  LICENSE  action.yml  DESIGN.md
├── src/probepath/
│   ├── __init__.py               # __version__
│   ├── cli.py                    # Typer app: scan / explain / graph-export / validate-config
│   ├── config.py                 # ProbepathConfig (.probepath.yml) load/merge/validate
│   ├── errors.py                 # typed exceptions (IngestError, AmbiguousInputError…)
│   │
│   ├── ingest/                   # Terraform → normalized resources (NO graph logic)
│   │   ├── __init__.py           # detect_format() + ingest() dispatch
│   │   ├── plan.py               # plan JSON: join planned_values ⋈ resource_changes ⋈ configuration
│   │   ├── state.py              # .tfstate parser
│   │   ├── hcl.py                # raw HCL (python-hcl2) — degraded, most "unknown"
│   │   ├── unknown.py            # is_unknown() + provenance/Confidence tracking
│   │   └── normalized.py         # ResourceRecord canonical intermediate form
│   │
│   ├── model/                    # typed data model (pure, no networkx)
│   │   ├── nodes.py edges.py ports.py cidr.py
│   │   └── graph.py              # ResourceGraph: MultiDiGraph wrapper + typed accessors
│   │
│   ├── aws/                      # AWS semantics, isolated + auditable
│   │   ├── resource_types.py     # tf type → Node class + sink-default flags
│   │   ├── sg_rules.py           # SG ingress/egress → edges (stateful, all 4 rule sources)
│   │   ├── nacl_rules.py         # NACL → edges (stateless, bidirectional ephemeral check)
│   │   ├── routing.py            # route tables, igw, nat, endpoints → routing edges + is_public
│   │   ├── elb.py                # ALB/NLB/CLB → relay nodes + target-group edges
│   │   └── sinks.py              # default sink catalog (rds, elasticache, redshift, opensearch, s3)
│   │
│   ├── engine/                   # graph build + reachability (the real algorithm)
│   │   ├── builder.py            # GraphBuilder: normalized resources → ResourceGraph
│   │   ├── source.py             # InternetSource injection
│   │   ├── reachability.py       # ReachabilityEngine: subgraph filter → has_path → constrained BFS → explain
│   │   ├── constraints.py        # edge_admits(): port∩, cidr∩, direction, statefulness, unknown→cap
│   │   ├── explain.py            # Path → HopExplanation list
│   │   └── verdict.py            # Verdict + ConservativeReason enums; suppression logic
│   │
│   ├── findings/
│   │   ├── finding.py            # Finding, Verdict, Suppression, ScannerFinding adapters
│   │   ├── correlate.py          # join external scanner findings ↔ probepath verdicts
│   │   └── diff.py               # base-vs-head NEW-path detection (the Action gate)
│   │
│   ├── report/                   # pure renderers (Findings → bytes/str)
│   │   ├── human.py json_report.py sarif.py mermaid.py
│   │   └── svg.py                # optional [viz] extra (pydot/graphviz)
│   │
│   └── adapters/                 # ingest OTHER scanners (stdlib JSON/SARIF)
│       ├── trivy.py checkov.py
│
├── tests/ { unit/  golden/  fixtures/  properties/ }
└── docs/ { MODEL.md  semantics.md  threat-model.md }
```

**Layering rule (CI-enforced):** `ingest → model → aws → engine → findings → report`. `report` may not import `engine` internals; `aws` may not import `engine`. A security reviewer can validate correctness by reading `aws/` and `engine/constraints.py` and nothing else.

### 4.2 Core classes

```python
class Confidence(Enum):
    KNOWN = "known"; AFTER_APPLY = "after_apply"; PARSED_HCL = "parsed_hcl"
    DEFAULT = "default"; MISSING = "missing"

class Verdict(Enum):
    REACHABLE; POTENTIALLY_REACHABLE; UNREACHABLE

class ConservativeReason(Enum):           # why POTENTIALLY_REACHABLE
    AFTER_APPLY_VALUE; MISSING_RESOURCE; UNPARSEABLE_HCL
    UNSUPPORTED_RESOURCE_TYPE; NACL_RETURN_UNKNOWN
    # rolled up to user-facing UNKNOWN_INPUT | OUT_OF_MODEL

@dataclass(frozen=True)
class SourceLocation: file: str|None; line: int|None; tf_address: str

@dataclass(frozen=True)
class Node: id: str; kind: NodeKind; location: SourceLocation; confidence: Confidence; raw: Mapping

@dataclass(frozen=True)
class EdgeConstraint:
    ports: PortSet; source_cidrs: CidrSet|None; source_sg: str|None
    stateful: bool; direction: Direction               # FORWARD | RETURN

@dataclass(frozen=True)
class Edge:
    src: str; dst: str; kind: EdgeKind; constraint: EdgeConstraint
    rationale: str; location: SourceLocation; confidence: Confidence  # min() of inputs

@dataclass(frozen=True)
class HopExplanation:
    index: int; from_node: str; to_node: str; edge_kind: EdgeKind
    why: str; location: SourceLocation; confidence: Confidence

@dataclass(frozen=True)
class Finding:
    rule_id: str                          # stable for SARIF, e.g. "probepath/internet-to-rds"
    sink: SinkRef; verdict: Verdict; reachability_class: ReachabilityClass  # NETWORK | IDENTITY
    path: list[HopExplanation]            # [] when unreachable
    blocked_reason: str|None              # which hop blocks & why (the suppression proof)
    conservative_reasons: list[ConservativeReason]
    fingerprint: str                      # sha256(sink.address + path-signature) — SARIF dedupe
    correlates: list[ScannerFindingRef]
```

**Port/CIDR algebra** (`ports.py`/`cidr.py`): interval-set wrappers (`portion` for ports, stdlib `ipaddress` for CIDRs) with `intersect`/`contains`/`is_empty`. A path is viable iff the intersection of all edge port-sets is non-empty AND each edge admits the source CIDR. `ALL_PORTS`, `EPHEMERAL = 1024–65535` are constants. This is the most heavily unit-tested module.

### 4.3 CLI (Typer)

```
probepath scan    [INPUT...] [--config .probepath.yml] [--format human|json|sarif]
                  [--fail-on reachable|potential|never] [--correlate trivy.sarif]
                  [--baseline base.json] [-o OUT]
probepath explain SINK_ADDRESS [INPUT...] [--format human|mermaid|svg|json] [--all-paths] [--max-paths K]
probepath graph-export [INPUT...] [--format mermaid|svg|dot|graphml] [-o OUT]
probepath validate-config [--config .probepath.yml]
probepath verify-against-aws ...        # opt-in oracle harness (§6.4); excluded from CI
```

- **`scan`** — primary CI/PR command. Exit codes: `0` clean, `1` policy violation (per `--fail-on`), `2` usage/ingest error. `--baseline` enables NEW-path diffing.
- **`explain`** — deep-dive one sink; renders hop-by-hop including the **blocked** path when unreachable (the demo money-shot, "here's why we say it's safe").
- Input auto-detection: `*.tfplan.json`/`terraform show -json` shape → plan; `*.tfstate` → state; `*.tf` → HCL. Multiple inputs merge (union of edges; resolved sources outrank HCL).

### 4.4 Output formats

- **human** (`rich`): summary panel (`N findings: X reachable, Y potential, Z suppressed`), per-sink hop tree with color (red=reachable, yellow=potential, green=suppressed) and `file:line` per hop.
- **json**: canonical, versioned (`"schema": "probepath/v1"`) `Finding` list. The stable machine contract + baseline-diff artifact.
- **sarif**: SARIF 2.1.0. `tool.driver.rules[]` = probepath rule catalog (one stable `id` per sink class). Each reachable/potential finding → a `result` with `ruleId`, `level` (`error` for REACHABLE, `warning` for POTENTIAL), `partialFingerprints.probepathPathHash = Finding.fingerprint`, `locations[]` at the sink's HCL `file:line`, and **`codeFlows[]` encoding the hop-by-hop path as a SARIF threadFlow** (each hop = a `threadFlowLocation` — exactly what GitHub's code-flow UI visualizes). Unreachable findings are **not** results (suppression = absence) but are recorded in `runs[].properties.suppressions` for audit. Fingerprints are stable across runs (stable `ruleId` + sink path), satisfying GitHub's dedupe requirement.
- **mermaid**: `flowchart LR` of the path (internet + sink red, hops labeled with port/rule), README-embeddable.
- **svg**: optional `[viz]` extra via `pydot`+graphviz, for `graph-export` and portfolio screenshots.

### 4.5 GitHub Action (`action.yml`) — the NEW-path gate

Composite action, pinned, offline. Steps: `pipx install probepath==<pin>` → `probepath scan --format sarif -o probepath.sarif --baseline … --fail-on …` → `github/codeql-action/upload-sarif@v3` → `probepath scan --format json` for the PR-comment body.

**The killer feature (`findings/diff.py`):** on a PR, run probepath against **base ref** and **head**, key by `Finding.fingerprint`, compute `{added_reachable, added_potential, resolved, unchanged}`, and **fail the check only if the PR introduces a NEW reachable (or potential, if `fail-on: potential`) internet→sink path.** Pre-existing paths are surfaced but don't block (adoptable on a messy repo). This gates on the **delta**, mirroring deploy-gating best practice. Baseline strategy: prefer regenerating from base ref; fall back to a committed `.probepath-baseline.json` for repos that can't `terraform plan` in CI.

### 4.6 Config (`.probepath.yml`, validated by hand-rolled dataclass validator)

```yaml
version: 1
sinks:
  defaults: true                       # built-in catalog (aws/sinks.py)
  include:
    - type: aws_db_instance
    - type: aws_elasticache_replication_group
    - tag: { Sensitivity: pii }
    - name_regex: "(?i)secrets?|vault"
    - s3: { when: { sensitive_tag: "data-classification=restricted" } }
  exclude:
    - name: aws_db_instance.scratch_dev
sources:
  internet_cidrs: ["0.0.0.0/0", "::/0"] # what counts as untrusted (CIDR-math, split-range aware)
policy:
  fail_on: reachable                    # reachable | potential | never
  treat_unknown_as: reachable           # principle #1; flipping prints a LOUD warning (only way to add FN risk)
  max_explanation_paths: 3
```

Built-in sink defaults: RDS (`aws_db_instance`, `aws_rds_cluster`), ElastiCache, Redshift, DocumentDB, OpenSearch, S3 with a sensitivity tag or an anonymous-allowing policy, Secrets Manager / SSM SecureString in-VPC.

---

## 5. Fixture matrix

Each fixture is a committed directory: raw HCL **and** `terraform show -json` plan output **and** `expected.yaml`. `expected.yaml` pins top-level verdict, exact hop sequence (positive), blocking hop + reason (negative), the `POTENTIALLY_REACHABLE` reason code, and a one-line `rationale` citing the AWS semantic exercised. Golden tests assert byte-exact on verdict **and** hop trace **and** reason code — a regression in *why* is still a regression. A `Makefile`/`tofu` target regenerates JSON deterministically (Terraform/OpenTofu version pinned per fixture dir). `--update-golden` exists but is never run in CI.

### 5.1 Positive — must yield `REACHABLE` (never suppressed)

| ID | Scenario | Proves |
|---|---|---|
| `P01_textbook_public_rds` | IGW → public-subnet route → EC2 SG `0.0.0.0/0:5432` → RDS SG allows EC2's SG:5432 | the canonical "ONE real path" demo |
| `P02_directly_public_rds` | `publicly_accessible=true`, IGW route, SG `0.0.0.0/0:5432` | directly-exposed DB; the most damning finding |
| `P03_alb_to_rds` | internet-facing ALB(SG `0.0.0.0/0:443`) → tg → EC2 → RDS SG refs ALB/EC2 SG | multi-hop through a LB relay |
| `P04_sg_chain_3_hops` (a.k.a. `trap_D1_bastion_pivot`) | IGW → bastion(`0.0.0.0/0:22`) → app(SG-ref) → ElastiCache(SG-ref:6379) | SG-to-SG transitivity over 3 hops — **the headline pivot** |
| `trap_A1_sg_to_sg_chain` | internet→ALB-SG→app-SG→RDS via `source_security_group_id` only, zero CIDRs on RDS SG | SG-ref edges resolved by membership, not CIDR |
| `trap_D2b_nlb_no_sg` | internet-facing NLB (no SG) → target SG allows client CIDR; NACL checked with `1024–65535` | SG-less NLB = all traffic reaches listeners |
| `P05_wide_cidr_not_quad_zero` / `trap_T09` | ingress `0.0.0.0/1`+`128.0.0.0/1` (or `"0.0.0.0/0 "`) | untrusted detection is CIDR math + normalization, not string-match |
| `trap_A4_prefix_list` | SG ingress via customer-managed prefix list containing `0.0.0.0/0` | resolve managed prefix-list entries |
| `trap_A5_all_protocol_minus1` | opening as `protocol="-1", from_port=0, to_port=0` | `-1` = all ports/protocols, not port 0 |
| `trap_A6_ipv6_open` | sink reachable only via `ipv6_cidr_blocks=["::/0"]` | IPv6 untrusted source (exceeds RA) |
| `trap_G2_port_range_contains` | SG rule `5000–6000` containing custom RDS port 5500 | range containment, not exact match |
| `P07_nacl_allows_ephemeral` (`trap_B1_nacl_return_open`) | restrictive NACL that allows ephemeral `1024–65535` out | NACL statelessness handled in the allow direction |
| `trap_D3_tgw_transitive` | internet→VPC-A→TGW→VPC-C-sink | TGW is transitive — must not under-connect |
| `trap_D3b_peering_sg_ref` | cross-VPC SG ref over a peering connection with matching route | peering SG references |
| `trap_D4_lambda_url_to_rds` | public Lambda Function URL (`auth=NONE`) → VPC Lambda → RDS | public Lambda entry + VPC egress to sink |
| `trap_E1_s3_public_policy` | `acl=private` but bucket policy `Principal:"*"` GetObject | S3 public via policy not ACL |
| `trap_E3_s3_authenticated_users_acl` | ACL grant to `AuthenticatedUsers` | AuthenticatedUsers = public |
| `trap_E4_opensearch_open_policy` | OpenSearch open access policy / Redshift `publicly_accessible=true` | sink registry beyond RDS+S3 |
| `T03_module_passthrough_var` | untrusted CIDR via a module var two levels deep, resolved in plan JSON | why plan JSON beats HCL-only |
| `trap_X_secondary_cidr_subnet` | sink in a subnet from a secondary VPC CIDR association | bind by `vpc_id`, not CIDR inference |

### 5.2 Negative — must yield `UNREACHABLE` (the suppressions; the whole value)

| ID | Scenario | Proves |
|---|---|---|
| `N01_no_igw_route` (`trap_TN_private_rds_no_path`) | RDS SG open to `0.0.0.0/0:5432` but **no `0.0.0.0/0→igw` route** | the flagship suppression: routing, not just SG |
| `N02_sg_open_nacl_denies` / `T08_overlapping_deny_allow_nacl` | SG open, NACL rule 90 DENY 5432 < rule 100 ALLOW 5432 | NACL lowest-number-first ordering (defends against over-reporting) |
| `N03_nacl_no_return_path` | inbound NACL allows service port, outbound does **not** allow ephemeral | NACL statelessness in the blocking direction |
| `N04_sg_ref_unrelated` | RDS SG references a *different* SG than the internet-facing host's | SG refs followed by id, not assumed |
| `N05_wrong_port` | path open on 443, sink on 5432, no rule covers 5432 | empty port-set intersection blocks |
| `N06_egress_only_no_ingress` | SG has egress `0.0.0.0/0` but no matching ingress | egress-open ≠ ingress-open |
| `N07_isolated_vpc` | sink in VPC-B, host in VPC-A, no peering/TGW | no connector ⇒ unreachable |
| `unreachable_internal_alb` | `internal`-scheme ALB | internal LB is not an internet entry point |
| `trap_TN_s3_all_bpa_true` | all four BPA flags explicitly `true`, no public policy | BPA closes only when fully-known-true |
| `trap_TN_eigw_inbound_closed` | IPv6 egress-only IGW: inbound UNREACHABLE + a paired egress-exfil finding | EIGW closes inbound, leaks egress |

### 5.3 Conservative traps — must yield `POTENTIALLY_REACHABLE` (NOT `UNREACHABLE`)

| ID | Trap | Naive (wrong) | Correct | Reason |
|---|---|---|---|---|
| `T01_unknown_cidr_var` / `trap_F1_computed_cidr` | `cidr_blocks=[var.x]` unset → `after_unknown` | UNREACHABLE | POTENTIAL | `UNKNOWN_INPUT` |
| `trap_F1b_computed_publicly_accessible` | RDS `publicly_accessible` unknown | UNREACHABLE | POTENTIAL | `UNKNOWN_INPUT` |
| `T02`/`trap_F2_count_unknown_cidrs` | `for_each` over a variable CIDR set | UNREACHABLE | POTENTIAL | undeterminable cardinality |
| `trap_F3_cross_module_ref` | sink in `module.data`, SG in `module.net`, HCL input | UNREACHABLE | POTENTIAL | unresolved cross-module HCL edge |
| `trap_F5_remote_state_sg` | SG from `terraform_remote_state` (not in plan) | UNREACHABLE | POTENTIAL | placeholder node |
| `trap_F5b_cross_account_arn` | referenced ARN in a different account | UNREACHABLE | POTENTIAL | unproven cross-account trust |
| `trap_E2_partial_bpa` | `block_public_policy=false`, rest true, public-ish policy | suppressed | POTENTIAL | partial BPA never suppresses |
| `T04_default_nacl_implicit` | subnet, no explicit NACL → default NACL allow-all | UNREACHABLE | REACHABLE | model AWS defaults |
| `T05_self_referencing_sg_loop` | SG-A↔SG-B cycle on the path | hang/crash/UNREACHABLE | terminate + correct | cycle-safe traversal |
| `trap_F6_unparseable_function` | `cidr_blocks=[cidrsubnet(var.x,8,0)]` | UNREACHABLE | POTENTIAL | unevaluated function |
| `T07_appliance_in_path` | firewall EC2 (`source_dest_check=false`) in route | UNREACHABLE | POTENTIAL | `OUT_OF_MODEL` |
| `trap_T06_prefix_list_managed` | source is a managed prefix list with entries not in plan | UNREACHABLE | POTENTIAL | `UNKNOWN_INPUT` |

### 5.4 Demo & adversarial-combination fixtures

- `trap_TN_scanner_noise_47` / `multi_finding_47` — a realistic stack with ~47 scanner-flaggable misconfigs where only **one** is internet→RDS reachable; golden = 1 reachable, 46 suppressed; ships a committed **Trivy SARIF** to correlate against. **This is the fixture that proves the pitch — wire it into the README/GIF.**
- `trap_X_alb_to_lambda_to_s3` — internet ALB → Lambda target → writes to public-via-policy S3 (cross-surface: NETWORK path to the proxy + IDENTITY exposure of the bucket).

> **Provenance:** §5.1–5.3 merge Pass 2's trap catalog with Pass 5's P/N/T matrix; overlapping fixtures are unified under one ID with the alias noted. Pass 5's `T08` is the deliberate counterweight — every other trap pushes toward conservatism; `T08` ensures we don't get lazy and call *everything* reachable (which would suppress nothing and make the product worthless). Correctness is two-sided; only the *consequences* are asymmetric.

---

## 6. Validation & defensibility

### 6.1 Golden tests (deterministic fixture matrix)

`pytest` over §5 fixtures, byte-exact on verdict + hop trace + reason code; blocks merge. A regression flipping a control (e.g. `N01`) to REACHABLE is a noise regression; a regression flipping any reachable trap to UNREACHABLE is a **release-blocking** false negative and fails CI hard. A CI job regenerates fixture JSON with the pinned Terraform/OpenTofu version and diffs (catches upstream schema drift).

### 6.2 Property-based tests (Hypothesis) — the false-negative hunt

A `@composite` strategy emits valid-ish plan JSON (subnets, RTs, SGs, NACLs, sinks, connectors). Invariants, in priority order:

1. **MASTER — Conservatism / soundness (monotonicity).** Verdict lattice `UNREACHABLE < POTENTIALLY_REACHABLE < REACHABLE`. Generate a topology, then a strictly more-permissive mutation (add allow, widen CIDR, add IGW route, add peering); assert the verdict never moves *down* the lattice. A violation is the highest-severity bug class. Use a `RuleBasedStateMachine` so Hypothesis shrinks to minimal counterexamples. Tagged `@pytest.mark.critical`; failure is release-blocking.
2. **Unknown-propagation.** Take a `REACHABLE`/`UNREACHABLE` result, replace any single input on the deciding path with `after_unknown=true`; assert the verdict becomes `POTENTIALLY_REACHABLE` (never stays `UNREACHABLE` if the unknown was on the blocking hop).
3. **Determinism/idempotence.** Same input (and shuffled resource order) ⇒ identical verdict + hop trace.
4. **No-untrusted-source ⇒ never REACHABLE.** All ingress CIDRs RFC1918, no public-covering range ⇒ never `REACHABLE`.
5. **Disconnected graph ⇒ never REACHABLE.**
6. **Termination** on any graph including cycles (Hypothesis `deadline` + visited-set assertion).
7. **CIDR-algebra correctness** — `is_untrusted(c)` iff `c` intersects public space, split-range aware, cross-checked against `ipaddress` as oracle.

The `.hypothesis/` example DB is CI-cached so counterexamples persist; any found counterexample graduates into §5 as a named fixture.

### 6.3 Model coverage matrix — publish verbatim in `docs/MODEL.md`

Three columns mapping every element to a test ID: **Modeled precisely** (§2.5–2.10), **Conservatively over-approximated** (§1.2 right column, → `POTENTIALLY_REACHABLE`), **Explicitly out of scope** (application auth, host firewalls, target health, DNS, traffic mirroring, BYOIP advertisement, runtime drift, SCPs, NAT packet transforms). A **meta-test** asserts every row maps to ≥1 fixture or property-test ID — keeps the published matrix honest. Also document **where we differ from AWS Reachability Analyzer**: we run pre-apply on config (RA needs deployed resources — our reason to exist); we model IPv6 (RA is IPv4-only); we treat Network Firewall as over-approximated (RA models its 5-tuple rules).

### 6.4 Opt-in oracle harness (`probepath verify-against-aws`)

**We ship the code; we never run it; we never quote its results as ours.** It lets a user with an account independently confirm verdicts. It enumerates probepath's `(source, sink, port, proto)` candidates and creates `AWS::EC2::NetworkInsightsPath` + `start-network-insights-analysis` (the public RA API), mapping `0.0.0.0/0` → an internet-gateway source, then emits a confusion table. Honest interpretation baked in:
- probepath `POTENTIALLY_REACHABLE` vs RA `UNREACHABLE` = **`CONSERVATIVE_OK`**, not a mismatch.
- The **only** true alarm = probepath `UNREACHABLE` while RA says reachable (the fatal class) → harness exits non-zero.
- IPv6-only paths → `NOT_COMPARABLE` (RA can't see them). Prints AWS cost/quota warnings.
- Excluded from CI (no creds) but smoke-tested with `moto`-mocked `boto3` so the code path doesn't rot.

### 6.5 Defensible claims vs forbidden claims

**CAN say:** "statically determines whether a network path from an untrusted source to a sensitive sink is possible under AWS's documented VPC routing/filtering semantics, before `terraform apply`"; "models the same network-admission layer as AWS VPC Reachability Analyzer, but on the plan, pre-deployment"; "**by design, never suppresses a finding when any input on the path is unknown**" (point to the conservatism property test); "deterministic and fully offline — no account, no keys, no network calls"; "*N* named scenarios incl. positive paths, decoy non-paths, and adversarial false-negative traps, all with locked verdicts" (state the **actual** count from the repo); "every UNREACHABLE names the blocking hop; every REACHABLE renders the full path."

**MUST NOT say:** ❌ any accuracy percentage (no labeled ground-truth corpus); ❌ "validated against AWS"/"matches RA" as our own result; ❌ "proves your database is secure" (we prove network unreachability, not security); ❌ "zero false negatives" as an absolute (say "conservative by design to avoid false negatives"); ❌ "detects all attack paths"; ❌ any runtime/live-behavior claim; ❌ accuracy comparisons to commercial scanners (say "complements scanners by adding reachability context").

### 6.6 README "Honest limitations" (drop-in)

> probepath is a **reachability reasoner, not a security oracle.** It decides whether a *network path* from an untrusted source to a sensitive sink is possible under AWS's documented VPC semantics — SGs, NACLs, route tables, gateways — on your Terraform *before* you apply. It does **not** send packets or analyze the data plane.
>
> **`UNREACHABLE` is the only verdict that hides a finding, and we are deliberately stingy with it.** If any input on a path is unknown (unresolved variable, uncomputable `count`, unseen managed prefix list, third-party appliance), we return `POTENTIALLY_REACHABLE` and keep the finding visible. A wrongly-suppressed real path is the one failure we treat as fatal; our property-based tests exist to hunt it.
>
> **Not modeled (never counts toward UNREACHABLE):** application-layer auth (DB passwords, IAM DB auth, S3 *authorization* policies, TLS/mTLS); host firewalls, service health, listening processes; DNS, traffic mirroring, BYOIP advertisement state; AWS Network Firewall / GWLB inspection and third-party appliances (→ POTENTIALLY_REACHABLE); full TGW route-table propagation; anything changed outside Terraform after apply. **Documented blind spot:** account-level S3 BPA is usually not in the Terraform; we never assume it exists.
>
> **Sinks are configurable but finite:** out of the box, RDS, Aurora, ElastiCache, Redshift, OpenSearch, and S3-flagged-sensitive.
>
> **We have not validated probepath against a live AWS account ourselves**, on principle (offline + reproducible). We ship `verify-against-aws`, an opt-in harness that cross-checks verdicts against AWS VPC Reachability Analyzer **in your own account**. We publish **no accuracy percentage** — we have no large labeled corpus to honestly back one.

`docs/semantics.md` reproduces §2.1 with citations (the public defense doc); `docs/threat-model.md` states the §1.2 boundaries.

---

## 7. Dependencies (lean, audited surface)

**Runtime core (5):**
- `networkx` — graph + constrained pathfinding (pure-Python, no native build).
- `typer` (pulls `click`) — typed CLI + auto `--help`.
- `rich` — human output.
- `python-hcl2` — raw HCL parsing (HCL path only; pure-parse, no evaluation).
- `portion` — interval algebra for port sets (tiny, pure-Python).

Stdlib does the rest: `ipaddress` (CIDR), `json` (plan/state/SARIF), `dataclasses`, `hashlib` (fingerprints), `pathlib`.

**Optional extras (not default):** `[viz]` → `pydot` (+ system graphviz) for SVG. `[adapters]` → nothing extra (Trivy/Checkov output is JSON/SARIF, parsed with stdlib).

**Deliberately excluded:** no `boto3`/AWS SDK (offline guarantee), no `requests`/`httpx` (no network egress — itself a selling point for a security tool), no `pydantic` (config validated with hand-rolled dataclass logic to keep the surface to 5). Every dep is pure-Python or ships wheels, so `pipx install probepath` is fast and the supply chain is small and auditable — exactly what a PCI-background reviewer wants.

**Dev deps:** `pytest`, `hypothesis`, `pytest-snapshot` (golden SARIF/JSON), `import-linter` (layering), `ruff`, `mypy --strict`, `moto` (mock the oracle harness's `boto3`).

---

## 8. Sources

AWS networking & semantics:
- [Compare security groups and network ACLs / NACL statelessness, ordering, first-match](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
- [Network ACL rules (rule numbers, allow/deny, port ranges)](https://docs.aws.amazon.com/vpc/latest/userguide/nacl-rules.html)
- [Ephemeral ports (per-OS / ELB 1024–65535)](https://docs.aws.amazon.com/vpc/latest/userguide/nacl-ephemeral-ports.html)
- [Security group rules (SG-as-source semantics)](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
- [SG/NACL inbound return traffic (statefulness)](https://repost.aws/knowledge-center/resolve-connection-sg-acl-inbound)
- [NLB security groups (SG only at creation; SG-less NLB; target SG referencing NLB SG)](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-security-groups.html)
- [NLB target groups / client IP preservation](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html)
- [ALB security groups (internet-facing vs internal)](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html)
- [RDS DB instance in a VPC (publicly_accessible requires public subnet + IGW)](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html)
- [AWS Config rds-instance-public-access-check / rds-instance-subnet-igw-check](https://docs.aws.amazon.com/config/latest/developerguide/rds-instance-public-access-check.html)
- [Route tables](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html)
- [Transit Gateway (transitive routing)](https://docs.aws.amazon.com/vpc/latest/tgw/how-transit-gateways-work.html)
- [VPC peering — referencing peer security groups](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-security-groups.html)
- [S3 Blocking public access / public determination](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)

Terraform:
- [JSON Output Format (planned_values, resource_changes, after_unknown, configuration/references)](https://developer.hashicorp.com/terraform/internals/json-format)
- [aws_vpc_security_group_ingress_rule](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule)
- [aws_default_security_group](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_security_group)
- [Managing AWS Security Groups through Terraform — Spacelift](https://spacelift.io/blog/terraform-security-group)

Tooling & validation:
- [GitHub SARIF support for code scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
- [networkx simple_paths](https://networkx.org/documentation/stable/reference/algorithms/simple_paths.html)
- [How AWS Reachability Analyzer works (config-model, data-plane caveat, IPv4-only, considerations)](https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html)
- [What is Reachability Analyzer (API, pricing)](https://docs.aws.amazon.com/vpc/latest/reachability/what-is-reachability-analyzer.html)
