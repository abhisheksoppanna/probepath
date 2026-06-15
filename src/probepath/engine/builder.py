"""GraphBuilder: normalized ResourceRecords -> ResourceGraph.

This is where AWS semantics become graph edges. The cardinal discipline (DESIGN.md §1, §2.2):
an edge is *omitted only when a gate is definitively closed with fully-known inputs*; on any
doubt we create the edge with degraded confidence and record nothing as blocked. Closures we
are sure about are recorded as ``BlockedEdge`` so an UNREACHABLE verdict can prove itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..aws.loadbalancer import LbModel, TargetGroup, collect_load_balancers, collect_target_groups
from ..aws.network import (
    Allow,
    NaclModel,
    SgModel,
    collect_nacls,
    collect_security_groups,
)
from ..aws.resource_types import SINK_TYPES, engine_default_port, sink_spec
from ..aws.routing import SubnetInfo, compute_publicness
from ..aws.s3 import evaluate_s3
from ..ingest.normalized import RecordIndex, ResourceRecord
from ..model.edges import BlockedEdge, Edge, EdgeConstraint
from ..model.enums import Confidence, ConservativeReason, Direction, EdgeKind, NodeKind
from ..model.graph import ResourceGraph
from ..model.nodes import INTERNET_ID, Node, SourceLocation
from ..model.ports import PortSet

_CONF_RANK = {
    Confidence.KNOWN: 0,
    Confidence.DEFAULT: 1,
    Confidence.PARSED_HCL: 2,
    Confidence.AFTER_APPLY: 3,
    Confidence.MISSING: 4,
}

_SG_ATTRS = ("vpc_security_group_ids", "security_groups", "security_group_ids")
_COMMON_PORTS = (22, 80, 443, 3306, 5432, 6379, 1433, 1521, 5439, 27017, 11211, 9200)


def weakest(*confs: Confidence) -> Confidence:
    return max(confs, key=lambda c: _CONF_RANK[c], default=Confidence.KNOWN)


def _sample_ports(ports: PortSet, cap: int = 64) -> list[int]:
    out: list[int] = []
    total = sum(hi - lo + 1 for lo, hi in ports.intervals)
    if total <= cap:
        for lo, hi in ports.intervals:
            out.extend(range(lo, hi + 1))
        return out
    for lo, hi in ports.intervals:  # large set: endpoints + common service ports
        out.extend({lo, hi})
    out.extend(p for p in _COMMON_PORTS if p in ports)
    return out


@dataclass
class _Actor:
    """A compute resource that can be an internet entry and/or originate a pivot."""

    addr: str
    node_id: str
    vpc: str | None
    subnet_addr: str | None
    subnet: SubnetInfo | None
    sg_addrs: list[str]
    has_public_ip: bool
    public_ip_conf: Confidence
    sg_unresolved: bool = False


class GraphBuilder:
    def __init__(self, records: list[ResourceRecord]) -> None:
        self.idx = RecordIndex(records)
        self.sgs: dict[str, SgModel] = collect_security_groups(self.idx)
        self.subnets: dict[str, SubnetInfo] = compute_publicness(self.idx)
        nacls, subnet_to_nacl = collect_nacls(self.idx)
        self.nacls: dict[str, NaclModel] = nacls
        for saddr, naddr in subnet_to_nacl.items():
            if saddr in self.subnets:
                self.subnets[saddr].nacl = naddr
        self.lbs: dict[str, LbModel] = collect_load_balancers(self.idx)
        self.tgs: dict[str, TargetGroup] = collect_target_groups(self.idx)
        self.graph = ResourceGraph()
        self.actors: list[_Actor] = []

    # --- small helpers ----------------------------------------------------
    def _sg_models(self, rec: ResourceRecord) -> list[SgModel]:
        out: list[SgModel] = []
        for attr in _SG_ATTRS:
            for t in self.idx.targets_of_type(
                rec, attr, "aws_security_group", "aws_default_security_group"
            ):
                if t.config_address in self.sgs and self.sgs[t.config_address] not in out:
                    out.append(self.sgs[t.config_address])
        return out

    def _sg_addrs(self, rec: ResourceRecord) -> list[str]:
        return [m.addr for m in self._sg_models(rec)]

    def _sg_unresolved(self, rec: ResourceRecord) -> bool:
        """True if the record references security groups we cannot resolve (module output,
        remote state, cross-account). We must not drop the edge — that would be a false
        negative; instead the caller emits a conservative POTENTIALLY edge (MF-6/MF-7)."""
        if self._sg_models(rec):
            return False
        return any(self.idx.has_unresolved_ref(rec, a) for a in _SG_ATTRS)

    def _subnet_of(self, rec: ResourceRecord, attr: str = "subnet_id") -> SubnetInfo | None:
        for t in self.idx.targets_of_type(rec, attr, "aws_subnet", "aws_default_subnet"):
            return self.subnets.get(t.config_address)
        return None

    def _nacl_for(self, subnet: SubnetInfo | None) -> NaclModel | None:
        if subnet is None or subnet.nacl is None:
            return None
        return self.nacls.get(subnet.nacl)

    def _nacl_ok(self, subnet: SubnetInfo | None, src_cidr: str | None, ports: PortSet) -> Allow:
        nacl = self._nacl_for(subnet)
        if nacl is None or nacl.is_default or not nacl.rules:
            return Allow(True, Confidence.DEFAULT, None, "no custom NACL (default allow)")
        if src_cidr is None:
            # Can't evaluate a custom NACL without the real source CIDR — never assert closure
            # on an unknown; conservatively allow with degraded confidence (DESIGN.md §1.3).
            return Allow(True, Confidence.AFTER_APPLY, ConservativeReason.AFTER_APPLY_VALUE,
                         f"NACL {nacl.addr}: source CIDR unknown, conservatively allowed")
        for p in _sample_ports(ports):
            a = nacl.allows(src_cidr, p)
            if a.allowed:
                return a
        return Allow(False, Confidence.KNOWN, None, f"NACL {nacl.addr} blocks {ports}")

    # --- build ------------------------------------------------------------
    def build(self) -> ResourceGraph:
        self.graph.add_node(
            Node(INTERNET_ID, NodeKind.INTERNET_SOURCE, SourceLocation("0.0.0.0/0 + ::/0"),
                 label="internet")
        )
        self._add_compute_nodes()
        self._add_sink_nodes()
        self._add_internet_to_compute()
        self._add_load_balancer_paths()
        self._add_intra_vpc_edges()
        self._add_direct_public_sinks()
        self._add_unresolved_sink_edges()
        self._add_s3()
        return self.graph

    def _add_unresolved_sink_edges(self) -> None:
        """A sink whose security groups live in a module/remote state we can't see cannot be
        proven safe — emit a conservative POTENTIALLY edge instead of dropping it (MF-6/MF-7)."""
        for tf_type in SINK_TYPES:
            for rec in self.idx.of_type(tf_type):
                if not self._sg_unresolved(rec):
                    continue
                self.graph.add_edge(Edge(
                    INTERNET_ID, rec.address, EdgeKind.IGW_TO_SINK,
                    EdgeConstraint(PortSet.single(self._sink_port(rec)), Direction.FORWARD,
                                   admits_internet=True),
                    "security group is unresolved (module / remote state) — cannot prove unreachable",
                    rec.loc(), Confidence.AFTER_APPLY, ConservativeReason.REMOTE_STATE_REF))

    def _add_compute_nodes(self) -> None:
        for rec in self.idx.of_type("aws_instance", "aws_network_interface"):
            subnet = self._subnet_of(rec)
            assoc = rec.resolve("associate_public_ip_address")
            if assoc.known:
                has_pub, pub_conf = bool(assoc.value), Confidence.KNOWN
            elif assoc.is_unknown:
                has_pub, pub_conf = True, Confidence.AFTER_APPLY
            elif subnet is not None:
                has_pub, pub_conf = subnet.is_public, subnet.confidence  # map_public_ip via subnet posture
            else:
                has_pub, pub_conf = True, Confidence.AFTER_APPLY
            node = Node(rec.address, NodeKind.ENI, rec.loc(), label=rec.address)
            self.graph.add_node(node)
            self.actors.append(
                _Actor(
                    addr=rec.config_address,
                    node_id=rec.address,
                    vpc=subnet.vpc if subnet else None,
                    subnet_addr=subnet.addr if subnet else None,
                    subnet=subnet,
                    sg_addrs=self._sg_addrs(rec),
                    has_public_ip=has_pub,
                    public_ip_conf=pub_conf,
                    sg_unresolved=self._sg_unresolved(rec),
                )
            )

    def _sink_port(self, rec: ResourceRecord) -> int:
        spec = sink_spec(rec.type)
        fallback = spec.default_port if spec else 443
        port = rec.resolve("port")
        if port.known and port.value is not None:
            return int(port.value)
        engine = rec.resolve("engine")
        return engine_default_port(engine.value if engine.known else None, fallback)

    def _sink_subnets(self, rec: ResourceRecord) -> list[SubnetInfo]:
        groups = {
            "aws_db_instance": ("db_subnet_group_name", "aws_db_subnet_group"),
            "aws_rds_cluster": ("db_subnet_group_name", "aws_db_subnet_group"),
            "aws_elasticache_cluster": ("subnet_group_name", "aws_elasticache_subnet_group"),
            "aws_elasticache_replication_group": ("subnet_group_name", "aws_elasticache_subnet_group"),
            "aws_redshift_cluster": ("cluster_subnet_group_name", "aws_redshift_subnet_group"),
        }
        out: list[SubnetInfo] = []
        if rec.type in groups:
            attr, gtype = groups[rec.type]
            for grp in self.idx.targets_of_type(rec, attr, gtype):
                for sn in self.idx.targets_of_type(grp, "subnet_ids", "aws_subnet"):
                    if sn.config_address in self.subnets:
                        out.append(self.subnets[sn.config_address])
        return out

    def _add_sink_nodes(self) -> None:
        for tf_type, spec in SINK_TYPES.items():
            for rec in self.idx.of_type(tf_type):
                node = Node(
                    rec.address, spec.kind, rec.loc(), label=rec.address, is_sink=True,
                    sink_label=spec.label,
                    attrs={
                        "port": self._sink_port(rec),
                        "sg_addrs": self._sg_addrs(rec),
                        "subnets": [s.addr for s in self._sink_subnets(rec)],
                        "config_address": rec.config_address,
                    },
                )
                self.graph.add_node(node)

    def _add_internet_to_compute(self) -> None:
        for actor in self.actors:
            models = [self.sgs[a] for a in actor.sg_addrs if a in self.sgs]
            if not actor.has_public_ip:
                continue
            if actor.subnet is not None and not actor.subnet.is_public:
                self.graph.add_blocked(
                    BlockedEdge("internet", actor.node_id,
                                f"host in private subnet ({actor.subnet.rationale})",
                                SourceLocation(actor.subnet_addr or actor.addr)))
                continue
            ports = PortSet.empty()
            conf = Confidence.KNOWN
            rationale = ""
            for m in models:
                p, c, r = m.internet_ports()
                if p:
                    ports = ports.union(p)
                    conf = weakest(conf, c)
                    rationale = rationale or r
            if ports.is_empty and actor.sg_unresolved:
                # SGs live in a module/remote state we can't see — don't claim "no ingress".
                ports, conf = PortSet.all(), Confidence.AFTER_APPLY
                rationale = "security group is unresolved (module/remote state)"
            if ports.is_empty:
                if models:
                    self.graph.add_blocked(
                        BlockedEdge("internet", actor.node_id,
                                    "no security-group ingress from the internet",
                                    SourceLocation(actor.addr)))
                continue
            nacl = self._nacl_ok(actor.subnet, "0.0.0.0/0", ports)
            if not nacl.allowed:
                self.graph.add_blocked(
                    BlockedEdge("internet", actor.node_id, nacl.rationale,
                                SourceLocation(actor.subnet_addr or actor.addr)))
                continue
            edge_conf = weakest(conf, actor.public_ip_conf,
                                actor.subnet.confidence if actor.subnet else Confidence.AFTER_APPLY,
                                nacl.confidence)
            why = f"{rationale}; {actor.subnet.rationale if actor.subnet else 'subnet unknown'}; public IP"
            self.graph.add_edge(Edge(
                INTERNET_ID, actor.node_id, EdgeKind.IGW_TO_HOST,
                EdgeConstraint(ports, Direction.FORWARD, admits_internet=True),
                why, SourceLocation(actor.subnet_addr or actor.addr), edge_conf, _reason_for(edge_conf)))

    def _add_load_balancer_paths(self) -> None:
        for lb in self.lbs.values():
            node = Node(lb.addr, NodeKind.LOAD_BALANCER, SourceLocation(lb.addr), label=lb.addr)
            self.graph.add_node(node)
            public_subnet = any(
                self.subnets[s].is_public for s in lb.subnet_addrs if s in self.subnets
            ) or not lb.subnet_addrs
            if not lb.is_internet_facing or not public_subnet:
                continue
            entry = lb.listener_ports()
            sg_conf = Confidence.KNOWN
            if lb.has_sg and lb.sg_addrs:
                allowed = PortSet.empty()
                for a in lb.sg_addrs:
                    if a in self.sgs:
                        p, c, _ = self.sgs[a].internet_ports()
                        allowed = allowed.union(p)
                        sg_conf = weakest(sg_conf, c)
                entry = entry.intersect(allowed)
            elif lb.has_sg and not lb.sg_addrs:
                sg_conf = Confidence.AFTER_APPLY  # SG present but unresolved -> conservative
            # SG-less NLB: entry stays = all listener ports
            if entry.is_empty:
                continue
            self.graph.add_edge(Edge(
                INTERNET_ID, lb.addr, EdgeKind.IGW_TO_LB,
                EdgeConstraint(entry, Direction.FORWARD, admits_internet=True),
                f"internet-facing {lb.lb_type} LB, listener(s) {entry}", SourceLocation(lb.addr),
                sg_conf, _reason_for(sg_conf)))
            self._wire_lb_targets(lb, entry)

    def _wire_lb_targets(self, lb: LbModel, entry: PortSet) -> None:
        for listener in lb.listeners:
            if listener.port is not None and listener.port not in entry and not listener.port_unknown:
                continue
            for tg_addr in listener.tg_addrs:
                tg = self.tgs.get(tg_addr)
                if tg is None:
                    continue
                tg_port = PortSet.all() if (tg.port is None or tg.port_unknown) else PortSet.single(tg.port)
                for target_addr in tg.target_addrs:
                    target = self._actor_by_config(target_addr)
                    if target is None:
                        continue
                    allow = self._target_admits_lb(target, lb, tg, tg_port)
                    if not allow.allowed:
                        continue
                    self.graph.add_edge(Edge(
                        lb.addr, target.node_id, EdgeKind.LB_TO_TARGET,
                        EdgeConstraint(tg_port, Direction.FORWARD),
                        allow.rationale, SourceLocation(target.addr), allow.confidence,
                        _reason_for(allow.confidence)))

    def _target_admits_lb(self, target: _Actor, lb: LbModel, tg: TargetGroup, tg_port: PortSet) -> Allow:
        models = [self.sgs[a] for a in target.sg_addrs if a in self.sgs]
        if not models:
            return Allow(True, Confidence.AFTER_APPLY, ConservativeReason.AFTER_APPLY_VALUE,
                         f"target {target.addr} has no resolvable SG -> assumed open")
        lb_cidrs = [
            self.subnets[s].cidr for s in lb.subnet_addrs
            if s in self.subnets and self.subnets[s].cidr
        ]
        # What source the TARGET sees (DESIGN.md §2.7):
        #   ALB                       -> the ALB's SG / the ALB's subnet private IPs
        #   NLB, preserve_client_ip   -> the original client IP (the internet)
        #   NLB, no preserve / ip tg  -> the NLB's subnet private IPs
        nlb_preserve = lb.lb_type == "network" and tg.preserve_client_ip and tg.target_type != "ip"
        src_cidrs: list[str | None] = ["0.0.0.0/0"] if nlb_preserve else (lb_cidrs or [None])
        for p in _sample_ports(tg_port):
            for m in models:
                for c in src_cidrs:
                    a = m.allows_from(lb.sg_addrs, c, p)  # checks LB SG-ref AND CIDR containment
                    if a.allowed:
                        return a
        return Allow(False)

    def _add_intra_vpc_edges(self) -> None:
        # actor -> sink (the pivot into the database) and actor -> actor (multi-hop pivots)
        for src in self.actors:
            for sink in self.graph.sinks():
                self._maybe_pivot_to_sink(src, sink)
            for dst in self.actors:
                if dst.node_id == src.node_id:
                    continue
                self._maybe_pivot_to_actor(src, dst)

    def _same_vpc(self, a: str | None, b: str | None) -> bool | None:
        if a is None or b is None:
            return None  # unknown -> caller treats conservatively (allow)
        return a == b

    def _maybe_pivot_to_sink(self, src: _Actor, sink: Node) -> None:
        port = int(sink.get("port", 443))
        sink_sgs = [self.sgs[a] for a in sink.get("sg_addrs", []) if a in self.sgs]
        sink_vpc = self._sink_vpc(sink)
        same = self._same_vpc(src.vpc, sink_vpc)
        if same is False:
            return  # different known VPCs, no peering modeled -> isolated
        src_cidr = src.subnet.cidr if src.subnet else None
        best: Allow | None = None
        for m in sink_sgs:
            a = m.allows_from(src.sg_addrs, src_cidr, port)
            if a.allowed and (best is None or _CONF_RANK[a.confidence] < _CONF_RANK[best.confidence]):
                best = a
        if best is None:
            return
        sink_subnet = self._first_subnet(sink.get("subnets", []))
        nacl = self._nacl_ok(sink_subnet, src_cidr, PortSet.single(port))
        if not nacl.allowed:
            self.graph.add_blocked(BlockedEdge(src.addr, sink.id, nacl.rationale, sink.location))
            return
        conf = weakest(best.confidence, nacl.confidence,
                       Confidence.AFTER_APPLY if same is None else Confidence.KNOWN)
        self.graph.add_edge(Edge(
            src.node_id, sink.id, EdgeKind.INTRA_VPC,
            EdgeConstraint(PortSet.single(port), Direction.FORWARD),
            best.rationale, sink.location, conf, _reason_for(conf)))

    def _maybe_pivot_to_actor(self, src: _Actor, dst: _Actor) -> None:
        same = self._same_vpc(src.vpc, dst.vpc)
        if same is False:
            return
        dst_models = [self.sgs[a] for a in dst.sg_addrs if a in self.sgs]
        src_cidr = src.subnet.cidr if src.subnet else None
        ports = PortSet.empty()
        conf = Confidence.KNOWN
        for m in dst_models:
            p, c = m.ports_from(src.sg_addrs, src_cidr)
            if p:
                ports = ports.union(p)
                conf = weakest(conf, c)
        if ports.is_empty:
            return
        nacl = self._nacl_ok(dst.subnet, src_cidr, ports)
        if not nacl.allowed:
            return
        conf = weakest(conf, nacl.confidence, Confidence.AFTER_APPLY if same is None else Confidence.KNOWN)
        self.graph.add_edge(Edge(
            src.node_id, dst.node_id, EdgeKind.INTRA_VPC,
            EdgeConstraint(ports, Direction.FORWARD),
            f"pivot {src.addr} -> {dst.addr} on {ports}", SourceLocation(dst.addr),
            conf, _reason_for(conf)))

    def _add_direct_public_sinks(self) -> None:
        for tf_type in SINK_TYPES:
            for rec in self.idx.of_type(tf_type):
                self._maybe_direct_public(rec)

    def _maybe_direct_public(self, rec: ResourceRecord) -> None:
        pa = rec.resolve("publicly_accessible")
        if pa.known and pa.value is False:
            return  # not publicly accessible: no direct internet path (in-VPC pivot still applies)
        pa_conf = Confidence.KNOWN if pa.known else Confidence.AFTER_APPLY
        subnets = self._sink_subnets(rec)
        public = any(s.is_public for s in subnets) if subnets else True  # unknown subnets -> conservative
        if subnets and not public:
            # publicly_accessible alone is NOT a path without a public subnet — record the proof.
            why = subnets[0].rationale
            self.graph.add_blocked(BlockedEdge(
                "internet", rec.address,
                f"database subnet is private ({why}); publicly_accessible is not a path on its own",
                rec.loc()))
            return
        port = self._sink_port(rec)
        sink_sgs = [self.sgs[a] for a in self._sg_addrs(rec) if a in self.sgs]
        best: Allow | None = None
        for m in sink_sgs:
            a = m.allows_internet(port)
            if a.allowed and (best is None or _CONF_RANK[a.confidence] < _CONF_RANK[best.confidence]):
                best = a
        if best is None:
            return
        sub = subnets[0] if subnets else None
        sub_conf = sub.confidence if sub else Confidence.AFTER_APPLY
        conf = weakest(best.confidence, pa_conf, sub_conf)
        self.graph.add_edge(Edge(
            INTERNET_ID, rec.address, EdgeKind.IGW_TO_SINK,
            EdgeConstraint(PortSet.single(port), Direction.FORWARD, admits_internet=True),
            f"directly internet-exposed: {best.rationale}; publicly_accessible + public subnet",
            rec.loc(), conf, _reason_for(conf)))

    def _add_s3(self) -> None:
        exposed = {v.bucket_addr: v for v in evaluate_s3(self.idx)}
        for rec in self.idx.of_type("aws_s3_bucket"):
            node = Node(rec.address, NodeKind.S3_BUCKET, rec.loc(), label=rec.address,
                        is_sink=True, sink_label="S3 bucket")
            self.graph.add_node(node)
            v = exposed.get(rec.config_address)
            if v is None:
                self.graph.add_blocked(BlockedEdge(
                    "internet", rec.address,
                    "Block Public Access fully enabled / no anonymous policy or ACL", rec.loc()))
                continue
            self.graph.add_edge(Edge(
                INTERNET_ID, rec.address, EdgeKind.IGW_TO_SINK,
                EdgeConstraint(PortSet.single(443), Direction.FORWARD, admits_internet=True),
                v.rationale, rec.loc(), v.confidence, v.reason))

    # --- lookups ----------------------------------------------------------
    def _actor_by_config(self, config_addr: str) -> _Actor | None:
        for a in self.actors:
            if a.addr == config_addr:
                return a
        return None

    def _sink_vpc(self, sink: Node) -> str | None:
        for s in sink.get("subnets", []):
            if s in self.subnets:
                return self.subnets[s].vpc
        return None

    def _first_subnet(self, addrs: list[str]) -> SubnetInfo | None:
        for a in addrs:
            if a in self.subnets:
                return self.subnets[a]
        return None


def _reason_for(conf: Confidence) -> ConservativeReason | None:
    if conf in (Confidence.KNOWN, Confidence.DEFAULT):
        return None
    if conf == Confidence.MISSING:
        return ConservativeReason.MISSING_RESOURCE
    if conf == Confidence.PARSED_HCL:
        return ConservativeReason.UNPARSEABLE_HCL
    return ConservativeReason.AFTER_APPLY_VALUE


def build_graph(records: list[ResourceRecord]) -> ResourceGraph:
    return GraphBuilder(records).build()
