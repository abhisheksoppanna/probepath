"""Core L3/L4 AWS network semantics: security groups, NACLs, and subnet publicness.

Everything here is biased toward *over*-reaching: when an input is unknown we return an
"allow" with degraded confidence rather than a "deny", because a wrongly-claimed deny is a
false negative (DESIGN.md §1, §2.5, §2.6). The only place we assert closure is when an input
is fully known and definitively shut.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..ingest.normalized import RecordIndex, ResolveState, ResourceRecord
from ..model.cidr import any_untrusted, cidr_contains, parse_cidr
from ..model.enums import Confidence, ConservativeReason
from ..model.ports import ALL_PORTS, EPHEMERAL, PortSet, ports_from_rule


@dataclass(frozen=True)
class Allow:
    allowed: bool
    confidence: Confidence = Confidence.KNOWN
    reason: ConservativeReason | None = None
    rationale: str = ""


NOT_ALLOWED = Allow(False)


def _paren(desc: str) -> str:
    return f" ({desc})" if desc else ""


def _conf(*states: ResolveState) -> Confidence:
    return Confidence.AFTER_APPLY if ResolveState.UNKNOWN in states else Confidence.KNOWN


# --------------------------------------------------------------------------- #
# Security groups (stateful)                                                   #
# --------------------------------------------------------------------------- #
@dataclass
class SgRule:
    ports: PortSet
    cidrs: list[str]
    source_sgs: set[str]
    is_self: bool
    admits_internet: bool  # a KNOWN untrusted cidr is present
    source_unknown: bool  # cidr/sg/prefix could be anything -> conservatively admit
    reason: ConservativeReason | None
    confidence: Confidence
    desc: str


@dataclass
class SgModel:
    addr: str
    rules: list[SgRule] = field(default_factory=list)

    def allows_internet(self, port: int) -> Allow:
        best = NOT_ALLOWED
        for r in self.rules:
            if port not in r.ports:
                continue
            if r.admits_internet:
                rationale = f"SG {self.addr} ingress allows 0.0.0.0/0 on {r.ports}{_paren(r.desc)}"
                return Allow(True, Confidence.KNOWN, None, rationale)
            if r.source_unknown:
                rationale = f"SG {self.addr} ingress source is unknown for {r.ports}{_paren(r.desc)}"
                best = Allow(True, Confidence.AFTER_APPLY, r.reason, rationale)
        return best

    def allows_from_sg(self, src_addr: str, port: int) -> Allow:
        best = NOT_ALLOWED
        for r in self.rules:
            if port not in r.ports:
                continue
            if src_addr in r.source_sgs or (r.is_self and src_addr == self.addr):
                rationale = f"SG {self.addr} ingress allows SG {src_addr} on {r.ports}{_paren(r.desc)}"
                return Allow(True, r.confidence, None, rationale)
            if r.source_unknown:
                rationale = f"SG {self.addr} ingress source is unknown for {r.ports}{_paren(r.desc)}"
                best = Allow(True, Confidence.AFTER_APPLY, r.reason, rationale)
        return best

    def allows_from(self, src_sgs: list[str], src_cidr: str | None, port: int) -> Allow:
        """Does this SG admit a packet on ``port`` from an in-VPC host that carries any of
        ``src_sgs`` and sits in ``src_cidr``? Covers SG-to-SG refs AND CIDR-containment
        (a rule allowing 0.0.0.0/0 or the VPC range admits the host's private IP)."""
        best = NOT_ALLOWED
        for r in self.rules:
            if port not in r.ports:
                continue
            matched = next((s for s in src_sgs if s in r.source_sgs), None)
            if matched is not None or (r.is_self and self.addr in src_sgs):
                who = matched or self.addr
                return Allow(True, r.confidence, None,
                             f"SG {self.addr} ingress allows SG {who} on {r.ports}{_paren(r.desc)}")
            if r.admits_internet or (
                r.cidrs and src_cidr is not None and any(cidr_contains(c, src_cidr) for c in r.cidrs)
            ):
                return Allow(True, r.confidence, None,
                             f"SG {self.addr} ingress allows {src_cidr or 'CIDR'} on {r.ports}{_paren(r.desc)}")
            if r.source_unknown or (r.cidrs and src_cidr is None):
                best = Allow(True, Confidence.AFTER_APPLY, r.reason or ConservativeReason.AFTER_APPLY_VALUE,
                             f"SG {self.addr} ingress source uncertain for {r.ports}{_paren(r.desc)}")
        return best

    def ports_from(self, src_sgs: list[str], src_cidr: str | None) -> tuple[PortSet, Confidence]:
        """Ports this SG opens to an in-VPC host (SG-ref or CIDR-containment), for pivots."""
        ports = PortSet.empty()
        conf = Confidence.KNOWN
        for r in self.rules:
            hit = (
                any(s in r.source_sgs for s in src_sgs)
                or (r.is_self and self.addr in src_sgs)
                or r.admits_internet
                or (r.cidrs and src_cidr is not None and any(cidr_contains(c, src_cidr) for c in r.cidrs))
            )
            soft = r.source_unknown or (r.cidrs and src_cidr is None)
            if hit:
                ports = ports.union(r.ports)
            elif soft:
                ports = ports.union(r.ports)
                conf = Confidence.AFTER_APPLY
        return ports, conf

    def internet_ports(self) -> tuple[PortSet, Confidence, str]:
        """Union of ports this SG opens to the internet (known + conservatively-unknown)."""
        ports = PortSet.empty()
        conf = Confidence.KNOWN
        rationale = ""
        for r in self.rules:
            if r.admits_internet:
                ports = ports.union(r.ports)
                if not rationale:
                    rationale = f"SG {self.addr} allows 0.0.0.0/0 on {r.ports}"
            elif r.source_unknown:
                ports = ports.union(r.ports)
                conf = Confidence.AFTER_APPLY
                if not rationale:
                    rationale = f"SG {self.addr} has an unknown ingress source on {r.ports}"
        return ports, conf, rationale

    def ports_from_sg(self, src_addr: str) -> tuple[PortSet, Confidence]:
        """Ports this SG opens to a given source SG (for intra-VPC pivots)."""
        ports = PortSet.empty()
        conf = Confidence.KNOWN
        for r in self.rules:
            if src_addr in r.source_sgs or (r.is_self and src_addr == self.addr):
                ports = ports.union(r.ports)
            elif r.source_unknown:
                ports = ports.union(r.ports)
                conf = Confidence.AFTER_APPLY
        return ports, conf


def _parse_sg_rules(rec: ResourceRecord, idx: RecordIndex, block: str) -> list[SgRule]:
    rules: list[SgRule] = []
    referenced_sgs = {
        t.config_address
        for t in idx.targets(rec, block)
        if t.type in ("aws_security_group", "aws_default_security_group")
    }
    # Read the rule-list STRUCTURE straight from values: resolve(block) would over-flag the
    # whole list as UNKNOWN whenever any nested leaf (e.g. a known-after-apply SG id) is
    # unknown. Per-field unknownness is still checked below via resolve(block, i, field).
    raw_list = rec.values.get(block)
    if isinstance(raw_list, dict):
        raw_list = [raw_list]
    rule_list = raw_list if isinstance(raw_list, list) else []
    for i, raw_rule in enumerate(rule_list):
        if not isinstance(raw_rule, dict):
            continue
        fp = rec.resolve(block, i, "from_port")
        tp = rec.resolve(block, i, "to_port")
        proto = rec.resolve(block, i, "protocol")
        ports = (
            ALL_PORTS
            if (fp.is_unknown or tp.is_unknown or proto.is_unknown)
            else ports_from_rule(fp.value, tp.value, proto.value)
        )
        cidr_res = rec.resolve(block, i, "cidr_blocks")
        v6_res = rec.resolve(block, i, "ipv6_cidr_blocks")
        pl_res = rec.resolve(block, i, "prefix_list_ids")
        sg_res = rec.resolve(block, i, "security_groups")
        self_res = rec.resolve(block, i, "self")

        known_cidrs: list[str] = []
        admits_internet = False
        source_unknown = False
        reason: ConservativeReason | None = None

        for res in (cidr_res, v6_res):
            if res.is_unknown:
                source_unknown = True
                reason = ConservativeReason.AFTER_APPLY_VALUE
            elif res.known and isinstance(res.value, list):
                known_cidrs.extend(str(c) for c in res.value)
        if any_untrusted(known_cidrs):
            admits_internet = True

        # Customer-managed prefix lists: contents not in the plan -> conservatively internet.
        if pl_res.is_unknown or (pl_res.known and pl_res.value):
            source_unknown = True
            reason = ConservativeReason.MANAGED_PREFIX_LIST

        source_sgs: set[str] = set()
        has_sg_source = False
        if sg_res.is_unknown:
            has_sg_source = True  # id known-after-apply, but the *reference* tells us which SG
        elif sg_res.known and sg_res.value:
            has_sg_source = True
        if has_sg_source:
            if referenced_sgs:
                source_sgs = set(referenced_sgs)
            else:
                # an SG source we cannot resolve (remote state / cross account)
                source_unknown = True
                reason = ConservativeReason.REMOTE_STATE_REF

        is_self = bool(self_res.value) if self_res.known else False

        confidence = _conf(fp.state, tp.state, proto.state)
        if source_unknown:
            confidence = Confidence.AFTER_APPLY

        desc = ""
        d = rec.resolve(block, i, "description")
        if d.known and d.value:
            desc = str(d.value)

        rules.append(
            SgRule(
                ports=ports,
                cidrs=known_cidrs,
                source_sgs=source_sgs,
                is_self=is_self,
                admits_internet=admits_internet,
                source_unknown=source_unknown,
                reason=reason,
                confidence=confidence,
                desc=desc,
            )
        )
    return rules


def collect_security_groups(idx: RecordIndex) -> dict[str, SgModel]:
    """Build an SgModel per security group, folding in inline ingress, the modern split
    ``aws_vpc_security_group_ingress_rule`` resources, and the default SG."""
    models: dict[str, SgModel] = {}
    for rec in idx.of_type("aws_security_group", "aws_default_security_group"):
        models[rec.config_address] = SgModel(rec.config_address, _parse_sg_rules(rec, idx, "ingress"))

    # Modern one-rule-per-resource ingress rules attach to a target SG via security_group_id.
    for rec in idx.of_type("aws_vpc_security_group_ingress_rule"):
        owners = idx.targets_of_type(
            rec, "security_group_id", "aws_security_group", "aws_default_security_group"
        )
        rule = _parse_split_rule(rec, idx)
        for owner in owners:
            models.setdefault(owner.config_address, SgModel(owner.config_address)).rules.append(rule)

    # Legacy one-rule-per-resource: aws_security_group_rule (still the dominant real-world form).
    for rec in idx.of_type("aws_security_group_rule"):
        if str(rec.resolve("type").value_or("ingress")) != "ingress":
            continue
        owners = idx.targets_of_type(
            rec, "security_group_id", "aws_security_group", "aws_default_security_group"
        )
        rule = _parse_legacy_sg_rule(rec, idx)
        for owner in owners:
            models.setdefault(owner.config_address, SgModel(owner.config_address)).rules.append(rule)
    return models


def _parse_legacy_sg_rule(rec: ResourceRecord, idx: RecordIndex) -> SgRule:
    """Parse an ``aws_security_group_rule`` (legacy attribute names: ``protocol``,
    ``cidr_blocks``, ``source_security_group_id``, ``self``)."""
    fp = rec.resolve("from_port")
    tp = rec.resolve("to_port")
    proto = rec.resolve("protocol")
    ports = (
        ALL_PORTS
        if (fp.is_unknown or tp.is_unknown or proto.is_unknown)
        else ports_from_rule(fp.value, tp.value, proto.value)
    )
    v4 = rec.resolve("cidr_blocks")
    v6 = rec.resolve("ipv6_cidr_blocks")
    pl = rec.resolve("prefix_list_ids")
    ref_sg = rec.resolve("source_security_group_id")
    self_res = rec.resolve("self")
    known_cidrs: list[str] = []
    admits_internet = False
    source_unknown = False
    reason: ConservativeReason | None = None
    for res in (v4, v6):
        if res.is_unknown:
            source_unknown = True
            reason = ConservativeReason.AFTER_APPLY_VALUE
        elif res.known and isinstance(res.value, list):
            known_cidrs.extend(str(c) for c in res.value)
    if any_untrusted(known_cidrs):
        admits_internet = True
    if pl.is_unknown or (pl.known and pl.value):
        source_unknown = True
        reason = ConservativeReason.MANAGED_PREFIX_LIST
    source_sgs: set[str] = {
        t.config_address
        for t in idx.targets_of_type(
            rec, "source_security_group_id", "aws_security_group", "aws_default_security_group"
        )
    }
    if not source_sgs and ref_sg.is_unknown:
        source_unknown = True
        reason = ConservativeReason.REMOTE_STATE_REF
    return SgRule(
        ports=ports,
        cidrs=known_cidrs,
        source_sgs=source_sgs,
        is_self=bool(self_res.value) if self_res.known else False,
        admits_internet=admits_internet,
        source_unknown=source_unknown,
        reason=reason,
        confidence=Confidence.AFTER_APPLY if source_unknown else _conf(fp.state, tp.state, proto.state),
        desc="security_group_rule",
    )


def _parse_split_rule(rec: ResourceRecord, idx: RecordIndex) -> SgRule:
    fp = rec.resolve("from_port")
    tp = rec.resolve("to_port")
    proto = rec.resolve("ip_protocol")
    ports = (
        ALL_PORTS
        if (fp.is_unknown or tp.is_unknown or proto.is_unknown)
        else ports_from_rule(fp.value, tp.value, proto.value)
    )
    v4 = rec.resolve("cidr_ipv4")
    v6 = rec.resolve("cidr_ipv6")
    pl = rec.resolve("prefix_list_id")
    ref_sg = rec.resolve("referenced_security_group_id")
    known_cidrs: list[str] = []
    admits_internet = False
    source_unknown = False
    reason: ConservativeReason | None = None
    for res in (v4, v6):
        if res.is_unknown:
            source_unknown = True
            reason = ConservativeReason.AFTER_APPLY_VALUE
        elif res.known and res.value:
            known_cidrs.append(str(res.value))
    if any_untrusted(known_cidrs):
        admits_internet = True
    if pl.is_unknown or (pl.known and pl.value):
        source_unknown = True
        reason = ConservativeReason.MANAGED_PREFIX_LIST
    # The SG source is driven by reference PRESENCE (the id is usually known-after-apply, so
    # its value is absent/null — only the reference survives).
    source_sgs: set[str] = {
        t.config_address
        for t in idx.targets_of_type(
            rec, "referenced_security_group_id", "aws_security_group", "aws_default_security_group"
        )
    }
    if not source_sgs and ref_sg.is_unknown:
        source_unknown = True
        reason = ConservativeReason.REMOTE_STATE_REF
    return SgRule(
        ports=ports,
        cidrs=known_cidrs,
        source_sgs=source_sgs,
        is_self=False,
        admits_internet=admits_internet,
        source_unknown=source_unknown,
        reason=reason,
        confidence=Confidence.AFTER_APPLY if source_unknown else _conf(fp.state, tp.state, proto.state),
        desc="vpc_security_group_ingress_rule",
    )


# --------------------------------------------------------------------------- #
# NACLs (stateless, ordered)                                                   #
# --------------------------------------------------------------------------- #
@dataclass
class NaclRule:
    rule_number: int
    egress: bool
    action: str  # "allow" | "deny"
    protocol: str
    ports: PortSet
    cidr: str


@dataclass
class NaclModel:
    addr: str
    is_default: bool
    rules: list[NaclRule] = field(default_factory=list)

    def _eval(self, egress: bool, src_or_dst_cidr: str, port: int) -> str:
        target = parse_cidr(src_or_dst_cidr)
        for rule in sorted((r for r in self.rules if r.egress == egress), key=lambda r: r.rule_number):
            if port not in rule.ports:
                continue
            rnet = parse_cidr(rule.cidr)
            if rnet is None or target is None:
                # unknown cidr -> match conservatively (an allow proceeds; a deny we honor)
                return rule.action
            if rnet.version == target.version and (
                rnet.supernet_of(target) or rnet == target  # type: ignore[arg-type]
            ):
                return rule.action
        return "deny"  # implicit final * deny

    def _ephemeral_return_open(self, src_cidr: str) -> bool:
        """Stateless return: the reply leaves on SOME ephemeral port in 1024-65535. True if
        ANY port in that range is allowed outbound under ordered first-match. We compute this
        over the whole interval (never a 4-port sample — narrowing is a false-negative vector,
        DESIGN.md §2.6)."""
        target = parse_cidr(src_cidr)
        undecided = EPHEMERAL
        allowed = PortSet.empty()
        for rule in sorted((r for r in self.rules if r.egress), key=lambda r: r.rule_number):
            rnet = parse_cidr(rule.cidr)
            applies = (
                rnet is None
                or target is None
                or (rnet.version == target.version and (rnet.supernet_of(target) or rnet == target))  # type: ignore[arg-type]
            )
            if not applies:
                continue
            seg = rule.ports.intersect(EPHEMERAL).intersect(undecided)
            if seg.is_empty:
                continue
            if rule.action == "allow":
                allowed = allowed.union(seg)
            undecided = undecided.difference(seg)  # first match wins for these ports
            if undecided.is_empty:
                break
        return not allowed.is_empty

    def allows(self, src_cidr: str, port: int) -> Allow:
        if self.is_default or not self.rules:
            return Allow(True, Confidence.DEFAULT, None, f"NACL {self.addr or 'default'} allows (default)")
        inbound = self._eval(False, src_cidr, port)
        if inbound == "deny":
            return Allow(False, Confidence.KNOWN, None, f"NACL {self.addr} inbound denies {port} from {src_cidr}")
        if not self._ephemeral_return_open(src_cidr):
            return Allow(False, Confidence.KNOWN, None, f"NACL {self.addr} blocks ephemeral return (1024-65535)")
        return Allow(True, Confidence.KNOWN, None, f"NACL {self.addr} allows {port} + ephemeral return")


def _parse_nacl_rules(rec: ResourceRecord) -> list[NaclRule]:
    rules: list[NaclRule] = []
    for block, egress in (("ingress", False), ("egress", True)):
        raw_list = rec.values.get(block)
        if not isinstance(raw_list, list):
            continue
        for r in raw_list:
            if not isinstance(r, dict):
                continue
            proto = str(r.get("protocol", "-1"))
            ports = ports_from_rule(r.get("from_port"), r.get("to_port"), proto)
            rule_no = r.get("rule_no")
            if rule_no is None:
                rule_no = r.get("rule_number")
            rules.append(
                NaclRule(
                    rule_number=int(rule_no) if rule_no is not None else 32767,
                    egress=egress,
                    action=str(r.get("action") or r.get("rule_action") or "allow").lower(),
                    protocol=proto,
                    ports=ports,
                    cidr=str(r.get("cidr_block", "0.0.0.0/0")),
                )
            )
    return rules


def collect_nacls(idx: RecordIndex) -> tuple[dict[str, NaclModel], dict[str, str]]:
    """Return (nacl models by config addr, subnet config addr -> nacl config addr)."""
    models: dict[str, NaclModel] = {}
    subnet_to_nacl: dict[str, str] = {}
    for rec in idx.of_type("aws_network_acl"):
        m = NaclModel(rec.config_address, is_default=False, rules=_parse_nacl_rules(rec))
        models[rec.config_address] = m
        for subnet in idx.targets_of_type(rec, "subnet_ids", "aws_subnet"):
            subnet_to_nacl[subnet.config_address] = rec.config_address
    for rec in idx.of_type("aws_default_network_acl"):
        models[rec.config_address] = NaclModel(rec.config_address, is_default=True)
    for rec in idx.of_type("aws_network_acl_association"):
        nacls = idx.targets_of_type(rec, "network_acl_id", "aws_network_acl")
        subnets = idx.targets_of_type(rec, "subnet_id", "aws_subnet")
        if nacls and subnets:
            subnet_to_nacl[subnets[0].config_address] = nacls[0].config_address
    return models, subnet_to_nacl
