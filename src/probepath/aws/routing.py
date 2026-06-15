"""Subnet publicness derivation (DESIGN.md §2.4).

``is_public`` is route-table-based, NEVER name/tag-based: a subnet named "public" with no
IGW route is private; a subnet named "private" with an IGW route is public. The only way we
assert a subnet is private (a closure that can suppress) is a fully-known route table with no
default-to-IGW route.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..ingest.normalized import RecordIndex, ResourceRecord
from ..model.enums import Confidence


@dataclass
class SubnetInfo:
    addr: str
    vpc: str | None
    cidr: str | None
    is_public: bool
    confidence: Confidence
    rationale: str
    nacl: str | None = None


@dataclass
class _RtInfo:
    has_default: bool = False
    targets_igw: bool = False
    targets_nat: bool = False
    unknown_target: bool = False

    @property
    def public(self) -> bool:
        return self.targets_igw or (self.has_default and self.unknown_target and not self.targets_nat)

    @property
    def nat_only(self) -> bool:
        return self.has_default and self.targets_nat and not self.targets_igw and not self.unknown_target


def _classify_route(
    rec: ResourceRecord, idx: RecordIndex, route_attr: str, route: dict[str, Any], index: int, info: _RtInfo
) -> None:
    cb = route.get("cidr_block") or ""
    v6 = route.get("ipv6_cidr_block") or ""
    if cb != "0.0.0.0/0" and v6 != "::/0":
        return
    info.has_default = True
    igw_ref = any(t.type == "aws_internet_gateway" for t in idx.targets(rec, route_attr))
    nat_ref = any(t.type == "aws_nat_gateway" for t in idx.targets(rec, route_attr))
    gw = str(route.get("gateway_id") or "")
    nat = str(route.get("nat_gateway_id") or "")
    gw_unknown = rec.resolve(route_attr, index, "gateway_id").is_unknown
    nat_unknown = rec.resolve(route_attr, index, "nat_gateway_id").is_unknown
    if gw.startswith("igw-") or (gw_unknown and igw_ref):
        info.targets_igw = True
    elif gw.startswith("eigw-"):
        pass  # egress-only IGW: IPv6 outbound only, never an inbound edge
    elif nat.startswith("nat-") or (nat_unknown and nat_ref):
        info.targets_nat = True
    elif gw_unknown or nat_unknown:
        info.unknown_target = True
    else:
        # target is some other gateway (TGW / peering / VPC endpoint) -> out of model
        info.unknown_target = True


def _route_tables(idx: RecordIndex) -> dict[str, _RtInfo]:
    rtinfo: dict[str, _RtInfo] = {}
    for rt in idx.of_type("aws_route_table"):
        info = _RtInfo()
        routes = rt.values.get("route")  # read structure directly; resolve() over-flags lists
        if isinstance(routes, list):
            for i, route in enumerate(routes):
                if isinstance(route, dict):
                    _classify_route(rt, idx, "route", route, i, info)
        rtinfo[rt.config_address] = info
    # standalone aws_route resources
    for r in idx.of_type("aws_route"):
        for rt in idx.targets_of_type(r, "route_table_id", "aws_route_table"):
            info = rtinfo.setdefault(rt.config_address, _RtInfo())
            cb = r.resolve("destination_cidr_block")
            v6 = r.resolve("destination_ipv6_cidr_block")
            pseudo = {
                "cidr_block": cb.value_or(""),
                "ipv6_cidr_block": v6.value_or(""),
                "gateway_id": r.resolve("gateway_id").value_or(""),
                "nat_gateway_id": r.resolve("nat_gateway_id").value_or(""),
            }
            _classify_route_standalone(r, idx, pseudo, info)
    return rtinfo


def _classify_route_standalone(rec: ResourceRecord, idx: RecordIndex, route: dict[str, Any], info: _RtInfo) -> None:
    cb = route.get("cidr_block") or ""
    v6 = route.get("ipv6_cidr_block") or ""
    if cb != "0.0.0.0/0" and v6 != "::/0":
        return
    info.has_default = True
    igw = idx.targets_of_type(rec, "gateway_id", "aws_internet_gateway")
    nat = idx.targets_of_type(rec, "nat_gateway_id", "aws_nat_gateway")
    gw = str(route.get("gateway_id") or "")
    if gw.startswith("igw-") or igw:
        info.targets_igw = True
    elif gw.startswith("eigw-"):
        pass
    elif str(route.get("nat_gateway_id") or "").startswith("nat-") or nat:
        info.targets_nat = True
    else:
        info.unknown_target = True


def compute_publicness(idx: RecordIndex) -> dict[str, SubnetInfo]:
    rtinfo = _route_tables(idx)

    subnet_rt: dict[str, str] = {}
    for assoc in idx.of_type("aws_route_table_association"):
        subnets = idx.targets_of_type(assoc, "subnet_id", "aws_subnet")
        rts = idx.targets_of_type(assoc, "route_table_id", "aws_route_table")
        if subnets and rts:
            subnet_rt[subnets[0].config_address] = rts[0].config_address

    main_rt: dict[str, str] = {}
    for m in idx.of_type("aws_main_route_table_association"):
        vpcs = idx.targets_of_type(m, "vpc_id", "aws_vpc")
        rts = idx.targets_of_type(m, "route_table_id", "aws_route_table")
        if vpcs and rts:
            main_rt[vpcs[0].config_address] = rts[0].config_address

    default_vpcs = {r.config_address for r in idx.of_type("aws_default_vpc")}

    out: dict[str, SubnetInfo] = {}
    for subnet in idx.of_type("aws_subnet", "aws_default_subnet"):
        vpc_targets = idx.targets_of_type(subnet, "vpc_id", "aws_vpc", "aws_default_vpc")
        vpc = vpc_targets[0].config_address if vpc_targets else None
        cidr = subnet.resolve("cidr_block").value_or(None)

        if subnet.type == "aws_default_subnet" or (vpc in default_vpcs):
            out[subnet.config_address] = SubnetInfo(
                subnet.config_address, vpc, cidr, True, Confidence.DEFAULT,
                "default VPC subnet (public posture)",
            )
            continue

        rt_addr = subnet_rt.get(subnet.config_address) or (main_rt.get(vpc) if vpc else None)
        if rt_addr and rt_addr in rtinfo:
            info = rtinfo[rt_addr]
            if info.public and not info.unknown_target:
                out[subnet.config_address] = SubnetInfo(
                    subnet.config_address, vpc, cidr, True, Confidence.KNOWN,
                    "public: route 0.0.0.0/0 -> internet gateway",
                )
            elif info.public:  # unknown route target -> conservatively public
                out[subnet.config_address] = SubnetInfo(
                    subnet.config_address, vpc, cidr, True, Confidence.AFTER_APPLY,
                    "default-route target unknown -> assumed internet gateway",
                )
            elif info.nat_only:
                out[subnet.config_address] = SubnetInfo(
                    subnet.config_address, vpc, cidr, False, Confidence.KNOWN,
                    "private: default route -> NAT gateway (egress only)",
                )
            else:  # has a resolved RT with no default-to-igw route
                out[subnet.config_address] = SubnetInfo(
                    subnet.config_address, vpc, cidr, False, Confidence.KNOWN,
                    "private: no 0.0.0.0/0 -> igw route",
                )
        else:
            # No resolvable route table. We must NOT assert closure from an absence of
            # evidence (an IGW or main-RT route may live in another module/state). Always
            # conservatively public with degraded confidence (DESIGN.md §2.4, §3.6).
            out[subnet.config_address] = SubnetInfo(
                subnet.config_address, vpc, cidr, True, Confidence.AFTER_APPLY,
                "route table unresolved -> conservatively public",
            )
    return out
