"""ALB / NLB resolution (DESIGN.md §2.7).

A load balancer is a relay node. Two segments must both pass for an internet->target path:
INTERNET->LB (scheme internet-facing, public subnet, SG admits or SG-less NLB) and LB->target
(target SG admits the LB / the original client). The SG checks are applied by the builder;
this module just resolves the topology.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..ingest.normalized import RecordIndex
from ..model.ports import PortSet


@dataclass
class Listener:
    port: int | None
    port_unknown: bool
    tg_addrs: list[str] = field(default_factory=list)


@dataclass
class LbModel:
    addr: str
    scheme: str  # "internet-facing" | "internal"
    scheme_unknown: bool
    lb_type: str  # "application" | "network"
    subnet_addrs: list[str] = field(default_factory=list)
    sg_addrs: list[str] = field(default_factory=list)
    has_sg: bool = True  # NLBs may have none -> all client traffic reaches listeners
    listeners: list[Listener] = field(default_factory=list)

    @property
    def is_internet_facing(self) -> bool:
        return self.scheme == "internet-facing" or self.scheme_unknown

    def listener_ports(self) -> PortSet:
        out = PortSet.empty()
        for ls in self.listeners:
            if ls.port_unknown or ls.port is None:
                return PortSet.all()
            out = out.union(PortSet.single(ls.port))
        return out


@dataclass
class TargetGroup:
    addr: str
    port: int | None
    port_unknown: bool
    target_type: str
    preserve_client_ip: bool  # NLB: target sees original client IP (default true for instance/TCP)
    target_addrs: list[str] = field(default_factory=list)


def collect_load_balancers(idx: RecordIndex) -> dict[str, LbModel]:
    lbs: dict[str, LbModel] = {}
    for rec in idx.of_type("aws_lb", "aws_alb", "aws_elb"):
        internal = rec.resolve("internal")
        scheme_val = rec.resolve("scheme")
        if scheme_val.known and scheme_val.value:
            scheme = str(scheme_val.value)
            scheme_unknown = False
        elif internal.known:
            scheme = "internal" if internal.value else "internet-facing"
            scheme_unknown = False
        else:
            scheme = "internet-facing"
            scheme_unknown = True
        lb_type = str(rec.resolve("load_balancer_type").value_or("application"))
        sg_addrs = [t.config_address for t in idx.targets_of_type(rec, "security_groups", "aws_security_group")]
        sg_res = rec.resolve("security_groups")
        has_sg = bool(sg_addrs) or sg_res.is_unknown or (sg_res.known and bool(sg_res.value))
        if lb_type == "network" and not sg_addrs and not sg_res.is_unknown:
            has_sg = False  # SG-less NLB: all client traffic reaches the listeners
        subnet_addrs = [t.config_address for t in idx.targets_of_type(rec, "subnets", "aws_subnet")]
        subnet_addrs += [
            t.config_address for t in idx.targets_of_type(rec, "subnet_mapping", "aws_subnet")
        ]
        lbs[rec.config_address] = LbModel(
            addr=rec.config_address,
            scheme=scheme,
            scheme_unknown=scheme_unknown,
            lb_type=lb_type,
            subnet_addrs=subnet_addrs,
            sg_addrs=sg_addrs,
            has_sg=has_sg,
        )

    for rec in idx.of_type("aws_lb_listener", "aws_alb_listener"):
        lb_targets = idx.targets_of_type(rec, "load_balancer_arn", "aws_lb", "aws_alb", "aws_elb")
        port_res = rec.resolve("port")
        tg_addrs = [
            t.config_address
            for t in idx.targets_of_type(rec, "default_action", "aws_lb_target_group")
        ]
        listener = Listener(
            port=int(port_res.value) if port_res.known and port_res.value is not None else None,
            port_unknown=port_res.is_unknown,
            tg_addrs=tg_addrs,
        )
        for lb in lb_targets:
            if lb.config_address in lbs:
                lbs[lb.config_address].listeners.append(listener)
    return lbs


def collect_target_groups(idx: RecordIndex) -> dict[str, TargetGroup]:
    tgs: dict[str, TargetGroup] = {}
    for rec in idx.of_type("aws_lb_target_group", "aws_alb_target_group"):
        port = rec.resolve("port")
        pci = rec.resolve("preserve_client_ip")
        # AWS default: enabled for NLB instance/TCP targets. If unknown/unset, assume True
        # (the conservative direction for the target-SG check below).
        preserve = bool(pci.value) if pci.known else True
        tgs[rec.config_address] = TargetGroup(
            addr=rec.config_address,
            port=int(port.value) if port.known and port.value is not None else None,
            port_unknown=port.is_unknown,
            target_type=str(rec.resolve("target_type").value_or("instance")),
            preserve_client_ip=preserve,
        )
    for rec in idx.of_type("aws_lb_target_group_attachment", "aws_alb_target_group_attachment"):
        for tg in idx.targets_of_type(rec, "target_group_arn", "aws_lb_target_group", "aws_alb_target_group"):
            targets = idx.targets_of_type(rec, "target_id", "aws_instance", "aws_lb", "aws_alb")
            if tg.config_address in tgs:
                tgs[tg.config_address].target_addrs.extend(t.config_address for t in targets)
    return tgs
