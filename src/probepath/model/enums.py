"""The fixed vocabulary of probepath. These enums are the trust contract (DESIGN.md §1.1).

They live in ``model`` so every layer (ingest, aws, engine, findings, report) can import
them without violating the ``ingest -> model -> aws -> engine -> findings -> report``
layering rule.
"""

from __future__ import annotations

from enum import Enum


class Verdict(Enum):
    """A reachability verdict on the lattice ``UNREACHABLE < POTENTIALLY_REACHABLE < REACHABLE``.

    ``UNREACHABLE`` is the *only* verdict that suppresses a finding, and it is emitted only
    when the model has complete, known information proving closure. Unknowns never move a
    verdict *down* toward ``UNREACHABLE`` — that is the cardinal rule (DESIGN.md §1.1).
    """

    REACHABLE = "reachable"
    POTENTIALLY_REACHABLE = "potentially_reachable"
    UNREACHABLE = "unreachable"

    @property
    def rank(self) -> int:
        return {
            Verdict.UNREACHABLE: 0,
            Verdict.POTENTIALLY_REACHABLE: 1,
            Verdict.REACHABLE: 2,
        }[self]

    def weakest(self, other: Verdict) -> Verdict:
        """A path's verdict is its weakest hop; combine two hop verdicts (min on the lattice)."""
        return self if self.rank <= other.rank else other

    def strongest(self, other: Verdict) -> Verdict:
        """Across alternate paths to a sink, the sink takes the strongest (max) verdict."""
        return self if self.rank >= other.rank else other


class Confidence(Enum):
    """How well-known is the input behind an edge. The confidence of an edge is the ``min()``
    of its contributing inputs; a single ``AFTER_APPLY`` input caps any path through it at
    ``POTENTIALLY_REACHABLE`` (DESIGN.md §4.2)."""

    KNOWN = "known"
    DEFAULT = "default"  # a known AWS default was applied (still trustworthy)
    PARSED_HCL = "parsed_hcl"  # came from un-evaluated HCL — degraded
    AFTER_APPLY = "after_apply"  # value is "known after apply"
    MISSING = "missing"  # referenced resource/attribute absent from the input

    @property
    def is_known(self) -> bool:
        return self in (Confidence.KNOWN, Confidence.DEFAULT)


class ConservativeReason(Enum):
    """Why a verdict is ``POTENTIALLY_REACHABLE`` rather than proven. Rolls up to the two
    user-facing classes ``UNKNOWN_INPUT`` and ``OUT_OF_MODEL`` (DESIGN.md §1.1)."""

    AFTER_APPLY_VALUE = "after_apply_value"
    MISSING_RESOURCE = "missing_resource"
    UNPARSEABLE_HCL = "unparseable_hcl"
    UNKNOWN_EXPANSION = "unknown_expansion"  # count/for_each cardinality not known
    MANAGED_PREFIX_LIST = "managed_prefix_list"  # contents not in the plan
    REMOTE_STATE_REF = "remote_state_ref"  # cross-account / terraform_remote_state
    UNSUPPORTED_RESOURCE_TYPE = "unsupported_resource_type"  # out-of-model on the path
    NACL_RETURN_UNKNOWN = "nacl_return_unknown"

    @property
    def user_class(self) -> str:
        out_of_model = {ConservativeReason.UNSUPPORTED_RESOURCE_TYPE}
        return "OUT_OF_MODEL" if self in out_of_model else "UNKNOWN_INPUT"


class ReachabilityClass(Enum):
    """The mechanism by which a sink is exposed."""

    NETWORK = "network"  # VPC routing/filtering path (the graph)
    IDENTITY = "identity"  # policy/ACL exposure (S3, OpenSearch access policy)


class Direction(Enum):
    FORWARD = "forward"
    RETURN = "return"


class NodeKind(Enum):
    INTERNET_SOURCE = "internet_source"
    INTERNET_GATEWAY = "internet_gateway"
    NAT_GATEWAY = "nat_gateway"
    EGRESS_ONLY_IGW = "egress_only_igw"
    VPC = "vpc"
    SUBNET = "subnet"
    SECURITY_GROUP = "security_group"
    NETWORK_ACL = "network_acl"
    ENI = "eni"  # EC2 instance / ENI / ECS task / Lambda-in-VPC compute
    LOAD_BALANCER = "load_balancer"
    TARGET_GROUP = "target_group"
    RDS = "rds"
    ELASTICACHE = "elasticache"
    REDSHIFT = "redshift"
    OPENSEARCH = "opensearch"
    S3_BUCKET = "s3_bucket"
    VPC_ENDPOINT = "vpc_endpoint"
    PLACEHOLDER = "placeholder"  # unmodeled / external / remote-state target


class EdgeKind(Enum):
    INTERNET_TO_IGW = "internet_to_igw"
    IGW_TO_HOST = "igw_to_host"
    IGW_TO_LB = "igw_to_lb"
    IGW_TO_SINK = "igw_to_sink"  # directly-public RDS etc.
    LB_TO_TARGET = "lb_to_target"
    INTRA_VPC = "intra_vpc"  # host -> in-VPC node via SG (incl. SG-to-SG pivots)
    EGRESS = "egress"  # sink/host -> internet (exfil finding class)
    PLACEHOLDER = "placeholder"  # edge into/out of an unmodeled node
