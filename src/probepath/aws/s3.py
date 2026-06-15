"""S3 public-exposure evaluator (DESIGN.md §2.9).

S3 is NOT in the VPC graph; its exposure is an identity/policy question. A bucket is
internet-exposed iff Block Public Access does not fully block it AND (a public bucket policy
OR a public ACL grants anonymous access). Any unknown field => assume public.

This is a *network/policy exposure* signal, not an IAM-authorization verdict.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from ..ingest.normalized import RecordIndex, ResourceRecord
from ..model.enums import Confidence, ConservativeReason

_BPA_FLAGS = ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")


@dataclass
class S3Verdict:
    bucket_addr: str
    exposed: bool
    confidence: Confidence
    reason: ConservativeReason | None
    rationale: str


def _principal_is_anonymous(principal: object) -> bool:
    """Anonymous iff Principal is exactly "*" or {"AWS": "*"} (or a list containing "*").
    A wildcard *account* ARN like "arn:aws:iam::*:root" is NOT anonymous (it's an account
    scope), so we match the literal "*" only — never substring."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        values = aws if isinstance(aws, list) else [aws]
        return any(v == "*" for v in values)
    return False


def _policy_is_public(policy_value: object) -> bool:
    """A statement with Effect:Allow + Principal "*" and no SourceIp/SourceVpc/account scoping."""
    if isinstance(policy_value, str):
        try:
            policy = json.loads(policy_value)
        except json.JSONDecodeError:
            return True  # unparseable -> conservative
    elif isinstance(policy_value, dict):
        policy = policy_value
    else:
        return False
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        if not _principal_is_anonymous(st.get("Principal")):
            continue
        cond = st.get("Condition") or {}
        cond_str = json.dumps(cond)
        if any(scope in cond_str for scope in ("SourceVpc", "aws:SourceVpce", "aws:PrincipalAccount", "aws:SourceAccount")):
            continue  # scoped to a VPC/account -> not anonymous-internet-public
        return True
    return False


def evaluate_s3(idx: RecordIndex) -> list[S3Verdict]:
    verdicts: list[S3Verdict] = []
    buckets = idx.of_type("aws_s3_bucket")
    pab_by_bucket: dict[str, ResourceRecord] = {}
    for pab_rec in idx.of_type("aws_s3_bucket_public_access_block"):
        for b in idx.targets_of_type(pab_rec, "bucket", "aws_s3_bucket"):
            pab_by_bucket[b.config_address] = pab_rec
    policy_by_bucket: dict[str, ResourceRecord] = {}
    for pol_rec in idx.of_type("aws_s3_bucket_policy"):
        for b in idx.targets_of_type(pol_rec, "bucket", "aws_s3_bucket"):
            policy_by_bucket[b.config_address] = pol_rec
    acl_by_bucket: dict[str, ResourceRecord] = {}
    for acl_rec in idx.of_type("aws_s3_bucket_acl"):
        for b in idx.targets_of_type(acl_rec, "bucket", "aws_s3_bucket"):
            acl_by_bucket[b.config_address] = acl_rec

    for bucket in buckets:
        # 1. Block Public Access closes the surface only if ALL four flags are explicitly true & known.
        pab = pab_by_bucket.get(bucket.config_address)
        fully_blocked = False
        if pab is not None:
            flags = [pab.resolve(f) for f in _BPA_FLAGS]
            fully_blocked = all(f.known and f.value is True for f in flags)
        if fully_blocked:
            continue  # provably not public

        # 2. Public via bucket policy?
        public = False
        conf = Confidence.KNOWN
        reason: ConservativeReason | None = None
        rationale = ""
        pol = policy_by_bucket.get(bucket.config_address)
        if pol is not None:
            pres = pol.resolve("policy")
            if pres.is_unknown:
                public, conf, reason = True, Confidence.AFTER_APPLY, ConservativeReason.AFTER_APPLY_VALUE
                rationale = "bucket policy is known-after-apply -> assumed public"
            elif pres.known and _policy_is_public(pres.value):
                public, rationale = True, "bucket policy allows Principal:* with no source scoping"

        # 3. Public via ACL?
        acl = acl_by_bucket.get(bucket.config_address)
        for rec, attr in ((acl, "acl"), (bucket, "acl")):
            if public or rec is None:
                continue
            a = rec.resolve(attr)
            if a.known and a.value in ("public-read", "public-read-write", "authenticated-read"):
                public, rationale = True, f"bucket ACL is '{a.value}' (anonymous/any-AWS access)"

        if public:
            partial_bpa = pab is not None and not fully_blocked
            if partial_bpa and conf == Confidence.KNOWN:
                rationale += " (Block Public Access present but not fully enabled)"
            verdicts.append(S3Verdict(bucket.config_address, True, conf, reason, rationale))
    return verdicts
