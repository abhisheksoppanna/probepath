"""Map Terraform resource types to node kinds, and define the default sink catalog.

A *sink* is a resource probepath treats as sensitive (a database, cache, warehouse, search
domain, or sensitive bucket). The catalog is configurable; these are the built-in defaults
(DESIGN.md §2.8, §4.6).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..model.enums import NodeKind

# Engine -> default port, when the resource doesn't state ``port`` explicitly.
_ENGINE_PORTS: dict[str, int] = {
    "postgres": 5432,
    "aurora-postgresql": 5432,
    "mysql": 3306,
    "mariadb": 3306,
    "aurora": 3306,
    "aurora-mysql": 3306,
    "sqlserver-ex": 1433,
    "sqlserver-se": 1433,
    "sqlserver-web": 1433,
    "sqlserver-ee": 1433,
    "oracle-ee": 1521,
    "oracle-se2": 1521,
}


@dataclass(frozen=True)
class SinkSpec:
    kind: NodeKind
    label: str
    default_port: int


SINK_TYPES: dict[str, SinkSpec] = {
    "aws_db_instance": SinkSpec(NodeKind.RDS, "RDS", 5432),
    "aws_rds_cluster": SinkSpec(NodeKind.RDS, "RDS (Aurora)", 5432),
    "aws_rds_cluster_instance": SinkSpec(NodeKind.RDS, "RDS (Aurora instance)", 5432),
    "aws_docdb_cluster": SinkSpec(NodeKind.RDS, "DocumentDB", 27017),
    "aws_elasticache_cluster": SinkSpec(NodeKind.ELASTICACHE, "ElastiCache", 6379),
    "aws_elasticache_replication_group": SinkSpec(NodeKind.ELASTICACHE, "ElastiCache (Redis)", 6379),
    "aws_redshift_cluster": SinkSpec(NodeKind.REDSHIFT, "Redshift", 5439),
    "aws_opensearch_domain": SinkSpec(NodeKind.OPENSEARCH, "OpenSearch", 443),
    "aws_elasticsearch_domain": SinkSpec(NodeKind.OPENSEARCH, "Elasticsearch", 443),
}

# Compute that can originate a pivot (be compromised, then reach further in).
COMPUTE_TYPES: dict[str, NodeKind] = {
    "aws_instance": NodeKind.ENI,
    "aws_network_interface": NodeKind.ENI,
}

LB_TYPES = {"aws_lb", "aws_alb", "aws_elb"}


def is_sink_type(tf_type: str) -> bool:
    return tf_type in SINK_TYPES


def sink_spec(tf_type: str) -> SinkSpec | None:
    return SINK_TYPES.get(tf_type)


def engine_default_port(engine: str | None, fallback: int) -> int:
    if not engine:
        return fallback
    return _ENGINE_PORTS.get(str(engine).lower(), fallback)
