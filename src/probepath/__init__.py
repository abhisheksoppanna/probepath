"""probepath — prove whether an internet-to-database attack path exists in Terraform.

probepath statically analyzes Terraform for AWS and decides whether a network path
from an untrusted source (the internet) to a sensitive sink (RDS, ElastiCache, ...) is
*possible* under AWS's documented VPC routing and filtering semantics — before you apply.

It is a reachability reasoner, not a security oracle: ``UNREACHABLE`` is the only verdict
that suppresses a finding, and it is emitted *only* when the model has complete, known
information proving closure. Unknowns always widen reachability. See DESIGN.md §1.1.
"""

__version__ = "0.1.0"
