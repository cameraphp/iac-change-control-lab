"""iac-change-control-lab: a local, fixture-driven policy-and-evidence gate.

Lab only. It evaluates synthetic, Terraform-plan-like JSON fixtures and writes local evidence.
It never contacts a cloud provider, never runs Terraform, and never changes infrastructure.
"""

__version__ = "0.1.0"
