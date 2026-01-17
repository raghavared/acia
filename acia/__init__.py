"""
ACIA - Autonomous Code Improvement Agent

A foundation model for autonomous code analysis, improvement, and deployment.
"""

__version__ = "0.1.0"
__author__ = "ACIA Team"

from acia.core.orchestrator import Orchestrator
from acia.core.config import ACIAConfig

__all__ = ["Orchestrator", "ACIAConfig", "__version__"]
