#!/usr/bin/env python3
"""
CAPSTONE SecAgg Forward Privacy Audit - Main Orchestrator
Entry point for the Python server-side security audit.
"""

import yaml
import sys
import os
from aggregator import create_auditor, SecurityAuditor


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def main():
    """Main entry point for the security audit."""
    # Determine config path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'config.yaml')
    
    if not os.path.exists(config_path):
        print(f"Error: Config file not found at {config_path}")
        sys.exit(1)
    
    # Load configuration
    config = load_config(config_path)
    
    # Create and run auditor
    auditor = create_auditor(config)
    results = auditor.run_full_audit()
    
    # Export results
    output_path = os.path.join(script_dir, 'audit_results.json')
    auditor.export_results(results, output_path)
    
    # Exit with appropriate code
    # Exit 0 if both audits completed (regardless of forward privacy result)
    sys.exit(0)


if __name__ == '__main__':
    main()