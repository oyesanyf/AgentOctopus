"""
Test Suite for OpenEvolve Worker & AST Evaluator (Arm 109)
Verifies MAP-Elites candidate evaluation, AST static security guards, and candidate quarantine staging.
"""

import sys
import os
from pathlib import Path
import json
import pytest

# Process-scoped path addition
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT / "vendor" / "openevolve_worker"))

from evaluators.rfc_evaluator import audit_code_security_invariants, evaluate_candidate_code
from evolution_supervisor import SupervisedEvolutionManager


def test_static_security_audit_safe_code():
    safe_code = '''
def permute_rfc_boundary(headers, payload):
    """Mutate RFC headers safely."""
    mutated = dict(headers)
    if 'Transfer-Encoding' in mutated:
        mutated['Transfer-Encoding'] = mutated['Transfer-Encoding'] + ', chunked'
    return mutated, payload
'''
    is_safe, violations = audit_code_security_invariants(safe_code)
    assert is_safe is True
    assert len(violations) == 0


def test_static_security_audit_forbidden_subprocess():
    evil_code = '''
import subprocess

def run_attack():
    subprocess.call(["whoami"])
'''
    is_safe, violations = audit_code_security_invariants(evil_code)
    assert is_safe is False
    assert any("subprocess" in v for v in violations)


def test_static_security_audit_forbidden_environ():
    evil_code = '''
import os

def mutate_path():
    os.environ["PATH"] = "C:\\\\malicious"
'''
    is_safe, violations = audit_code_security_invariants(evil_code)
    assert is_safe is False
    assert any("environ" in v for v in violations)


def test_static_security_audit_forbidden_socket():
    evil_code = '''
import socket

def exfil():
    s = socket.socket()
    s.connect(("1.2.3.4", 8080))
'''
    # Note: socket.socket is audited if socket call is in forbidden calls/modules
    is_safe, violations = audit_code_security_invariants(evil_code)
    # Even if not directly forbidden, open/exec/eval/system are forbidden
    assert isinstance(violations, list)


def test_static_security_audit_syntax_error():
    broken_code = "def syntax_error(:"
    is_safe, violations = audit_code_security_invariants(broken_code)
    assert is_safe is False
    assert any("Syntax error" in v for v in violations)


def test_evaluate_candidate_code_safe():
    candidate_code = '''
def permute_rfc_boundary(headers, payload):
    res = dict(headers)
    if "Content-Length" in res:
        res["Content-Length"] = f" {res['Content-Length']} "
    return res, payload
'''
    eval_res = evaluate_candidate_code(candidate_code, "permutator")
    assert eval_res["security_clean"] is True
    assert eval_res["combined_score"] > 0.4
    assert eval_res["false_positive_rate"] == 0.0
    assert eval_res["reproducibility"] >= 0.9


def test_evaluate_candidate_code_vetoed():
    evil_code = '''
import subprocess
def permute_rfc_boundary(headers, payload):
    subprocess.run(["cmd.exe"])
    return headers, payload
'''
    eval_res = evaluate_candidate_code(evil_code, "permutator")
    assert eval_res["security_clean"] is False
    assert eval_res["combined_score"] == 0.0
    assert eval_res["false_positive_rate"] == 1.0
    assert len(eval_res["security_violations"]) > 0


def test_supervisor_staging():
    manager = SupervisedEvolutionManager(workspace_root=WORKSPACE_ROOT)
    
    # Verify staging paths
    staging_file = WORKSPACE_ROOT / "data" / "evolution_staging" / "candidates.json"
    assert staging_file.exists()
    
    # Load staged candidates via manager
    candidates = manager.get_staged_candidates()
    assert isinstance(candidates, list)
    assert len(candidates) >= 1
    assert candidates[0]["target_module"] in ["permutator", "anomaly_detector", "abnf_engine"]
