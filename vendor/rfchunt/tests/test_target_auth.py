import pytest
from mcp_server import TargetAuthorizationGate

def test_target_auth():
    # allowed
    TargetAuthorizationGate.check_auth("127.0.0.1", payload_len=1024)
    TargetAuthorizationGate.check_auth("localhost", payload_len=1024)
    
    with pytest.raises(PermissionError):
        TargetAuthorizationGate.check_auth("evil.com", payload_len=1024)
        
    with pytest.raises(ValueError):
        TargetAuthorizationGate.check_auth("127.0.0.1", payload_len=100_000_000)

def test_baseline_subtraction():
    from anomaly_detector import AnomalyDetector
    # Should not trigger anomaly if baseline matches exactly
    raw = b"HTTP/1.1 200 OK\\r\\n\\r\\nfoo"
    baseline = b"HTTP/1.1 200 OK\\r\\n\\r\\nfoo"
    anoms = AnomalyDetector.analyze_response(raw, baseline_response=baseline)
    assert len(anoms) == 0
