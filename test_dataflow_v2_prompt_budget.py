from app.dataflow_v2.analysis import _truncate_text_by_estimated_tokens


def test_truncate_text_by_estimated_tokens_uses_token_budget():
    text = "a" * 89999
    assert _truncate_text_by_estimated_tokens(text, max_tokens=30000) == text


def test_truncate_text_by_estimated_tokens_truncates_at_token_budget():
    text = "a" * 90001
    out = _truncate_text_by_estimated_tokens(text, max_tokens=30000)
    assert len(out) == 90000
    assert out == "a" * 90000
