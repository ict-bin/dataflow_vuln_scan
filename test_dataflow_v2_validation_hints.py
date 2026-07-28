from __future__ import annotations

from app.dataflow_v2.analysis import TaintAnalysisCallbacks, _collect_validation_hints, _format_validation_hint
from app.dataflow_v2.models import FunctionRecord, PropagationRecord, Validation


def test_format_validation_hint_includes_owner_function():
    hint = _format_validation_hint(
        Validation(
            line=9599,
            kind="length_check",
            target="v142",
            summary="checks authenticator length",
            function_file="1/output/libipsec.c",
            function_name="IPSEC_AH_HandleInputPktV4",
        )
    )

    assert "1/output/libipsec.c::IPSEC_AH_HandleInputPktV4" in hint
    assert "@L9599" in hint
    assert "v142 - checks authenticator length" in hint


def test_format_validation_hint_falls_back_without_owner():
    hint = _format_validation_hint(
        Validation(
            line=0,
            kind="null_check",
            target="return",
            summary="checks return value",
        )
    )

    assert "(unknown)" in hint
    assert "@L?" in hint


def test_collect_validation_hints_includes_caller_context_for_callsites():
    func = FunctionRecord(
        file="1/output/libipsec.c",
        name="IPSEC_AH_HandleInputPktV4",
        signature="void f()",
        start_line=9243,
        end_line=10159,
    )
    pre_validations = [
        Validation(
            line=9697,
            kind="bounds_check",
            target="*a3",
            summary="ensures auth offset is not below ip header length",
            function_file=func.file,
            function_name=func.name,
            function_start_line=func.start_line,
            function_end_line=func.end_line,
        )
    ]
    props = [
        PropagationRecord(
            source_func_id=func.func_id,
            source_taint_name="a2",
            target_taint_name="contiguous_ptr",
            target_function="MBUF_MakeMemoryContinuous_fl",
            target_file="1/output/mbuf.c",
            call_line=9440,
            description="a2 is passed to create contiguous memory",
            validations=[
                Validation(
                    line=9919,
                    kind="length_check",
                    target="v63",
                    summary="caps copy length to 2048",
                    function_file=func.file,
                    function_name=func.name,
                )
            ],
        ),
        PropagationRecord(
            source_func_id=func.func_id,
            source_taint_name="spi",
            target_taint_name="lookup_key",
            target_function="VOS_AVL3_Find",
            call_line=0,
            description="spi is used as AVL lookup key",
        ),
    ]

    validation_hints, function_hints = _collect_validation_hints(
        pre_validations,
        props,
        current_func=func,
    )

    assert any("1/output/libipsec.c::IPSEC_AH_HandleInputPktV4 @L9697" in hint for hint in validation_hints)
    assert any(
        "1/output/libipsec.c::IPSEC_AH_HandleInputPktV4 @L9440 -> MBUF_MakeMemoryContinuous_fl" in hint
        and "[callee: 1/output/mbuf.c]" in hint
        for hint in function_hints
    )
    assert any(
        "1/output/libipsec.c::IPSEC_AH_HandleInputPktV4 @L? -> VOS_AVL3_Find" in hint
        for hint in function_hints
    )


def test_build_prompt_uses_structured_validation_sections():
    cb = object.__new__(TaintAnalysisCallbacks)
    cb.source_root = "/src/root"
    func = FunctionRecord(
        file="1/output/libipsec.c",
        name="IPSEC_AH_HandleInputPktV4",
        signature="void f()",
        start_line=9243,
        end_line=10159,
    )
    prompt = cb._build_prompt(
        func,
        "int demo(void) { return 0; }",
        type("TP", (), {"names": ["a1"], "signature": "a1", "positions": [0]})(),
        [
            Validation(
                line=9697,
                kind="bounds_check",
                target="*a3",
                summary="ensures auth offset is not below ip header length",
                function_file=func.file,
                function_name=func.name,
                function_start_line=func.start_line,
                function_end_line=func.end_line,
            )
        ],
    )

    assert "前置校验摘要（上游链路）" in prompt
    assert "当前函数内相关校验点" in prompt
    assert "可能相关的调用点" in prompt
    assert "1/output/libipsec.c::IPSEC_AH_HandleInputPktV4 @L9697" in prompt
