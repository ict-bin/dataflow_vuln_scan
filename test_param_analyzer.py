"""Local test for param_analyzer and scheduling.

Creates a temporary C project with various parameter passing patterns,
then verifies the analyzer correctly classifies each followup.
"""
from __future__ import annotations

import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.param_analyzer import (
    analyze,
    FollowupSemantics,
    ParamSemantics,
    _classify_arg,
    _lookup_param_decl,
    mark_ambiguous,
)


def _write_project(root: Path) -> None:
    """Create a realistic C project under root with various parameter patterns."""
    src = root / "src"
    os.makedirs(src, exist_ok=True)

    (src / "network.c").write_text(textwrap.dedent("""\
        // Network input handler
        #include "types.h"

        void handle_packet(Packet* pkt, int flags) {
            // pkt: non-const pointer → may modify
            // flags: int → value type

            validate_packet(pkt);           // P0: &pkt or pkt pointer, may modify
            log_event(flags);               // P2: int value, isolated
            unsigned len = pkt->len;
            route_packet(pkt, len);         // P0: pkt pointer, may modify
            stats.count++;                  // P2: stats is global, but count is value
        }

        int validate_packet(Packet* pkt) {
            if (!pkt) return -1;
            if (pkt->len > MAX_SIZE) return -2;
            return 0;
        }

        void route_packet(Packet* pkt, unsigned len) {
            // forward to dispatch
            send_packet(pkt);
        }
    """))

    (src / "types.h").write_text(textwrap.dedent("""\
        #ifndef TYPES_H
        #define TYPES_H

        #define MAX_SIZE 65536

        typedef struct {
            unsigned len;
            char* data;
        } Packet;

        struct Stats {
            unsigned count;
        };
        extern struct Stats stats;

        #endif
    """))

    (src / "utils.c").write_text(textwrap.dedent("""\
        #include "types.h"
        #include <stdio.h>

        void log_event(int code) {
            printf("event: %d\n", code);
        }

        void send_packet(const Packet* pkt) {
            // const pointer → isolated (P2)
        }

        void modify_buf(char* buf) {
            // non-const pointer → P0
            buf[0] = 'X';
        }

        void read_buf(const char* buf) {
            // const pointer → P2
            printf("%s\n", buf);
        }

        int calc_checksum(char* data, int len) {
            // data may be modified, len is value → P0
            int sum = 0;
            for (int i = 0; i < len; i++) sum += data[i];
            return sum;
        }
    """))

    (src / "macros.c").write_text(textwrap.dedent("""\
        #define CHECK_NULL(p) if (!(p)) return
        #define MAX_BUF 4096

        void process_buf(char* buf, size_t n) {
            CHECK_NULL(buf);
            if (n <= MAX_BUF) {
                transform_buf(buf, n);
            }
        }
    """))


class TestClassifyArg(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = Path(tempfile.mkdtemp(prefix="dvs_test_"))
        _write_project(cls.project)
        cls.source_root = str(cls.project / "src")

    def test_value_literal(self):
        """42 → value type, isolated"""
        p = _classify_arg("42", arg_index=1, source_root=self.source_root)
        self.assertTrue(p.is_value_type)
        self.assertFalse(p.needs_sequential)

    def test_simple_pointer_with_decl(self):
        """'buf' where declaration is 'char* buf' → pointer, not const"""
        p = _classify_arg(
            "buf", arg_index=1,
            func_name="modify_buf",
            hint_file="utils.c",
            source_root=self.source_root,
        )
        self.assertTrue(p.is_pointer)
        self.assertFalse(p.is_const_qualified)
        self.assertTrue(p.needs_sequential)

    def test_const_pointer(self):
        """'pkt' where declaration is 'const Packet* pkt' → const pointer"""
        p = _classify_arg(
            "pkt", arg_index=1,
            func_name="send_packet",
            hint_file="utils.c",
            source_root=self.source_root,
        )
        self.assertTrue(p.is_pointer)
        self.assertTrue(p.is_const_qualified)
        self.assertFalse(p.needs_sequential)

    def test_ambiguous_struct_field(self):
        """'pkt->len' where pkt is Packet* → pointer access"""
        p = _classify_arg(
            "pkt->len", arg_index=1,
            source_root=self.source_root,
        )
        self.assertTrue(p.is_pointer)
        self.assertFalse(p.is_const_qualified)
        self.assertTrue(p.needs_sequential)

    def test_address_of(self):
        """'&value' → taken address, may modify"""
        p = _classify_arg(
            "&value", arg_index=1,
            source_root=self.source_root,
        )
        self.assertTrue(p.is_pointer)
        self.assertFalse(p.is_const_qualified)
        self.assertTrue(p.needs_sequential)

    def test_no_source_root_value(self):
        """Simple name without source_root → value type (best guess)"""
        p = _classify_arg("len", arg_index=1, source_root="")
        self.assertTrue(p.is_value_type)
        self.assertFalse(p.needs_sequential)

    def test_no_source_root_pointer_default(self):
        """Simple name with valid source_root but no decl → pointer (conservative)"""
        p = _classify_arg(
            "buf", arg_index=1,
            func_name="non_existent_func",
            hint_file="utils.c",
            source_root=self.source_root,
        )
        # No decl found → conservative pointer
        self.assertTrue(p.is_pointer)
        self.assertTrue(p.needs_sequential)


class TestAnalyzeFollowup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = Path(tempfile.mkdtemp(prefix="dvs_test_"))
        _write_project(cls.project)
        cls.source_root = str(cls.project / "src")

    def test_validate_packet_sequential(self):
        """validate_packet(pkt) where pkt is Packet* → P0, needs_sequential"""
        sem = analyze(
            "validate_packet", "network.c",
            tainted_params=["pkt"],
            callsite_args=["pkt"],
            source_root=self.source_root,
        )
        self.assertTrue(
            sem.needs_sequential,
            f"Expected sequential=True, got {sem.needs_sequential}"
        )

    def test_log_event_isolated(self):
        """log_event(flags) where flags is int → P2, isolated"""
        sem = analyze(
            "log_event", "utils.c",
            tainted_params=["flags"],
            callsite_args=["flags"],
            source_root=self.source_root,
        )
        # 'flags' is declared as 'int code' → value type
        self.assertFalse(
            sem.needs_sequential,
            f"int param should be isolated, got {sem.reason}"
        )

    def test_field_access_matches_base(self):
        """pkt->len should match tainted param pkt"""
        sem = analyze(
            "route_packet", "network.c",
            tainted_params=["pkt"],
            callsite_args=["pkt"],
            source_root=self.source_root,
        )
        # pkt is a pointer → P0
        self.assertTrue(sem.needs_sequential)

    def test_send_packet_const_isolated(self):
        """send_packet(const Packet* pkt) → P2, isolated"""
        sem = analyze(
            "send_packet", "utils.c",
            tainted_params=["pkt"],
            callsite_args=["pkt"],
            source_root=self.source_root,
        )
        self.assertFalse(
            sem.needs_sequential,
            f"const pointer should be isolated, got {sem.reason}"
        )

    def test_mixed_params_sequential(self):
        """calc_checksum(data, len) → pointer is non-const, sequential=P0"""
        sem = analyze(
            "calc_checksum", "utils.c",
            tainted_params=["data", "len"],
            callsite_args=["data", "len"],
            source_root=self.source_root,
        )
        self.assertTrue(sem.needs_sequential)

    def test_read_buf_const_isolated(self):
        """read_buf(const char*) → P2"""
        sem = analyze(
            "read_buf", "utils.c",
            tainted_params=["buf"],
            callsite_args=["buf"],
            source_root=self.source_root,
        )
        self.assertFalse(sem.needs_sequential)


class TestMarkAmbiguous(unittest.TestCase):
    def test_conservative_is_ambiguous(self):
        sem = FollowupSemantics(
            needs_sequential=True,
            reason="complex",
            source="conservative",
        )
        self.assertTrue(mark_ambiguous(sem))

    def test_script_with_evidence_not_ambiguous(self):
        sem = FollowupSemantics(
            needs_sequential=True,
            reason="evidence-based",
            source="script",
            params=[ParamSemantics(is_pointer=True, evidence="decl: char* buf")],
        )
        self.assertFalse(mark_ambiguous(sem))

    def test_script_no_evidence_is_ambiguous(self):
        sem = FollowupSemantics(
            needs_sequential=True,
            source="script",
            params=[ParamSemantics(is_pointer=True, evidence="")],
        )
        self.assertTrue(mark_ambiguous(sem))


class TestLookupDecl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = Path(tempfile.mkdtemp(prefix="dvs_test_"))
        _write_project(cls.project)
        cls.source_root = str(cls.project / "src")

    def test_find_modify_buf_decl(self):
        decl = _lookup_param_decl(
            "modify_buf", arg_index=1,
            hint_file="utils.c",
            source_root=self.source_root,
        )
        self.assertIn("char", decl)
        self.assertIn("*", decl)
        self.assertNotIn("const", decl)

    def test_find_send_packet_const_decl(self):
        decl = _lookup_param_decl(
            "send_packet", arg_index=1,
            hint_file="utils.c",
            source_root=self.source_root,
        )
        self.assertIn("const", decl)
        self.assertIn("Packet", decl)

    def test_not_found_returns_empty(self):
        decl = _lookup_param_decl(
            "nonexistent", arg_index=1,
            hint_file="",
            source_root=self.source_root,
        )
        self.assertEqual(decl, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
