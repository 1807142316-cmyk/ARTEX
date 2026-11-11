import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "skills" / "binary-format-inspection" / "scripts" / "run.py"


def elf_fixture(bits=64, endian="little"):
    order = "<" if endian == "little" else ">"
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if endian == "little" else 2, 1, 0]) + b"\0" * 8
    if bits == 64:
        header = struct.pack(order + "HHIQQQIHHHHHH", 1, 62, 1, 0, 0, 128, 0, 64, 0, 0, 64, 3, 1)
        null = b"\0" * 64
        strings = struct.pack(order + "IIQQQQIIQQ", 1, 3, 0, 0, 64, 17, 0, 0, 1, 0)
        text = struct.pack(order + "IIQQQQIIQQ", 11, 1, 6, 0, 96, 1, 0, 0, 1, 0)
    else:
        header = struct.pack(order + "HHIIIIIHHHHHH", 1, 20, 1, 0, 0, 128, 0, 52, 0, 0, 40, 3, 1)
        null = b"\0" * 40
        strings = struct.pack(order + "IIIIIIIIII", 1, 3, 0, 0, 64, 17, 0, 0, 1, 0)
        text = struct.pack(order + "IIIIIIIIII", 11, 1, 6, 0, 96, 1, 0, 0, 1, 0)
    raw = bytearray(128)
    raw[:len(ident + header)] = ident + header
    raw[64:81] = b"\0.shstrtab\0.text\0"
    raw[96] = 0xC3
    return bytes(raw) + null + strings + text


def pe_fixture(bits=64):
    raw = bytearray(1024)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 60, 128)
    raw[128:132] = b"PE\0\0"
    optional_size = 240 if bits == 64 else 224
    struct.pack_into("<HHIIIHH", raw, 132, 0x8664 if bits == 64 else 0x14C, 1, 0, 0, 0, optional_size, 0x2022 if bits == 64 else 0x102)
    struct.pack_into("<H", raw, 152, 0x20B if bits == 64 else 0x10B)
    struct.pack_into("<I", raw, 168, 0x1000)
    struct.pack_into("<Q" if bits == 64 else "<I", raw, 176 if bits == 64 else 180, 0x140000000 if bits == 64 else 0x400000)
    struct.pack_into("<II", raw, 184, 0x1000, 0x200)
    struct.pack_into("<II", raw, 208, 0x2000, 0x200)
    struct.pack_into("<HH", raw, 220, 3, 0x160)
    struct.pack_into("<I", raw, 260 if bits == 64 else 244, 16)
    struct.pack_into("<8sIIIIIIHHI", raw, 152 + optional_size, b".text", 1, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    raw[512] = 0xC3
    return bytes(raw)


class BinaryFormatInspectionTests(unittest.TestCase):
    def run_file(self, raw, flag="--input"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "saved.bin"
            path.write_bytes(raw)
            args = [str(path)] if flag is None else [flag, str(path)]
            return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, encoding="utf-8")

    def test_elf_headers_sections_and_hash_respect_class_and_endianness(self):
        for bits, endian, machine in [(64, "little", "AMD x86-64"), (64, "big", "AMD x86-64"), (32, "little", "PowerPC"), (32, "big", "PowerPC")]:
            with self.subTest(bits=bits):
                raw = elf_fixture(bits, endian)
                result = self.run_file(raw)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["input_sha256"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(report["input_bytes"], len(raw))
                self.assertEqual(report["format"], "ELF")
                self.assertEqual(report["header"]["bits"], bits)
                self.assertEqual(report["header"]["endianness"], endian)
                self.assertEqual(report["header"]["machine"], machine)
                self.assertEqual(report["header"]["file_type"], "relocatable")
                self.assertEqual(report["header"]["entry_point"], 0)
                self.assertEqual([(item["name"], item["file_offset"], item["file_size"]) for item in report["sections"]], [("", 0, 0), (".shstrtab", 64, 17), (".text", 96, 1)])
                self.assertEqual(report["imports"]["status"], "not_inspected")
                self.assertIn("structural", report["scope"])

    def test_pe_headers_sections_and_entry_rva_keep_declared_semantics(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                raw = pe_fixture(bits)
                result = self.run_file(raw, flag=None)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["format"], "PE")
                self.assertEqual(report["header"]["bits"], bits)
                self.assertEqual(report["header"]["endianness"], "little")
                self.assertEqual(report["header"]["machine"], "AMD x86-64" if bits == 64 else "Intel 80386")
                self.assertEqual(report["header"]["file_type"], "dll" if bits == 64 else "executable_image")
                self.assertEqual(report["header"]["entry_point_rva"], 4096)
                self.assertEqual(report["header"]["image_base"], 5368709120 if bits == 64 else 4194304)
                self.assertEqual(report["header"]["subsystem"], 3)
                self.assertEqual(report["sections"], [{"index": 0, "name": ".text", "virtual_address": 4096, "virtual_size": 1, "file_offset": 512, "file_size": 512, "characteristics": 1610612768}])
                self.assertEqual(report["imports"]["status"], "not_inspected")

    def test_malformed_truncated_and_excessive_inputs_fail_with_json_and_no_partial_report(self):
        invalid_name = bytearray(elf_fixture())
        struct.pack_into("<I", invalid_name, 256, 999)
        sectionless = bytearray(elf_fixture()[:64])
        struct.pack_into("<Q", sectionless, 40, 0)
        struct.pack_into("<H", sectionless, 60, 0)
        bad_elf_version = bytearray(elf_fixture())
        bad_elf_version[6] = 2
        many_sections = bytearray(elf_fixture())
        struct.pack_into("<H", many_sections, 60, 1025)
        extended = bytearray(elf_fixture())
        struct.pack_into("<H", extended, 60, 0)
        pe_too_short = bytearray(pe_fixture())
        struct.pack_into("<H", pe_too_short, 148, 2)
        pe_section_overrun = bytearray(pe_fixture())
        struct.pack_into("<I", pe_section_overrun, 412, 1024)
        pe_directories = bytearray(pe_fixture())
        struct.pack_into("<I", pe_directories, 260, 17)
        cases = [(b"", "unsupported"), (b"\x7fELF", "bounds"), (b"MZ", "bounds"), (elf_fixture()[:-1], "bounds"), (invalid_name, "name offset"), (sectionless, "missing section"), (bad_elf_version, "version"), (many_sections, "1024"), (extended, "extended"), (pe_fixture()[:130], "bounds"), (pe_fixture()[:-1], "bounds"), (pe_too_short, "too short"), (pe_section_overrun, "bounds"), (pe_directories, "directory")]
        for raw, expected in cases:
            with self.subTest(expected=expected, length=len(raw)):
                result = self.run_file(raw)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertEqual(result.stdout, "")
                self.assertIn(expected, json.loads(result.stderr)["error"])
                self.assertNotIn("Traceback", result.stderr)

    def test_size_path_and_argument_limits_use_the_same_error_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oversized = root / "large.bin"
            with oversized.open("wb") as output:
                output.truncate(64 * 1024 * 1024 + 1)
            for args, expected in [([str(oversized)], "64 MiB"), ([str(root)], "regular file"), ([str(root / "missing.bin")], "regular file"), ([], "one input"), ([str(root), "--input", str(root)], "one input")]:
                with self.subTest(expected=expected):
                    result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, encoding="utf-8")
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(expected, json.loads(result.stderr)["error"])

    def test_absent_section_names_are_not_fabricated_and_nobits_stays_virtual(self):
        raw = bytearray(elf_fixture())
        struct.pack_into("<H", raw, 62, 0)
        struct.pack_into("<I", raw, 260, 8)
        struct.pack_into("<Q", raw, 280, 999999)
        struct.pack_into("<Q", raw, 288, 4096)
        result = self.run_file(raw)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["header"]["section_names_status"], "absent")
        self.assertIsNone(report["sections"][2]["name"])
        self.assertEqual(report["sections"][2]["file_size"], 0)
        self.assertEqual(report["sections"][2]["declared_size"], 4096)

    def test_installed_platform_binary_is_read_as_data(self):
        path = Path(sys.executable) if sys.platform == "win32" else Path("/bin/true")
        if not path.is_file():
            self.skipTest("platform binary not present")
        result = subprocess.run([sys.executable, str(SCRIPT), "-input", str(path)], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["format"], "PE" if sys.platform == "win32" else "ELF")
        self.assertGreater(report["header"]["section_count"], 0)
        self.assertEqual(report["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
