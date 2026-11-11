"""Inspect bounded ELF/PE headers and section metadata in one saved file."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys


MAX_BYTES = 64 * 1024 * 1024
MAX_SECTIONS = 1024
MAX_PROGRAM_HEADERS = 1024
MAX_NAME_BYTES = 256


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, json.dumps({"error": message}) + "\n")


def region(raw, offset, size, label):
    if offset < 0 or size < 0 or offset > len(raw) or size > len(raw) - offset:
        raise ValueError(label + " exceeds file bounds")
    return memoryview(raw)[offset:offset + size]


def unpack(raw, fmt, offset, label):
    return struct.unpack(fmt, region(raw, offset, struct.calcsize(fmt), label))


def inspect_elf(raw):
    ident = region(raw, 0, 16, "ELF identification")
    if ident[4] not in (1, 2) or ident[5] not in (1, 2) or ident[6] != 1:
        raise ValueError("unsupported ELF class, byte order or identification version")
    bits = 32 if ident[4] == 1 else 64
    order = "<" if ident[5] == 1 else ">"
    values = unpack(raw, order + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"), 16, "ELF header")
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstrndx = values
    if version != 1 or ehsize != (52 if bits == 32 else 64):
        raise ValueError("unsupported ELF version or header size")
    if phnum == 0xffff or shstrndx == 0xffff or (shnum == 0 and shoff != 0):
        raise ValueError("ELF extended numbering is not supported")
    if phnum > MAX_PROGRAM_HEADERS or shnum > MAX_SECTIONS:
        raise ValueError("ELF exceeds 1024 section or program headers")
    if phnum:
        minimum = 32 if bits == 32 else 56
        if phsize < minimum or phoff < ehsize:
            raise ValueError("invalid ELF program header table")
        region(raw, phoff, phsize * phnum, "ELF program header table")
        for index in range(phnum):
            fields = unpack(raw, order + ("IIIIIIII" if bits == 32 else "IIQQQQQQ"), phoff + phsize * index, "ELF program header")
            offset, size = (fields[1], fields[4]) if bits == 32 else (fields[2], fields[5])
            if size:
                region(raw, offset, size, "ELF program segment")
    sections = []
    if shnum:
        if shsize < (40 if bits == 32 else 64) or shoff < ehsize:
            raise ValueError("invalid ELF section header table")
        region(raw, shoff, shsize * shnum, "ELF section header table")
        for index in range(shnum):
            fields = unpack(raw, order + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ"), shoff + shsize * index, "ELF section header")
            name, section_type, section_flags, address, offset, size, link, info, alignment, entry_size = fields
            if index == 0 and any(fields):
                raise ValueError("ELF null section is nonzero; extended numbering is not supported")
            if section_type not in (0, 8):
                region(raw, offset, size, "ELF section data")
            sections.append({"index": index, "name_offset": name, "name": None, "type_code": section_type, "flags": section_flags, "address": address, "file_offset": offset, "file_size": 0 if section_type in (0, 8) else size, "declared_size": size})
    elif shstrndx != 0:
        raise ValueError("ELF names reference a missing section table")
    if shstrndx:
        if shstrndx >= shnum or sections[shstrndx]["type_code"] != 3:
            raise ValueError("ELF section-name table index or type is invalid")
        table = sections[shstrndx]
        names = bytes(region(raw, table["file_offset"], table["declared_size"], "ELF section-name table"))
        if not names or names[0] != 0 or names[-1] != 0:
            raise ValueError("ELF section-name table must start and end with NUL")
        for section in sections:
            offset = section["name_offset"]
            if offset >= len(names):
                raise ValueError("ELF section name offset exceeds string table")
            end = names.find(b"\0", offset, min(len(names), offset + MAX_NAME_BYTES + 1))
            if end < 0:
                raise ValueError("ELF section name is unterminated or exceeds 256 bytes")
            section["name"] = names[offset:end].decode("ascii", errors="backslashreplace")
    for section in sections:
        del section["name_offset"]
    return {"format": "ELF", "header": {"bits": bits, "endianness": "little" if order == "<" else "big", "machine_code": machine, "machine": {3: "Intel 80386", 20: "PowerPC", 21: "PowerPC64", 40: "ARM", 62: "AMD x86-64", 183: "AArch64", 243: "RISC-V"}.get(machine, "unknown"), "file_type_code": kind, "file_type": {0: "none", 1: "relocatable", 2: "executable", 3: "shared_object", 4: "core"}.get(kind, "unknown"), "entry_point": entry, "flags": flags, "program_header_count": phnum, "section_count": shnum, "section_names_status": "present" if shstrndx else "absent"}, "sections": sections}


def inspect_pe(raw):
    region(raw, 0, 64, "DOS header")
    peoff, = unpack(raw, "<I", 60, "DOS PE offset")
    if peoff < 64 or region(raw, peoff, 4, "PE signature") != b"PE\0\0":
        raise ValueError("invalid PE signature or DOS PE offset")
    machine, count, timestamp, symbols, symbol_count, optional_size, flags = unpack(raw, "<HHIIIHH", peoff + 4, "PE COFF header")
    if count > MAX_SECTIONS:
        raise ValueError("PE exceeds 1024 section headers")
    optional = peoff + 24
    region(raw, optional, optional_size, "PE optional header")
    magic, = unpack(raw, "<H", optional, "PE optional magic")
    if magic not in (0x10B, 0x20B):
        raise ValueError("unsupported PE optional header magic")
    bits = 32 if magic == 0x10B else 64
    minimum = 96 if bits == 32 else 112
    if optional_size < minimum:
        raise ValueError("PE optional header is too short")
    entry, = unpack(raw, "<I", optional + 16, "PE entry RVA")
    image_base, = unpack(raw, "<I" if bits == 32 else "<Q", optional + (28 if bits == 32 else 24), "PE image base")
    size_image, size_headers = unpack(raw, "<II", optional + 56, "PE image/header sizes")
    subsystem, dll_flags = unpack(raw, "<HH", optional + 68, "PE subsystem")
    directory_count, = unpack(raw, "<I", optional + minimum - 4, "PE directory count")
    if directory_count > 16 or minimum + directory_count * 8 > optional_size:
        raise ValueError("PE directory count exceeds supported optional header bounds")
    table = optional + optional_size
    table_end = table + count * 40
    region(raw, table, count * 40, "PE section header table")
    if size_headers < table_end or size_headers > len(raw):
        raise ValueError("PE SizeOfHeaders does not cover header tables within the file")
    sections = []
    for index in range(count):
        name, vsize, vaddr, size, offset, reloc, lines, reloc_count, line_count, characteristics = unpack(raw, "<8sIIIIIIHHI", table + index * 40, "PE section header")
        if size:
            if offset < size_headers:
                raise ValueError("PE section data overlaps headers")
            region(raw, offset, size, "PE section data")
        sections.append({"index": index, "name": name.split(b"\0", 1)[0].decode("ascii", errors="backslashreplace"), "virtual_address": vaddr, "virtual_size": vsize, "file_offset": offset, "file_size": size, "characteristics": characteristics})
    return {"format": "PE", "header": {"bits": bits, "endianness": "little", "machine_code": machine, "machine": {0x14C: "Intel 80386", 0x8664: "AMD x86-64", 0x1C0: "ARM", 0x1C4: "ARM Thumb-2", 0xAA64: "AArch64"}.get(machine, "unknown"), "file_type": "dll" if flags & 0x2000 else "executable_image" if flags & 2 else "image_without_executable_flag", "characteristics": flags, "entry_point_rva": entry, "image_base": image_base, "image_size": size_image, "subsystem": subsystem, "dll_characteristics": dll_flags, "section_count": count}, "sections": sections}


def inspect_file(raw):
    if raw.startswith(b"\x7fELF"):
        result = inspect_elf(raw)
    elif raw.startswith(b"MZ"):
        result = inspect_pe(raw)
    else:
        raise ValueError("unsupported binary format; expected ELF or PE")
    result.update({"input_sha256": hashlib.sha256(raw).hexdigest(), "input_bytes": len(raw), "imports": {"status": "not_inspected", "reason": "imports, symbols and dynamic dependencies are outside this header/section inventory"}, "scope": "structural header/section observations only; no execution, loading, disassembly, signature validation or vulnerability verdict"})
    return result


def main():
    parser = Parser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path)
    parser.add_argument("--input", "-input", dest="input_option", type=Path)
    args = parser.parse_args()
    if (args.input is None) == (args.input_option is None):
        parser.error("supply one input path, positionally or with --input")
    path = args.input if args.input is not None else args.input_option
    try:
        if not path.is_file():
            raise ValueError("input must be a readable regular file")
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("input exceeds 64 MiB")
        result = inspect_file(raw)
        print(json.dumps(result, sort_keys=True))
        return 0
    except OSError:
        message = "input file could not be read"
    except (MemoryError, RecursionError):
        message = "input exceeds inspection resource limits"
    except ValueError as error:
        message = str(error)
    print(json.dumps({"error": message}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
