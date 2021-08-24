"""ELF reconstruction logic"""

import struct
from elftools.elf.enums import ENUM_SH_TYPE_BASE, ENUM_P_TYPE_BASE
from elftools.dwarf.enums import ENUM_DW_TAG, ENUM_DW_CHILDREN, ENUM_DW_AT, ENUM_DW_FORM

SECTIONS_TO_KEEP = [
    ".note.gnu.build-id",
    ".note.ABI-tag",
    ".comment",
    ".dynsym",
]

SECTIONS_TO_CREATE = [
    ".debug_info",  # main dwarf info
    ".debug_abbrev",  # dwarf type definition
    ".debug_line",  # source code line info
    ".debug_str",  # string table for debug info
    ".debug_ranges",  # address ranges
    ".symtab",  # symbolic table
    ".strtab",  # string table for symtab
]

DEBUG_SECTION_HEADER = {
    "sh_type": "SHT_PROGBITS",
    "sh_flags": 0,
    "sh_addr": 0,
    "sh_link": 0,
    "sh_info": 0,
    "sh_addralign": 1,
    "sh_entsize": 0,
}

SYMTAB_SECTION_HEADER = {
    "sh_type": "SHT_SYMTAB",
    "sh_flags": 0,
    "sh_addr": 0,
    "sh_link": 0,  # Modified in the code to .strtab's index
    "sh_info": 0,
    "sh_addralign": 8,
    "sh_entsize": 24,
}


def build_symtab_section_header(sh_link):
    """Build a symtab section header"""
    SYMTAB_SECTION_HEADER["sh_link"] = sh_link
    return SYMTAB_SECTION_HEADER


STRTAB_SECTION_HEADER = {
    "sh_type": "SHT_STRTAB",
    "sh_flags": 0,
    "sh_addr": 0,
    "sh_link": 0,
    "sh_info": 0,
    "sh_addralign": 1,
    "sh_entsize": 0,
}


def int_to_bytes(i, width=2):
    """
    Transforms an int to a bytes representation, in little endian format, padded
    using the width argument (in bytes).
    """
    return bytes.fromhex(hex(i)[2:].zfill(width * 2))[::-1]


class ELFHeader:
    """ELF header builder"""

    def __init__(self, analysis):
        self.data = b""

    def build(self):
        """Build the ELF header"""
        pass


class ProgramHeaderTable:
    """Program header table builder"""

    def __init__(self, analysis):
        self.data = b""
        self.elffile = analysis.elffile

    def build(self):
        """Build the program header table"""
        for segment in self.elffile.iter_segments():
            self.copy_row(segment.header)

    def copy_row(self, header):
        """
        Copy a row from the original header, with some p_filesz fields set to 0
        """
        row = b""
        row += int_to_bytes(ENUM_P_TYPE_BASE[header["p_type"]], width=4)
        row += int_to_bytes(header["p_flags"], width=4)
        row += int_to_bytes(header["p_offset"], width=8)
        row += int_to_bytes(header["p_vaddr"], width=8)
        row += int_to_bytes(header["p_paddr"], width=8)
        row += int_to_bytes(
            header["p_filesz"]
            if header["p_type"] in ["PT_PHDR", "PT_NOTE"]
            else 0,
            width=8,
        )
        row += int_to_bytes(header["p_memsz"], width=8)
        row += int_to_bytes(header["p_align"], width=8)
        self.data += row


class Sections:
    """Sections builder"""

    def __init__(self, analysis):
        self.data = b""

    def build(self):
        """Build the sections"""
        pass


class SectionHeaderTable:
    """Section header table builder"""

    def __init__(self, analysis):
        self.data = b""

    def build(self):
        """Build the section header table"""
        pass


class Reconstruction:
    """The reconstruction after an analysis"""

    def __init__(self, analysis):
        self.elffile = analysis.elffile
        self.classes = analysis.classes

        # The four main parts of an ELF file that we will fill out
        self.elf_header = b""
        self.sections = b""
        self.section_header_table = b""

        # self.elf_header = ELFHeader(analysis)
        self.program_header_table = ProgramHeaderTable(analysis)
        # self.sections = Sections(analysis)
        # self.section_header_table = SectionHeaderTable(analysis)

        # Attributes related to the section_header_table and the sections
        self.e_shnum = 0
        self.e_shstrndx = 0
        self.sections_offset = 0
        self.sections_list = []
        self.shstrtab_data = b""

        # Attributes related to the debug sections
        self.debug_info = b""
        self.debug_abbrev = b""
        self.debug_str = b""

        # Attributes related to the symbol sections
        self.st_shndx = 0
        self.symtab = b""
        self.strtab = b""

        # The final cumulated data
        self.data = b""

    def reconstruct(self):
        """Main reconstruction method"""
        self.program_header_table.build()
        self.construct_sections_and_sections_header_table()
        self.construct_elf_header()

        self.data += self.elf_header
        self.data += self.program_header_table.data
        self.data += self.sections
        self.data += self.section_header_table

    def construct_sections_and_sections_header_table(self):
        """Construct the sections and section header table"""
        self.sections_offset = int("0x40", 16) + len(self.program_header_table.data)

        for section in self.elffile.iter_sections():
            section_data = b""
            section_header = b""

            # We skip the .shstrtab section and the sections we will create later
            if section.name == ".shstrtab" or section.name in SECTIONS_TO_CREATE:
                continue

            if section.name == ".data.rel.ro":
                self.st_shndx = self.e_shnum

            self.e_shnum += 1

            # All of the sections we keep as is
            if section.name in SECTIONS_TO_KEEP:
                section_data += section.data()
                section_header += self.create_section_header(section.header)
            # The other sections (we squash them)
            else:
                # TODO set SHT_NOBITS flag
                section_data += bytes(section.header["sh_size"])
                section_header += self.create_section_header(section.header)

            # We add the name to the shstrtab section
            self.shstrtab_data += section.name.encode() + b"\x00"
            self.sections += section_data
            self.section_header_table += section_header
            if section.name:
                self.sections_list.append(section.name)

        # We build the debug sections to add them to the sections later
        self.build_debug_sections()
        # We build the table sections to add them to the sections later
        self.build_table_sections()

        # All of the sections we create
        for section_name in SECTIONS_TO_CREATE:
            header = DEBUG_SECTION_HEADER
            self.e_shnum += 1
            section_header = b""
            section_data = b""
            if section_name == ".debug_info":
                section_data += self.debug_info
            elif section_name == ".debug_abbrev":
                section_data += self.debug_abbrev
            elif section_name == ".debug_str":
                section_data += self.debug_str
            elif section_name == ".symtab":
                section_data += self.symtab
                header = build_symtab_section_header(self.e_shnum)
            elif section_name == ".strtab":
                section_data += self.strtab
                header = STRTAB_SECTION_HEADER
            section_header += self.create_section_header(
                header,
                sh_size=len(section_data),
            )
            self.shstrtab_data += section_name.encode() + b"\x00"
            self.sections += section_data
            self.section_header_table += section_header
            self.sections_list.append(section_name)

        # We write the .shstrtab section
        self.e_shstrndx = self.e_shnum
        self.e_shnum += 1
        shstrtab_name = b".shstrtab\x00"
        self.section_header_table += self.create_section_header(
            self.elffile.get_section_by_name(".shstrtab").header,
            sh_size=len(self.shstrtab_data) + len(shstrtab_name),
        )
        self.shstrtab_data += shstrtab_name
        self.sections += self.shstrtab_data
        self.sections_list.append(".shstrtab")

    def create_section_header(self, header, sh_size=-1):
        """Create a single section header"""
        if sh_size == -1:
            sh_size = header["sh_size"]
        section_header = b""
        section_header += int_to_bytes(len(self.shstrtab_data), width=4)
        section_header += int_to_bytes(ENUM_SH_TYPE_BASE[header["sh_type"]], width=4)
        section_header += int_to_bytes(header["sh_flags"], width=8)
        section_header += int_to_bytes(header["sh_addr"], width=8)
        section_header += int_to_bytes(
            self.sections_offset + len(self.sections), width=8
        )
        section_header += int_to_bytes(sh_size, width=8)
        section_header += int_to_bytes(header["sh_link"], width=4)
        section_header += int_to_bytes(header["sh_info"], width=4)
        section_header += int_to_bytes(header["sh_addralign"], width=8)
        section_header += int_to_bytes(header["sh_entsize"], width=8)
        return section_header

    def build_debug_sections(self):
        """Build the debug sections"""
        debug_info = b""
        debug_abbrev = b""
        debug_str = b""

        # We create the debug_abbrev types

        debug_abbrev += struct.pack(
            "9Bxx",
            1,
            ENUM_DW_TAG["DW_TAG_compile_unit"],
            ENUM_DW_CHILDREN["DW_CHILDREN_yes"],
            ENUM_DW_AT["DW_AT_language"],
            ENUM_DW_FORM["DW_FORM_data2"],
            ENUM_DW_AT["DW_AT_low_pc"],
            ENUM_DW_FORM["DW_FORM_addr"],
            ENUM_DW_AT["DW_AT_ranges"],
            ENUM_DW_FORM["DW_FORM_sec_offset"],
        )

        debug_abbrev += struct.pack(
            "11Bxx",
            2,
            ENUM_DW_TAG["DW_TAG_class_type"],
            ENUM_DW_CHILDREN["DW_CHILDREN_yes"],
            ENUM_DW_AT["DW_AT_containing_type"],
            ENUM_DW_FORM["DW_FORM_ref4"],
            ENUM_DW_AT[
                "DW_AT_calling_convention"
            ],  # TODO is calling_convention: data1 expandable ?
            ENUM_DW_FORM["DW_FORM_data1"],
            ENUM_DW_AT["DW_AT_name"],
            ENUM_DW_FORM["DW_FORM_strp"],
            ENUM_DW_AT["DW_AT_byte_size"],
            ENUM_DW_FORM["DW_FORM_data1"],
        )

        debug_abbrev += struct.pack(
            "5Bxx",
            3,
            ENUM_DW_TAG["DW_TAG_inheritance"],
            ENUM_DW_CHILDREN["DW_CHILDREN_no"],
            ENUM_DW_AT["DW_AT_type"],
            ENUM_DW_FORM["DW_FORM_ref4"],
        )

        debug_abbrev += struct.pack("x")

        # We create the compilation unit header
        # The first field, unit_length, is added at the end of this method
        debug_info += int_to_bytes(4)  # version
        debug_info += bytes(4)  # debug_abbrev_offset
        debug_info += int_to_bytes(8, width=1)  # address_size

        # The root DIE
        debug_info += b"\x01"  # abbrev number
        debug_info += b"\x21\x00"  # language (C++)
        # TODO figure out which is 8byte and which is 4
        # (in theory, both are 8)
        debug_info += b"\x00\x00\x00\x00\x00\x00\x00\x00"  # low_pc
        debug_info += b"\x00\x00\x00\x00"  # ranges

        first_class_offset = len(debug_info) + 4

        for cpp_class in self.classes:
            # Class
            type_location = (
                len(debug_info) + 4
            )  # TODO find out what happens with multiple inheritance for the containing type
            debug_info += b"\x02"  # abbrev number
            debug_info += int_to_bytes(type_location, width=4)  # containing type
            debug_info += b"\x04"  # calling_convention
            debug_info += int_to_bytes(len(debug_str), width=4)  # name
            debug_info += (
                b"\x08"  # byte_size # TODO maybe find out the size of the class
            )

            # We add the name to debug_str
            debug_str += cpp_class.name.encode() + b"\x00"

            # Inherits from
            for inheritance in cpp_class.inherits_from:
                debug_info += b"\x03"  # abbrev number
                debug_info += int_to_bytes(
                    self.find_class_location(inheritance, first_class_offset), width=4
                )  # type

            # Null tag
            debug_info += b"\x00"

        # Null tag
        debug_info += b"\x00"

        # Finally, we add the unit_length (initial length) at the beginning of the
        # compilation unit header
        debug_info = int_to_bytes(len(debug_info), width=4) + debug_info

        self.debug_info = debug_info
        self.debug_abbrev = debug_abbrev
        self.debug_str = debug_str

    def find_class_location(self, cpp_class_to_find, offset):
        """Find the class location in the debug info from the class name"""
        location = offset
        for cpp_class in self.classes:
            if cpp_class.name == cpp_class_to_find:
                return location
            location += 12
            location += 5 * len(cpp_class.inherits_from)
        return 0

    def build_table_sections(self):
        """Build the .symtab and .strtab sections"""
        # First, we check the existing symtab and import the existing symbols
        symtab_section = self.elffile.get_section_by_name(".symtab")
        counter = -1

        symtab = b""
        strtab = b""

        symtab += b"\x00" * 24
        strtab += b"\x00"

        if symtab_section:
            for symbol in symtab_section.iter_symbols():
                counter += 1
                skip_symbol = False

                # We check if the type of the table is "STT_SECTION"
                if symbol["st_info"]["type"] == "STT_SECTION":
                    continue

                # We check if the symbol corresponds to a class we have discovered
                for cpp_class in self.classes:
                    name = cpp_class.name
                    rtti_name = "_ZTI" + mangle(name)
                    vtable_name = "_ZTV" + mangle(name)
                    # If it is, we skip it to add it later
                    if symbol.name in [rtti_name, vtable_name]:
                        skip_symbol = True
                        break

                if skip_symbol:
                    continue

                entry_offset = (
                    symtab_section["sh_offset"] + counter * symtab_section["sh_entsize"]
                )
                symtab_section.stream.seek(entry_offset)
                symbol_value = symtab_section.stream.read(symtab_section["sh_entsize"])

                # We do not include the symbol if it is null
                if symbol_value == b"\x00" * symtab_section["sh_entsize"]:
                    continue

                # We find the id of the section pointed to by the symbol
                st_shndx = symbol["st_shndx"]
                if isinstance(st_shndx, int):
                    section_name = self.elffile.get_section(st_shndx).name
                    try:
                        new_st_shndx = self.sections_list.index(section_name)
                    except:
                        continue

                    # Now we can create the symbol with new st_name and st_shndx
                    symtab += int_to_bytes(len(strtab), width=4)  # st_name
                    symtab += symbol_value[4:6]  # st_info, st_other
                    symtab += int_to_bytes(new_st_shndx, width=2)  # st_shndx
                    symtab += symbol_value[8:]  # st_value, st_size

                    strtab += symbol.name.encode() + b"\x00"

        for cpp_class in self.classes:
            symtab += int_to_bytes(len(strtab), width=4)  # st_name
            symtab += b"\x21"  # st_info
            symtab += b"\x00"  # st_other
            symtab += int_to_bytes(self.st_shndx, width=2)  # st_shndx (.data.rel.ro id)
            symtab += int_to_bytes(cpp_class.address, width=8)  # st_value
            symtab += b"\x10\x00\x00\x00\x00\x00\x00\x00"  # st_size # TODO

            strtab += b"_ZTI" + mangle(cpp_class.name).encode() + b"\x00"

            symtab += int_to_bytes(len(strtab), width=4)  # st_name
            symtab += b"\x21"  # st_info
            symtab += b"\x00"  # st_other
            symtab += int_to_bytes(self.st_shndx, width=2)  # st_shndx (.data.rel.ro id)
            try:
                symtab += int_to_bytes(cpp_class.vtable_address, width=8)  # st_value
            except:
                symtab += b"\x00" * 8  # st_value
            symtab += b"\x20\x00\x00\x00\x00\x00\x00\x00"  # st_size # TODO

            strtab += b"_ZTV" + mangle(cpp_class.name).encode() + b"\x00"

        self.symtab = symtab
        self.strtab = strtab

    def construct_elf_header(self):
        """Construct the elf header"""
        self.elffile.stream.seek(0)
        self.elf_header += self.elffile.stream.read(
            int("0x20", 16)
        )  # Read until e_phoff

        self.elf_header += int_to_bytes(int("0x40", 16), width=8)  # e_phoff
        self.elf_header += int_to_bytes(
            int("0x40", 16) + len(self.program_header_table.data) + len(self.sections),
            width=8,
        )  # e_shoff

        self.elffile.stream.seek(int("0x30", 16))  # Seek at e_flags
        self.elf_header += self.elffile.stream.read(12)  # Read until e_shnum

        self.elf_header += int_to_bytes(self.e_shnum)  # e_shnum
        self.elf_header += int_to_bytes(self.e_shstrndx)  # e_shstrndx


def mangle(name):
    """Mangle a name according to the ABI"""
    namespaces = name.split("::")
    mangled_name = ""
    for namespace in namespaces:
        mangled_name += str(len(namespace)) + namespace
    if len(namespaces) > 1:
        mangled_name = "N" + mangled_name + "E"
    return mangled_name


def reconstruct(analysis):
    """Main reconstruct method"""
    reconstruction = Reconstruction(analysis)
    reconstruction.reconstruct()
    return reconstruction.data
