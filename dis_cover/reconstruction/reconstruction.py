from elftools.elf.enums import ENUM_SH_TYPE_BASE, ENUM_P_TYPE_BASE

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

# Transforms an int to a bytes representation, in little endian format, padded
# using the width argument (in bytes).
def int_to_bytes(i, width=2):
    return bytes.fromhex(hex(i)[2:].zfill(width * 2))[::-1]


class Reconstruction:
    """The reconstruction after an analysis"""

    def __init__(self, analysis):
        self.elffile = analysis.elffile
        self.classes = analysis.classes

    def reconstruct(self):
        # The four main parts of an ELF file that we will fill out
        self.elf_header = b""
        self.program_header_table = b""
        self.sections = b""
        self.section_header_table = b""

        self.construct_program_header_table()
        self.construct_sections_and_sections_header_table()
        self.construct_elf_header()

        self.data = b""
        self.data += self.elf_header
        self.data += self.program_header_table
        self.data += self.sections
        self.data += self.section_header_table

    # Construct the program header table
    def construct_program_header_table(self):
        # We simply copy the original header table, with some p_filesz fields set
        # to 0
        for segment in self.elffile.iter_segments():
            header = segment.header
            program_header = b""
            program_header += int_to_bytes(ENUM_P_TYPE_BASE[header["p_type"]], width=4)
            program_header += int_to_bytes(header["p_flags"], width=4)
            program_header += int_to_bytes(header["p_offset"], width=8)
            program_header += int_to_bytes(header["p_vaddr"], width=8)
            program_header += int_to_bytes(header["p_paddr"], width=8)
            if segment.header["p_type"] in ["PT_PHDR", "PT_NOTE"]:
                program_header += int_to_bytes(header["p_filesz"], width=8)
            else:
                program_header += int_to_bytes(0, width=8)
            program_header += int_to_bytes(header["p_memsz"], width=8)
            program_header += int_to_bytes(header["p_align"], width=8)

            self.program_header_table += program_header

    # Construct the sections and section header table
    def construct_sections_and_sections_header_table(self):

        self.sections_list = []
        self.e_shnum = 0
        self.e_shstrndx = 0
        self.shstrtab_data = b""
        self.sections_offset = int("0x40", 16) + len(self.program_header_table)
        # self.sections_offset = len(self.program_header_table)

        # The first field is always empty
        # self.section_header_table += b"\x00" * 64

        for section in self.elffile.iter_sections():
            section_data = b""
            section_header = b""

            # We skip the .shstrtab section, we will do it after the SECTIONS_TO_CREATE
            if section.name == ".shstrtab":
                continue
            # We skip these for now if they exist
            elif section.name in SECTIONS_TO_CREATE:
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
            self.sections_list.append(section.name)

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
        debug_info = b""
        debug_abbrev = b""
        debug_str = b""

        # We create the debug_abbrev types

        debug_abbrev += b"\x01"  # abbrev 1
        debug_abbrev += b"\x11"  # compile_unit
        debug_abbrev += b"\x01"  # has children
        debug_abbrev += b"\x13\x05"  # language: data2
        debug_abbrev += b"\x11\x01"  # low_pc: address
        debug_abbrev += b"\x55\x17"  # ranges: sec_offset
        debug_abbrev += b"\x00\x00"

        debug_abbrev += b"\x02"  # abbrev 2
        debug_abbrev += b"\x02"  # class_type
        debug_abbrev += b"\x01"  # has children
        debug_abbrev += b"\x1d\x13"  # containing_type: ref4
        debug_abbrev += b"\x36\x0b"  # calling_convention: data1 EXPANDABLE ?
        debug_abbrev += b"\x03\x0e"  # name: strp
        debug_abbrev += b"\x0b\x0b"  # byte_size: data1
        debug_abbrev += b"\x00\x00"

        debug_abbrev += b"\x03"  # abbrev 3
        debug_abbrev += b"\x1c"  # inheritance
        debug_abbrev += b"\x00"  # no children
        debug_abbrev += b"\x49\x13"  # type: ref4
        debug_abbrev += b"\x00\x00"

        debug_abbrev += b"\x00"

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

        self.first_class_location = len(debug_info) + 4

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
                    self.find_class_location(inheritance), width=4
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

    def find_class_location(self, cpp_class):
        location = self.first_class_location
        for c in self.classes:
            if c.name == cpp_class:
                return location
            location += 12
            for i in c.inherits_from:
                location += 5
        return 0

    def build_table_sections(self):

        # First, we check the existing symtab and import the existing symbols
        symtab_section = self.elffile.get_section_by_name(".symtab")
        n = -1

        symtab = b""
        strtab = b""

        symtab += b"\x00" * 24
        strtab += b"\x00"

        if symtab_section:
            for symbol in symtab_section.iter_symbols():
                n += 1
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
                    symtab_section["sh_offset"] + n * symtab_section["sh_entsize"]
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

        for c in self.classes:
            symtab += int_to_bytes(len(strtab), width=4)  # st_name
            symtab += b"\x21"  # st_info
            symtab += b"\x00"  # st_other
            symtab += int_to_bytes(self.st_shndx, width=2)  # st_shndx (.data.rel.ro id)
            symtab += int_to_bytes(c.address, width=8)  # st_value
            symtab += b"\x10\x00\x00\x00\x00\x00\x00\x00"  # st_size # TODO

            strtab += b"_ZTI" + mangle(c.name).encode() + b"\x00"

            symtab += int_to_bytes(len(strtab), width=4)  # st_name
            symtab += b"\x21"  # st_info
            symtab += b"\x00"  # st_other
            symtab += int_to_bytes(self.st_shndx, width=2)  # st_shndx (.data.rel.ro id)
            try:
                symtab += int_to_bytes(c.vtable_address, width=8)  # st_value
            except:
                symtab += b"\x00" * 8  # st_value
            symtab += b"\x20\x00\x00\x00\x00\x00\x00\x00"  # st_size # TODO

            strtab += b"_ZTV" + mangle(c.name).encode() + b"\x00"

        self.symtab = symtab
        self.strtab = strtab

    def construct_elf_header(self):
        # We construct the elf header
        self.elffile.stream.seek(0)
        self.elf_header += self.elffile.stream.read(
            int("0x20", 16)
        )  # Read until e_phoff

        self.elf_header += int_to_bytes(int("0x40", 16), width=8)  # e_phoff
        self.elf_header += int_to_bytes(
            int("0x40", 16) + len(self.program_header_table) + len(self.sections),
            width=8,
        )  # e_shoff

        self.elffile.stream.seek(int("0x30", 16))  # Seek at e_flags
        self.elf_header += self.elffile.stream.read(12)  # Read until e_shnum

        self.elf_header += int_to_bytes(self.e_shnum)  # e_shnum
        self.elf_header += int_to_bytes(self.e_shstrndx)  # e_shstrndx


# Mangle a name according to the abi
def mangle(name):
    namespaces = name.split("::")
    mangled_name = ""
    for namespace in namespaces:
        mangled_name += str(len(namespace)) + namespace
    if len(namespaces) > 1:
        mangled_name = "N" + mangled_name + "E"
    return mangled_name


def reconstruct(analysis):

    reconstruction = Reconstruction(analysis)

    reconstruction.reconstruct()

    return reconstruction.data
