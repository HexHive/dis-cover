import struct
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86_const import *
from itanium_demangler import parse as demangle


DATA_SECTIONS = [".rodata", ".data.rel.ro", ".data.rel.ro.local", ".rdata"]


class CppClass:
    def __init__(self, name):
        self.name = name
        self.inherits_from = set()
        self.address = None

    def __str__(self):
        output = self.name
        if len(self.inherits_from) > 0:
            output += "\tinherits from %s" % ", ".join(self.inherits_from)
        return output

    def __hash__(self):
        return hash(
            str(hash(self.name))
            + str(hash("".join(sorted([str(hash(c)) for c in self.inherits_from]))))
        )

    def __eq__(self, other):
        return hash(self) == hash(other)


class ElfAnalysis:
    """An analysis of an ELF file"""

    def __init__(self, file_name):
        self.file_name = file_name
        f = open(self.file_name, "rb")
        self.elffile = ELFFile(f)
        self.sections = []
        for section in self.elffile.iter_sections():
            self.sections.append(
                (section["sh_addr"] + section["sh_size"], section.name)
            )
        self.sections.sort(key=lambda i: i[0])
        self.classes = []
        self.names = {}
        self.sections_data = {}
        self.addresses = []

    def get_section_name(self, addr):
        if addr < 0:
            return "out of bounds"
        for (end, name) in self.sections:
            if addr < end:
                return name
        return "out of bounds"

    def get_section_data_by_name(self, name):
        if self.sections_data.get(name) == None:
            self.sections_data[name] = self.elffile.get_section_by_name(name).data()
        return self.sections_data[name]

    def extract_name(self, addr):
        if self.names.get(addr) != None:
            return self.names[addr]
        section_name = self.get_section_name(addr)
        if section_name == "out of bounds":
            return
        section = self.elffile.get_section_by_name(section_name)
        section_data = self.get_section_data_by_name(section_name)
        relative_address = addr - section["sh_addr"]
        if relative_address >= 0 and relative_address < len(section_data):
            name = "_Z"
            while (
                relative_address < len(section_data)
                and section_data[relative_address] != 0
            ):
                name += chr(section_data[relative_address])
                relative_address += 1
            self.names[addr] = str(demangle(name))
            try:
                return str(demangle(name))
            except:
                return str(name)

    def __str__(self):
        output = "🔎  List of classes found in %s:\n" % self.file_name
        return output + "\n".join([str(c) for c in self.get_classes()])

    def get_classes(self):
        return self.classes

    def extract_rtti_info(self):

        self.program_map = {}

        for data_section_name in DATA_SECTIONS:

            data_section = self.elffile.get_section_by_name(data_section_name)

            # If there is no section, we go to the next one
            if not data_section:
                continue

            data = self.get_section_data_by_name(data_section_name)

            base_address = data_section["sh_addr"]

            for offset in range(0, len(data), 8):
                line = list(data[offset : offset + 8])
                line.reverse()
                line_str = "".join([format(d, "02x") for d in line])
                line_int = int(line_str, 16)
                section = self.get_section_name(line_int)

                flag = "unknown"

                if section in DATA_SECTIONS:
                    flag = "data"
                elif line_int == 0:
                    flag = "zeroes"

                self.program_map[base_address + offset] = (line_int, flag)

        self.addresses = list(self.program_map.keys())
        self.addresses.sort()

        # Add "begin_vtable" and "begin_rtti" flags
        # Append CppClass objects to self.classes
        for address in self.addresses:
            (line, flag) = self.program_map[address]
            next_v = self.program_map.get(address + 8)
            if not next_v:
                continue
            (next_line, next_flag) = next_v
             # First we find out if this is the beginning of a vtable
            if flag == "zeroes" and next_flag == "data":
                # If it is, we find the associated RTTI
                success, cpp_class = self.flag_rtti_recur(next_line)
                if cpp_class:
                    cpp_class.vtable_address = address
                # If we have successfuly flagged an RTTI, then at
                # address there is a vtable
                if success:
                    self.program_map[address] = (line, "begin_vtable")

    def flag_rtti_recur(self, address):
        # We check that the beginning of the table is the beginning of an RTTI
        rtti_start = self.program_map.get(address)
        if not rtti_start:
            return False, None
        (line, flag) = rtti_start

        if flag == "begin_rtti":
            name = self.extract_name(self.program_map[address + 8][0])
            for cpp_class in self.classes:
                if cpp_class.name == name:
                    return name, cpp_class
            return name, None

        if flag not in ["unknown", "zeroes"]:
            return False, None

        # We check that the next part of the table is a name
        name_field = self.program_map.get(address + 8)
        if not name_field:
            return False, None
        (name_line, name_flag) = name_field
        if name_flag != "data":
            return False, None

        name = self.extract_name(name_line)
        if not name or name == "None":
            return False, None

        cpp_class = CppClass(name)
        cpp_class.address = address
        self.program_map[address] = (line, "begin_rtti")

        i = 2
        while address + 8 * i in self.addresses:
            (parent_line, parent_flag) = self.program_map[address + 8 * i]
            i += 1
            if parent_flag in ["zeroes", "begin_rtti", "begin_vtable"]:
                break
            parent_name, _ = self.flag_rtti_recur(parent_line)
            if not parent_name:
                continue
            cpp_class.inherits_from.add(parent_name)

        self.classes.append(cpp_class)

        return name, cpp_class


def analyse(elf_file_name):

    analysis = ElfAnalysis(elf_file_name)

    analysis.extract_rtti_info()

    return analysis
