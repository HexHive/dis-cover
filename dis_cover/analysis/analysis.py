import struct
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86_const import *
from itanium_demangler import parse as demangle


DATA_SECTIONS = [".rodata", ".data.rel.ro", ".data.rel.ro.local", ".rdata"]
FUNCTION_SECTIONS = [".text", ".plt", ".extern"]


class CppClass:
    def __init__(self, name):
        self.name = name
        self.inherits_from = set()
        self.address = None

    def __str__(self):
        output = "class"
        output += "\t%s" % self.name
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


class Entry:
    """A table entry"""

    def __init__(self, address, value, section):
        self.address = address
        self.value = value
        self.section = section

        description = "?"
        if self.is_offset_to_top():
            description = "Offset-to-Top"
        elif self.section == ".data.rel.ro":
            description = "&RTTI"
        elif self.section == ".text":
            description = "&Function-Entry"
        elif self.section == ".rodata":
            description = "&__type_name"
        self.description = description

    def is_offset_to_top(self):
        return int(self.value, 16) == 0

    def __str__(self):
        return "\t\t0x%x\t%s\t[%s]" % (self.address, self.value, self.description)


class Table:
    """A vtable or RTTI table"""

    def __init__(self, address):
        self.address = address
        self.is_RTTI = False
        self.is_vtable = False
        self.entries = []
        self.inherits_from = []
        self.associated_RTTI = None

    def get_name(self):
        if self.is_RTTI:
            return str(self.name)
        elif self.is_vtable and self.associated_RTTI:
            return self.associated_RTTI.get_name()
        return "Unknown"

    def get_methods_count(self):
        return len(filter(lambda e: e.section == ".text", self.entries))

    def __str__(self):
        output = ""
        if self.is_RTTI:
            output += "RTTI "
        elif self.is_vtable:
            output += "class "
        else:
            output += "unknown "
        output += "\t%s" % self.get_name()
        if self.associated_RTTI and len(self.associated_RTTI.inherits_from) > 0:
            output += "\tinherits from %s" % ", ".join(
                [t.get_name() for t in self.associated_RTTI.inherits_from]
            )
        return output


class ElfAnalysis:
    """An analysis of an ELF file"""

    def __init__(self, file_name):
        self.tables = []
        self.vfunc_calls = 0
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

    def find_table(self, addr):
        for table in self.tables:
            if table.address == addr:
                return table

    def __str__(self):
        output = "Analysis of %s\n" % self.file_name
        return output + "\n".join([str(c) for c in self.get_classes()])

    def get_classes(self):
        return self.classes

    def find_vfunc_calls(self):

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        # We keep a copy of the previous instructions, that will be of use in the loop
        prev_instructions = []

        text_section = self.elffile.get_section_by_name(".text")

        # For each instruction in the disassembly of the `.text` section
        for i in md.disasm(text_section.data(), text_section["sh_addr"]):

            # If the instruction is a `call`
            if i.id == X86_INS_CALL:

                # If one of the previous instructions was a `mov` and moved a pointer to RDI
                for prev in prev_instructions:
                    if (
                        prev.id == X86_INS_MOV
                        and prev.operands[0].reg == X86_REG_RDI
                        and prev.operands[1].type == X86_OP_REG
                    ):

                        # If the call's operand is a memory address
                        if i.operands[0].type == X86_OP_MEM:
                            self.vfunc_calls += 1

                        # If the call's operand is a register
                        elif i.operands[0].type == X86_OP_REG:
                            # If that register was just assigned a memory address
                            for other_prev in prev_instructions:
                                if other_prev.id == X86_INS_MOV:
                                    assigned = other_prev.operands[0]
                                    value = other_prev.operands[1]
                                    if (
                                        assigned.type == X86_OP_REG
                                        and assigned.reg == i.operands[0].reg
                                        and value.type == X86_OP_MEM
                                    ):
                                        self.vfunc_calls += 1
                                        break

            # Here we keep track of the latest instructions
            prev_instructions.append(i)
            if len(prev_instructions) > 3:
                prev_instructions = prev_instructions[1:4]

    def extract_vtables(self):

        # Step 1 : Find all potential tables by finding empty spaces that might
        #          be the offset-to-top section, and create a Table for them.

        data_section = self.elffile.get_section_by_name(".data.rel.ro")

        # If there is no .data.rel.ro, we cannot extract vtable information
        if not data_section:
            return

        data = data_section.data()

        current_address = data_section["sh_addr"]

        for i in range(round(len(data) / 8)):
            line = list(data[8 * i : 8 * i + 8])
            line.reverse()
            line_str = "".join([format(d, "02x") for d in line])
            address = int(line_str, 16)
            section = self.get_section_name(address)

            entry = Entry(current_address, line_str, section)

            if entry.is_offset_to_top():
                self.tables.append(Table(current_address))

            if len(self.tables):
                self.tables[-1].entries.append(entry)

            current_address += 8

        # Step 2 : Differenciate between vtables and their associated RTTI by
        #          finding the pointers to RTTIs at the beginning of the vtables
        #          and in other related RTTIs.

        for table in self.tables:
            for (i, entry) in enumerate(table.entries):
                # If the first entry after the offset_to_top is a pointer to
                # an RTTI, then the table is a vtable.
                if i == 1 and entry.section == ".data.rel.ro":
                    table.is_vtable = True
                    pointer_address = int(entry.value, 16)
                    table.associated_RTTI = self.find_table(pointer_address)
                # Else if the first entry after the offset_to_top is a pointer
                # to __type_name, then the table is an RTTI.
                elif i == 1 and entry.section == ".rodata":
                    table.is_RTTI = True
                    pointer_address = int(entry.value, 16)
                    table.name = self.extract_name(pointer_address)
                # Else if the table is an RTTI and the entry is a pointer to
                # another RTTI, then there is inheritance.
                elif table.is_RTTI and entry.section == ".data.rel.ro":
                    pointer_address = int(entry.value, 16)
                    table.inherits_from.append(self.find_table(pointer_address))

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
                elif section in FUNCTION_SECTIONS:
                    flag = "function"
                elif line_int == 0:
                    flag = "zeroes"
                elif line_int <= 16777216:
                    flag = "offset_to_top"

                self.program_map[base_address + offset] = (line_int, flag)

        self.addresses = list(self.program_map.keys())
        self.addresses.sort()

        # Add "begin_vtable" and "begin_rtti" flags
        # Append CppClass objects to self.classes
        for address in self.addresses:
            (line, flag) = self.program_map[address]
            # First we find out if this is the beginning of a vtable
            if flag in ["offset_to_top", "zeroes"] and address + 8 in self.addresses:
                (next_line, next_flag) = self.program_map[address + 8]
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

        if flag not in ["unknown", "offset_to_top", "zeroes"]:
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

    # analysis.find_vfunc_calls()
    # analysis.extract_vtables()
    analysis.extract_rtti_info()

    return analysis
