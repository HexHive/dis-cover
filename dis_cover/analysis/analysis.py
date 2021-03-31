from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86_const import *
from itanium_demangler import parse as demangle


class CppClass:
    def __init__(self, name):
        self.name = name
        self.inherits_from = set()


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

    def get_section_name(self, addr):
        if addr < 0:
            return "out of bounds"
        for (end, name) in self.sections:
            if addr < end:
                return name
        return "out of bounds"

    def extract_name(self, addr):
        section_name = self.get_section_name(addr)
        section = self.elffile.get_section_by_name(section_name)
        section_data = section.data()
        relative_address = addr - section["sh_addr"]
        if relative_address >= 0 and relative_address < len(section_data):
            name = "_Z"
            while (
                relative_address < len(section_data)
                and section_data[relative_address] != 0
            ):
                name += chr(section_data[relative_address])
                relative_address += 1
            return demangle(name)

    def find_table(self, addr):
        for table in self.tables:
            if table.address == addr:
                return table

    def __str__(self):
        output = "Analysis of %s\n" % self.file_name
        vtables = filter(lambda t: t.is_vtable, self.tables)
        return output + "\n".join([str(table) for table in vtables])

    def get_classes(self):
        classes = []
        rttis = filter(lambda t: t.is_RTTI, self.tables)
        for rtti in rttis:
            cpp_class = CppClass(rtti.get_name())
            if len(rtti.inherits_from) > 0:
                cpp_class.inherits_from = {t.get_name() for t in rtti.inherits_from}
            classes.append(cpp_class)
        return classes

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


def analyse(elf_file_name):

    analysis = ElfAnalysis(elf_file_name)

    analysis.extract_vtables()
    analysis.find_vfunc_calls()

    return analysis
