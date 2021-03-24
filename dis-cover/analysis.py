from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86_const import *
from itanium_demangler import parse as demangle


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
            return self.name
        elif self.is_vtable and self.associated_RTTI:
            return self.associated_RTTI.get_name()
        return "Unknown Name"


class Analysis:
    """An analysis of an ELF file"""

    def __init__(self, file_name):
        self.tables = []
        self.vfunc_calls = 0
        f = open(file_name, "rb")
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
        section_name = self.get_section_name(int(addr, 16))
        section = self.elffile.get_section_by_name(section_name)
        section_data = section.data()
        relative_address = int(addr, 16) - section["sh_addr"]
        if relative_address > 0 and relative_address < len(section_data):
            # name = '_ZTS'
            name = ""
            while (
                relative_address < len(section_data)
                and section_data[relative_address] != 0
            ):
                name += chr(section_data[relative_address])
                relative_address += 1
            # print(demangle(name))
            return name

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

        # Step 1 : See what parts of the data section are referenced to in the code

        # TODO

        # Step 2 : Find all potential tables by finding empty spaces that might
        #          be the offset-to-top section, and create a Table for them.

        data_section = self.elffile.get_section_by_name(".data.rel.ro")
        data = data_section.data()

        print("\n\tAnalysis of the .data.rel.ro section")

        current_address = data_section["sh_addr"]

        for i in range(round(len(data) / 8)):
            line = list(data[8 * i : 8 * i + 8])
            line.reverse()
            line_str = "".join([format(d, "02x") for d in line])
            address = int(line_str, 16)
            section = self.get_section_name(address)

            entry = Entry(current_address, line_str, section)

            if entry.is_offset_to_top():
                print()
                self.tables.append(Table(current_address))

            self.tables[-1].entries.append(entry)

            print(entry)

            current_address += 8

        # Step 3 : Differenciate between vtables and their associated RTTI by
        #          finding the pointers to RTTIs at the beginning of the vtables
        #          and in other related RTTIs.

        for table in self.tables:
            for (i, entry) in enumerate(table.entries):
                # If the first entry after the offset_to_top is a pointer to
                # an RTTI, then the table is a vtable.
                if i == 1 and entry.section == ".data.rel.ro":
                    table.is_vtable = True
                    # TODO find the table object associated with this address
                    table.associated_RTTI = entry.value
                # Else if the first entry after the offset_to_top is a pointer
                # to __type_name, then the table is an RTTI.
                elif i == 1 and entry.section == ".rodata":
                    table.is_RTTI = True
                    table.name = self.extract_name(entry.value)
                    print(table.name)
                # Else if the table is an RTTI and the entry is a pointer to
                # another RTTI, then there is inheritance.
                elif table.is_RTTI and entry.section == ".data.rel.ro":
                    # TODO find the table object associated with this address
                    table.inherits_from.append(entry.value)


def analyse(elf_file_name):

    analysis = Analysis(elf_file_name)

    analysis.extract_vtables()
    analysis.find_vfunc_calls()

    return analysis
