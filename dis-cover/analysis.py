from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86_const import *


class Analysis:
    """An analysis of an ELF file"""

    vfunc_calls = 0

    def __init__(self, file_name):
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

        # Step 2 : Find all potential vtables by finding empty spaces that might
        #          be the offset-to-top section.

        data_section = self.elffile.get_section_by_name(".data.rel.ro")
        data = data_section.data()

        print("\n\tAnalysis of the .data.rel.ro section")

        current_address = data_section["sh_addr"]

        for i in range(round(len(data) / 8)):
            line = list(data[8 * i : 8 * i + 8])
            line.reverse()
            address_str = "".join([format(d, "02x") for d in line])
            address = int(address_str, 16)
            section = self.get_section_name(address)
            description = "?"
            if address == 0:
                description = "Offset-to-Top"
                print()
            elif section == ".data.rel.ro":
                description = "&RTTI"
            elif section == ".text":
                description = "&Function-Entry"
            elif section == ".rodata":
                description = "&__type_name"
            print("\t\t0x%x\t%s\t[%s]" % (current_address, address_str, description))
            current_address += 8

        # Step 3 : Differenciate between vtables and their associated RTTI by
        #          finding the pointers to RTTIs at the beginning of the vtables
        #          and in other related RTTIs.

        # TODO


def analyse(elf_file_name):

    analysis = Analysis(elf_file_name)

    analysis.extract_vtables()
    analysis.find_vfunc_calls()

    return analysis