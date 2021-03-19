from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86_const import *


class Analysis:
    """An analysis of an ELF file"""


def analyse(elf_file_name):
    f = open(elf_file_name, "rb")

    elffile = ELFFile(f)

    text_section = elffile.get_section_by_name(".text")

    rodata_section = elffile.get_section_by_name(".rodata")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # The number of vtable calls we find
    vtable_calls = 0

    # We keep a copy of the previous instructions, that will be of use in the loop
    prev_instructions = []

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
                        vtable_calls += 1

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
                                    vtable_calls += 1
                                    break

        # Here we keep track of the latest instructions
        prev_instructions.append(i)
        if len(prev_instructions) > 3:
            prev_instructions = prev_instructions[1:4]

    return vtable_calls
