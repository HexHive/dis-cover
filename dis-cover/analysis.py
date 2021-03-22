from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86_const import *


class Analysis:
    """An analysis of an ELF file"""


def extract_vtables(data_section):

    # Step 1 : See what parts of the data section are referenced to in the code

    # TODO

    # Step 2 : Find all potential vtables by finding empty spaces that might
    #          be the offset-to-top section.

    # TODO

    # Step 3 : Differenciate between vtables and their associated RTTI by
    #          finding the pointers to RTTIs at the beginning of the vtables
    #          and in other related RTTIs.

    # TODO

    data = data_section.data()
    for i in range(round(len(data) / 8)):
        print("".join([format(d, '02x') for d in data[8 * i:8 * i + 8]]))

"""

vtable for A
0000000000000000 => Offset-to-top
783d000000000000 => -> ZTI1A (Pointer to A, RTTI, Run-Time Type Information)
9a11000000000000 => -> ZN1A1fEv (Pointer to A->f)

RTTI for A
0000000000000000 => ZTI1A
0420000000000000 => ZTI1A

vtable for B
0000000000000000 => Offset-to-top
a03d000000000000 => -> ZTI1B (Pointer to B, RTTI, Run-Time Type Information)
9c11000000000000 => -> ZN1B1fEv (Pointer to B->f)

RTTI for B
0000000000000000 => ZTI1B
0720000000000000 => ZTI1B
783d000000000000 => -> ZTI1A (parent)

"""

def find_vfunc_calls(text_section):

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    # The number of vfunc calls we find
    vfunc_calls = 0

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
                        vfunc_calls += 1

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
                                    vfunc_calls += 1
                                    break

        # Here we keep track of the latest instructions
        prev_instructions.append(i)
        if len(prev_instructions) > 3:
            prev_instructions = prev_instructions[1:4]

    return vfunc_calls


def analyse(elf_file_name):
    f = open(elf_file_name, "rb")

    elffile = ELFFile(f)

    text_section = elffile.get_section_by_name(".text")

    data_section = elffile.get_section_by_name(".data.rel.ro")

    vtables = extract_vtables(data_section)
    vfunc_calls = find_vfunc_calls(text_section)

    return vfunc_calls
