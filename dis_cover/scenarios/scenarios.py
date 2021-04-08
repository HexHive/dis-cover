from elftools.elf.elffile import ELFFile
from elftools.dwarf.enums import ENUM_DW_TAG
from .compilation import compile_under_scenario
from ..analysis import analyse, CppClass

COMPILERS = [
    "clang++",
    "g++",
]

OPTIONS = [
    "-O0",
    "-O1",
    "-O2",
    "-O3",
    "-Os",
    "-fno-exceptions",
    "-fno-unwind-tables",
    # "-fno-rtti",
]


class Color:
    END = "\033[0m"
    BOLD = "\033[1m"
    ON_RED = "\033[41m"
    ON_GREEN = "\033[42m"
    ON_YELLOW = "\033[43m"


class DwarfAnalysis:
    def __init__(self):
        self.classes = []

    def get_classes(self):
        return self.classes


def extract_dwarf_data(source_file_name, output_directory):
    compiled_with_dwarf = compile_under_scenario(
        source_file_name, ("clang++", "-gdwarf"), output_directory
    )
    elf_with_dwarf = ELFFile(open(compiled_with_dwarf, "rb"))
    return elf_with_dwarf.get_dwarf_info()


def extract_namespace(DIE):
    parent = DIE.get_parent()
    if parent and parent.tag == "DW_TAG_namespace":
        namespace = parent.attributes["DW_AT_name"].value.decode("UTF-8")
        namespace += "::"
        return namespace + extract_namespace(parent)
    else:
        return ""


def analyse_dwarf(dwarf_info):
    classes = dict()
    # For each Compile Unit
    for CU in dwarf_info.iter_CUs():
        offset = CU.cu_offset
        # For every Debugging Information Entry
        for DIE in CU.iter_DIEs():
            # If the DIE describes a class
            if DIE.tag == "DW_TAG_class_type":
                # Get the class' name
                name_attr = DIE.attributes["DW_AT_name"]
                name = name_attr.value.decode("UTF-8")
                # Extract the namespace by going up the tree
                namespace = extract_namespace(DIE)
                # Append the namespace to the name
                name = namespace + name
                # Compute the DIE's offset
                class_offset = DIE.offset - offset
                # Create an entry in the dictionary
                classes[(name, class_offset)] = []
                # We now look for the parents of the class
                for child in DIE.iter_children():
                    if child.tag == "DW_TAG_inheritance":
                        type_attr = child.attributes["DW_AT_type"]
                        parent_offset = type_attr.value
                        classes[(name, class_offset)].append(parent_offset)

    # We now fill out the analysis object
    dwarf_analysis = DwarfAnalysis()
    cpp_classes = []
    for c in classes:
        cpp_class = CppClass(c[0])
        inherits_from = classes[c]
        # We find the name from the offset for every parent of the class
        for i in inherits_from:
            parent_name = [p[0] for p in classes if p[1] == i][0]
            cpp_class.inherits_from.add(parent_name)
        cpp_classes.append(cpp_class)
    dwarf_analysis.classes = cpp_classes

    return dwarf_analysis


def compare_results(elf, dwarf):

    elf_classes = elf.get_classes()
    successes = 0
    exceptions = []

    for dwarf_class in dwarf.get_classes():
        elf_class = next((e for e in elf_classes if e.name == dwarf_class.name), None)
        if elf_class and elf_class.inherits_from == dwarf_class.inherits_from:
            successes += 1
        else:
            exceptions.append(dwarf_class.name)

    output = "%3.f%%" % (100 * successes / (len(dwarf.get_classes()) or 1))

    # Add some color to the output 💅
    if successes == 0:
        # Red for failure
        output = "%s%s%s" % (Color.ON_RED, output, Color.END)
    elif successes == len(dwarf.get_classes()):
        # Green for success
        output = "%s%s%s" % (Color.ON_GREEN, output, Color.END)
    else:
        # Yellow otherwise
        output = "%s%s%s" % (Color.ON_YELLOW, output, Color.END)

    return output, exceptions


def run_scenarios(source_file_name, output_directory):

    # Extract the dwarf data from the source
    dwarf_info = extract_dwarf_data(source_file_name, output_directory)
    # Analyze the dwarf data to compare it later with what we find
    dwarf_results = analyse_dwarf(dwarf_info)

    # Print in bold the source file name
    print("%sRunning scenario for %s%s" % (Color.BOLD, source_file_name, Color.END))
    # For each compiler
    for compiler in COMPILERS:
        # And each compiler option
        for option in OPTIONS:
            # Compile with the given compiler and option
            elf_file_name = compile_under_scenario(
                source_file_name, (compiler, option), output_directory
            )
            # Run the analysis
            results = analyse(elf_file_name)
            # Compare the results with the dwarf results
            output, exceptions = compare_results(results, dwarf_results)
            print("%s classes recovered (%s %s)" % (output, compiler, option))
            for exception in exceptions:
                print("  %s not recovered" % exception)
