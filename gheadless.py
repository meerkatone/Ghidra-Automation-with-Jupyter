import csv
from ghidra.program.util import DefinedDataIterator, CyclomaticComplexity

dangerous_functions = ["system", "execve", "execle", "execvp", "execlp", "doSystemCmd"]

fm = currentProgram.getFunctionManager()

# Collecting information
files = currentProgram.getName()
arches = currentProgram.getLanguage().toString()
hashes = currentProgram.getExecutableSHA256()
strings = [str(s) for s in DefinedDataIterator.definedStrings(currentProgram)]
all_funcs = list(fm.getFunctions(True))
total_cc = 0
system_xrefs_details = []

# Find dangerous functions and their xrefs
for func in all_funcs:
    if func.getName() in dangerous_functions:
        entry_point = func.getEntryPoint()
        references = getReferencesTo(entry_point)
        for xref in references:
            # Fetching the referencing function details
            ref_func = fm.getFunctionContaining(xref.getFromAddress())
            if ref_func:
                # Collecting address and function name
                detail = "{} ({})".format(xref.getFromAddress(), ref_func.getName())
                system_xrefs_details.append(detail)

num_calls_in_system_xrefs = len(system_xrefs_details)

# Calculating average cyclomatic complexity
for func in all_funcs:
    total_cc += CyclomaticComplexity().calculateCyclomaticComplexity(func, monitor)

# Calculating average cyclomatic complexity
num_funcs = len(all_funcs)
average_cc = total_cc / num_funcs if num_funcs > 0 else 0

# Saving results to CSV
csv_file_path = "./ghidratest.csv"
with open(csv_file_path, mode="a") as csv_file:
    fieldnames = [
        "File",
        "Architecture",
        "SHA256",
        "Strings",
        "Functions",
        "System_Xrefs",
        "Total_System_Xrefs",
        "Average_Cyclomatic_Complexity",
    ]
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

    # Writing data
    writer.writerow(
        {
            "File": files,
            "Architecture": arches,
            "SHA256": hashes,
            "Strings": ", ".join(strings),
            "Functions": ", ".join([str(func) for func in all_funcs]),
            "System_Xrefs": "; ".join(system_xrefs_details),
            "Total_System_Xrefs": num_calls_in_system_xrefs,
            "Average_Cyclomatic_Complexity": round(average_cc, 2),
        }
    )
