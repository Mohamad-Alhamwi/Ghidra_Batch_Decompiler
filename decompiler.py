# A Ghidra headless script that filters out runtime symbols, decompiles the
# remaining functions of a given binary, and exports the results either into
# separate .c files per function or into a single file, depending on the mode.
# @author Mohamad Alhamwi

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import fnmatch
import os

## Color Coding.
INFORMATION = "\033[96m"      ## Bright cyan.
WARNING = "\033[93m"          ## Bright yellow.
SUCCESS = "\033[32m"          ## Green.
FAILURE = "\033[91m"          ## Bright red.
RESET = "\033[0m"             ## Default colors back.

## A list of functions to be checked against.
runtime_symbols = {
    "_init",
    "_fini",
    "_start",
    "entry",
    "__libc_start_main",
    "frame_dummy",
    "__do_global_dtors_aux",
    "register_tm_clones",
    "deregister_tm_clones",
    "__gmon_start__",
    "__cxa_finalize"
}

## A list of function patterns to be checked against.
runtime_symbol_patterns = {
    "_ITM_*",
    "__libc_csu_*",
    "_DT_*"
}

## Optional filters to suppress noise.
SKIP_EXTERNAL = True
SKIP_THUNKS = True

def is_runtime_by_pattern(function_name):
    for pattern in runtime_symbol_patterns:
        if fnmatch.fnmatchcase(function_name, pattern):
            return True

    return False

def get_functions(program):
    ## A list to hold all functions inside the current program.
    all_functions = []
    ## A list to hold functions to be excluded in analysis.
    excluded_functions = set()
    ## A list to hold functions to be included in analysis.
    included_functions = set()
    
    ## Get a FunctionManager reference for the current program.
    function_manager = program.getFunctionManager()
    ## Get a list of all the functions inside the current program.
    functions = function_manager.getFunctions(True)

    for function in functions:
        function_name = function.getName()
        all_functions.append(function)

        if SKIP_EXTERNAL and function.isExternal():
            continue

        if SKIP_THUNKS and function.isThunk():
            continue

        if is_runtime_by_pattern(function_name):
            excluded_functions.add(function)
            continue
        
        if function_name in runtime_symbols:
            excluded_functions.add(function)
            continue
    
        included_functions.add(function)

    return all_functions, excluded_functions, included_functions

def print_functions(caption, functions):    
    print(f"\n{caption}:")

    for function in functions:
        print(f"{INFORMATION}[*] {function.getEntryPoint()}{RESET}: {function.getName()}")

    return None

def get_current_program():
    state = getState()
    current_program = state.getCurrentProgram()

    return current_program

def decompile(program, functions):
    decompiler = DecompInterface()
    decompiler.openProgram(program)

    results = []

    # Decompile the given functions.
    for function in functions:
        result = decompiler.decompileFunction(function, 0, ConsoleTaskMonitor())
        results.append(result)
        
    return results

def check_decompilation_results(results):
    decompiled_functions = []
    failed_functiones = []

    print(f"\n{INFORMATION}[*]{RESET} Decompilation Results:")
    for result in results:
        ## Check for error conditions.
        if result.decompileCompleted():
           print(f"{SUCCESS}[+]{RESET} Function {result.getFunction().getName()} is decompiled successfully.")
           decompiled_functions.append((result.getFunction().getName(), result.getDecompiledFunction().getC()))

        else:
            print(f"{WARNING}[!]{RESET} An error occured while decompiling the function {result.getFunction().getName()}")
            failed_functiones.append(result.getFunction().getName())
            print(f"{FAILURE}[-]{RESET} {result.getErrorMessage()}")

    return decompiled_functions, failed_functiones

def export_separate(functions, output_dir, parent_dir):
    parent_dir_name = os.path.splitext(parent_dir)[0]
    os.makedirs(os.path.join(output_dir, parent_dir_name), exist_ok=True)

    for function in functions:
        file_name = os.path.join(output_dir, parent_dir_name, f"{function[0]}.c")

        with open(file_name, "w") as file:
            file.write(function[1])
    
    print(f"\n{SUCCESS}[+]{RESET} Decompiled code exported successfully into {output_dir}.")

    return None

def main():
    ## Get the current program instance.
    program = get_current_program()
    all_functions, excluded_functions, included_functions = get_functions(program)

    ## Get arguments.
    args = getScriptArgs()
    print("Ghidra script args:", args)

    mode = args[0]
    output_dir = args[1]
    current_bin_name = args[2]

    print_functions(f"{INFORMATION}[*]{RESET} All functions", all_functions)
    print_functions(f"{INFORMATION}[*]{RESET} Excluded functions", excluded_functions)
    print_functions(f"{INFORMATION}[*]{RESET} Included functions", included_functions)

    decompilation_results = decompile(program, included_functions)

    decompiled_functions, _ = check_decompilation_results(decompilation_results)

    if mode == "separate":
        export_separate(decompiled_functions, output_dir, current_bin_name)

    elif mode == "single":
        export_single(decompiled_functions, output_dir, current_bin_name)

    return None

if __name__ == "__main__":
    main()
