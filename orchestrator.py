#!/usr/bin/env python3

import subprocess
import argparse
import os

## Color Coding.
INFORMATION = "\033[96m"      ## Bright cyan.
WARNING = "\033[93m"          ## Bright yellow.
SUCCESS = "\033[32m"          ## Green.
FAILURE = "\033[91m"          ## Bright red.
RESET = "\033[0m"             ## Default colors back.

def parse_args():
    parser = argparse.ArgumentParser(description = "Decompile binaries in batch mode and export their results.")

    parser.add_argument("mode", choices = ["single", "separate"], help = "Export mode: 'single' for one file, 'separate' for separate files.")
    parser.add_argument("binary", help = "Path to the binary files to analyze.")
    parser.add_argument("output", help = "Directory to export the decompiled results.")

    return parser.parse_args()

def get_binaries(path):
    bins_list = []
    print(f"{INFORMATION}[*]{RESET} Binaries are being loaded ...")

    for (directory, _, names) in os.walk(f"{path}", topdown=True):
        bins_path = directory
        bin_names = names

        for bin_name in bin_names:
            full_path = bins_path + "/" + bin_name
            bins_list.append({"path": full_path, "name": bin_name})
    
    return bins_list

def run_headless(mode, bins, output_dir):
    errors = []

    try:
        for bin in bins:
            ## Set up the required parameters for Ghidra's headless.
            project_directory = f"/home/remnux/Desktop/Final_Experement/SAST_On_SRE_Final/Test_Ground_Ghidra_Projects/" ## Change me!
            project_name = f"{bin['name']}" ## Change me!

            ## Command to run.
            cmd = [
                "analyzeHeadless",
                project_directory,
                project_name,
                "-import", bin["path"],
                "-scriptPath", ".", ## Change me if you move decompiler.py
                "-postScript", "decompiler.py", mode, output_dir, bin['name'],
                "-recursive",
                "-overwrite",
                "-deleteProject"
            ]

            print(f"{INFORMATION}[*] {bin['name']}{RESET} is being processed ...")

            ## Fire up analyzeHeadless.
            ps = subprocess.run(cmd, capture_output = True, text = True)

            if ps.returncode:
                error_info = {
                    "path": bin["path"],
                    "code": ps.returncode,
                    "stderr": ps.stderr
                }

                print(f"{WARNING}[!]{RESET} Something went wrong when analyzing {bin['name']}")

                errors.append(error_info)

            print(f"{SUCCESS}[+] {bin['name']}{RESET} was processed successfully.")
    
    except KeyboardInterrupt:
        print(f"\n{WARNING}[!]{RESET} CTRL+C detected!")

        if len(errors):
            print(f"{WARNING}[!]{RESET} Writing partial errors before exiting ...")

    finally:
        if len(errors):
            with open("./error_log.txt", "w") as error_log:
                for error in errors:
                    error_log.write(f"{error}\n")

def main(args):
    print(f"{INFORMATION}[*]{RESET} Mode selected: {args.mode}.")
    print(f"{INFORMATION}[*]{RESET} Binaries path: {args.binary}.")
    print(f"{INFORMATION}[*]{RESET} Output directory: {args.output}.")

    ## A list to hold all the binary file names to be analyzed.
    bins = get_binaries(args.binary)

    print(f"{INFORMATION}[*]{RESET} Analyses started ...")
    run_headless(args.mode, bins, args.output)
    print(f"{INFORMATION}[*]{RESET} Analyses finished.")

if __name__ == "__main__":
    args = parse_args()
    main(args)
