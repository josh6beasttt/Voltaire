#!/usr/bin/env python
import argparse
import os
import re
import sys
from subprocess import call
from sys import platform as _platform

# OS we're using
is_windows = _platform == "win32"

# Valid profiles
valid_profiles = dict.fromkeys(
    ["VistaSP0x64", "VistaSP0x86", "VistaSP1x64", "VistaSP1x86", "VistaSP2x64", "VistaSP2x86", "Win10x64",
     "Win10x86", "Win2003SP0x86", "Win2003SP1x64", "Win2003SP1x86", "Win2003SP2x64", "Win2003SP2x86",
     "Win2008R2SP0x64", "Win2008R2SP1x64", "Win2008SP1x64", "Win2008SP1x86", "Win2008SP2x64",
     "Win2008SP2x86", "Win2012R2x64", "Win2012x64", "Win7SP0x64", "Win7SP0x86", "Win7SP1x64", "Win7SP1x86",
     "Win81U1x64", "Win81U1x86", "Win8SP0x64", "Win8SP0x86", "Win8SP1x64", "Win8SP1x86", "WinXPSP1x64",
     "WinXPSP2x64", "WinXPSP2x86", "WinXPSP3x86"])


def filter_mutantscan(args):
    args["dest"] = os.path.abspath(args["dest"]) + os.sep
    logfile = "{path}ES{number}_{command}.txt".format(path=args["dest"], number=args["es"],
                                                      command="mutantscan -s")
    outfile = "{path}mutantscan_filter.txt".format(path=args["dest"])
    open_outfile = open(outfile, "w", encoding='utf-8')

    nameMap = {}

    with open(logfile, encoding='utf-8') as f:
        add_line_flag = 0
        open_outfile.write(next(f))
        open_outfile.write(next(f))
        for line in f:
            for word in line.split():
                if (not re.search("0x\w{16}|\.\.\.", word) and not word.isdigit()):
                    add_line_flag = 1


            if (add_line_flag == 1):
                nameMap[word] = line
                add_line_flag = 0

        for key in sorted(nameMap, key=lambda v: v.upper()):
            open_outfile.write(nameMap[key])


def filter_netscan(args):
    args["dest"] = os.path.abspath(args["dest"]) + os.sep
    logfile = "{path}ES{number}_{command}.txt".format(path=args["dest"], number=args["es"],
                                                      command="netscan")

    outfile = "{path}netscan_filter.txt".format(path=args["dest"])
    open_outfile = open(outfile, "w", encoding='utf-8')

    with open(logfile, encoding='utf-8') as f:
        add_line_flag = 0
        open_outfile.write(next(f))
        for line in f:
            for word in line.split():
                if(re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", word)):
                    add_line_flag = 1
                    #if(word == )

            if(add_line_flag == 1):
                open_outfile.write(line)
                add_line_flag = 0


def filter_pslist(args):
    path = os.path.abspath(args["dest"]) + os.sep
    logfile = "{path}ES{number}_{command}.txt".format(path=path, number=args["es"], command="pslist")

    with open(logfile, encoding='utf-8') as f:
        for line in f:
            command = "{command} -p {pid}".format(command="procmemdump", pid=line[3])
            args["dest"] = "{path}{dump}ES{number}_{pid}.txt".format(path=path, dump="procmemdump" + os.sep,
                                                                number=args["es"], pid=line[3])
            individual_scan(args, command)


def individual_scan(args, command):
    is_valid(args)

    program = os.path.abspath("vol.exe") if is_windows else "vol.py"

    run_command(args, program, command)


def scan(args):
    is_valid(args)

    program = os.path.abspath("vol.exe") if is_windows else "vol.py"

    for command in ["pslist", "pstree", "netscan", "psxview", "consoles", "psscan", "mutantscan -s", "cmdscan",
                    "dlllist", "filescan", "iehistory", "svcscan", "modules", "modscan", "sessions", "messagehooks",
                    "windows", "wintree", "clipboard", "deskscan"]:
        run_command(args, program, command)


def is_valid(args):
    args["src"] = "\"{path}\"".format(path=os.path.abspath(args["src"]))
    args["dest"] = os.path.abspath(args["dest"])

    if "src" in args:
        print("Source file: {src}".format(src=args["src"]))

    if "dest" in args:
        print("Destination directory: {dest}".format(dest=args["dest"]))

    if "profile" in args:
        if args["profile"] in valid_profiles:
            print("Profile name: {profile}".format(profile=args["profile"]))
        else:
            print("Profile not valid: {profile}".format(profile=args["profile"]))
            sys.exit(1)
    else:
        print("WARNING: No profile set!")

    if "es" in args:
        print("ES: {es}".format(es=args["es"]))
    else:
        print("NOTICE: No ES set. Defaulting to ES=1.")


def run_command(args, program, command):
    path = args["dest"] + os.sep
    outfile = "{path}ES{number}_{command}.txt".format(path=path, number=args["es"], command=command)

    if "profile" in args:
        params = "-f {src} --profile={profile} {command} --output-file=\"{dest}\"".format(src=args["src"],
                                                                                          profile=args["profile"],
                                                                                          command=command,
                                                                                          dest=outfile)
    else:
        params = "-f {src} {command} --output-file=\"{dest}\"".format(src=args["src"], command=command,
                                                                      dest=outfile)

    print("{program} {params}".format(program=program, params=params))
    result = call("{program} {params}".format(program=program, params=params))

    if result == 0:
        print("Completed {command}".format(command=command))
    else:
        print("Error running {command}".format(command=command))

    if is_windows:
        path = args["dest"] + os.sep
        outfile = "\"{outfile}\"".format(outfile="{path}ES{number}_autorun.txt".format(path=path, number=args["es"]))
        print("Starting {command}".format(command=command))

        if "profile" in args:
            params = "-f {src} --profile={profile} printkey \"Software\\Microsoft\\Windows\\CurrentVersion\\Run\" --output-file={dest}".format(
                src=args["src"], profile=args["profile"], dest=outfile)

        else:
            params = "-f {src} printkey \"Software\\Microsoft\\Windows\\CurrentVersion\\Run\" --output-file={dest}".format(
                src=args["src"], dest=outfile)

        result = call("{program} {params}".format(program=program, params=params))

        if result == 0:
            print("Completed autorun")
        else:
            print("Error running autorun \n " + params)

    print("Volatility files saved to {dest}".format(dest=args["dest"]))


def process(args):
    args["src"] = os.path.abspath(args["src"])
    args["dest"] = os.path.abspath(args["dest"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batches common Volatility commands")
    sub_parsers = parser.add_subparsers(dest="subparser_name")  # this line changed

    scan_parser = sub_parsers.add_parser('scan')
    scan_parser.set_defaults(which="scan")

    scan_parser.add_argument("-s", "--src", help="Input file", required=True)
    scan_parser.add_argument("-d", "--dest", help="Output directory", required=True)
    scan_parser.add_argument("-p", "--profile", help="Profile name", required=False)
    scan_parser.add_argument("-e", "--es", help="ES mode", default=1, required=False)

    process_parser = sub_parsers.add_parser("process")
    process_parser.set_defaults(which="process")

    process_parser.add_argument("-s", "--src", help="Input directory", required=True)
    process_parser.add_argument("-d", "--dest", help="Output directory", required=True)

    args = vars(parser.parse_args())

    subcommand = args.get("which", "")

    if "scan" == subcommand:
        scan(args)
        filter_mutantscan(args)
        filter_netscan(args)
        filter_pslist(args)
    elif "process" == subcommand:
        process(args)
    else:
        parser.print_help()
