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

public_ip_addresses_to_exclude = '|'.join([
    "(^0\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^10\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^100\.(6[4-9]|[7-9][0-9]|1([0-1][0-9]|2[0-7]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^127\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^169\.254\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^172\.(1[6-9]|2[0-9]|3[0-1])\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^192\.0\.0\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^192\.0\.2\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^192\.88\.99\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^192\.168\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^198\.(1[8-9])\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^198\.51\.100\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^203\.0\.113\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^(2(2[4-9]|3[0-9]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))",
    "(^(2(4[0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])))"])

valid_ip_addresses = "^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))\.([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))"


def filter_mutantscan(args):
    path = os.path.abspath(args["dest"]) + os.sep
    logfile = "{path}ES{number}_{command}.txt".format(path=path, number=args["es"],
                                                      command="mutantscan -s")
    outfile = "{path}mutantscan_filter.txt".format(path=args["dest"] + os.sep)
    open_outfile = open(outfile, "w", encoding='utf-8')

    nameMap = {}

    with open(logfile, encoding='utf-8') as f:
        add_line_flag = 0
        open_outfile.write(next(f))
        open_outfile.write(next(f))
        for line in f:
            for word in line.split():
                if not re.search("0x\w{16}|\.\.\.", word) and not word.isdigit():
                    add_line_flag = 1

            if (add_line_flag == 1):
                nameMap[word] = line
                add_line_flag = 0

        for key in sorted(nameMap, key=lambda v: v.upper()):
            open_outfile.write(nameMap[key])


def filter_netscan(args):
    path = os.path.abspath(args["dest"]) + os.sep
    logfile = "{path}ES{number}_{command}.txt".format(path=path, number=args["es"],
                                                      command="netscan")

    outfile = "{path}netscan_filter.txt".format(path=args["dest"] + os.sep)
    open_outfile = open(outfile, "w", encoding='utf-8')

    with open(logfile, encoding='utf-8') as f:
        open_outfile.write(next(f))
        for line in f:
            if is_in_range(line):
                open_outfile.write(line)


def filter_pslist(args):
    path = os.path.abspath(args["dest"]) + os.sep
    logfile = "{path}ES{number}_{command}.txt".format(path=path, number=args["es"], command="pslist")
    program = os.path.abspath("vol.exe") if is_windows else "vol.py"

    with open(logfile, encoding='utf-8') as f:
        next(f)
        next(f)
        for line in f:
            words = line.split()
            command = "{command} -p {pid}".format(command="procdump", pid=words[2])
            run_command(args, program, command)


def individual_scan(args, command):
    program = os.path.abspath("vol.exe") if is_windows else "vol.py"

    run_command(args, program, command)


def scan(args):
    is_valid(args)

    program = os.path.abspath("vol.exe") if is_windows else "vol.py"

    for command in ["pslist", "pstree", "netscan", "psxview", "consoles", "psscan", "mutantscan -s", "cmdscan",
                    "dlllist", "filescan", "iehistory", "svcscan", "modules", "modscan", "sessions", "messagehooks",
                    "windows", "wintree", "clipboard", "deskscan"]:
        run_command(args, program, command)


def is_in_range(line):
    add_line_flag = 0
    for word in line.split():
        if re.search(valid_ip_addresses, word) and not re.search(public_ip_addresses_to_exclude, word):
            add_line_flag = 1
            break

    if add_line_flag == 1:
        return True
    else:
        return False


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
    outflag = "--output-file="

    if re.search("procdump", outfile):
        outflag = "--dump-dir="
        outfile = path + "procdump"

    if "profile" in args:
        params = "-f {src} --profile={profile} {command} {destflag}\"{dest}\"".format(src=args["src"],
                                                                                      profile=args["profile"],
                                                                                      command=command,
                                                                                      destflag=outflag,
                                                                                      dest=outfile)
    else:
        params = "-f {src} {command} {destflag}\"{dest}\"".format(src=args["src"], command=command, destflag=outflag,
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

        if re.search("procdump", outfile):
            outflag = "--dump-dir="
            outfile = path + "procdump"

        if "profile" in args:
            params = "-f {src} --profile={profile} printkey \"Software\\Microsoft\\Windows\\CurrentVersion\\Run\" {destflag}{dest}".format(
                src=args["src"], profile=args["profile"], destflag=outflag, dest=outfile)

        else:
            params = "-f {src} printkey \"Software\\Microsoft\\Windows\\CurrentVersion\\Run\" {destflag}{dest}".format(
                src=args["src"], destflag=outflag, dest=outfile)

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
