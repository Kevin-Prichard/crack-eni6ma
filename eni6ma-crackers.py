#!/usr/bin/env python3

import argparse
from collections import defaultdict as dd
import os
from statistics import fmean
import struct
import sys
from typing import Generator, List, Tuple

from psutil import Process


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        sys.stderr.write('error: %s\n' % message)
        self.print_help()


def get_args(argv: List[str]) -> Tuple[argparse.Namespace, ArgumentParser]:
    parser = ArgumentParser(
        prog='./crack-eni6ma.py',
        description='Replicate the Eni6ma login process, '
                    'taking snapshots of the panels, '
                    'then intersect them to find user\'s password')

    parser.add_argument('--password', '-p', dest='password', type=str, action='store', required=True)
    parser.add_argument('--iters', '-n', dest='iters', type=int, action='store', required=True, default=10)
    parser.add_argument('--progress', '-s', dest='progress', action='store_true', default=False)
    return parser.parse_args(argv), parser


process = Process(os.getpid())

ASCII = "".join(chr(i) for i in range(32, 127))
ASCII_LEN = len(ASCII)
PANELS_CHAR_LEN = 96
PANEL_LEN = PANELS_CHAR_LEN // 4
EMPTY_STR = ""

def rand_i32(upper_bound: int) -> Generator[int, None, int]:
    # returns random integer in the range: 0 .. upper_bound - 1
    with open("/dev/random", "rb") as rand_raw:  # ash
        while True:
            rand_val = abs(struct.unpack("I", rand_raw.read(4))[0])
            yield int(rand_val / 2 ** 32 * upper_bound)


def gen_4panels():
    randchars = [EMPTY_STR] * 24 * 4
    cp = 0

    while cp < ASCII_LEN:
        while True:
            ptr = next(rand_i32(PANELS_CHAR_LEN))
            if randchars[ptr] == EMPTY_STR:
                break
        randchars[ptr] = ASCII[cp]
        cp += 1

    return ["".join(randchars[i * PANEL_LEN:(i + 1) * PANEL_LEN]) for i in range(4)]


def perform_many_logins(passcode: str, end_after_iters: int) -> List[List[str]]:
    entries = dd(int)
    panelsets = []
    iters = 0

    while iters < end_after_iters:
        entry = []
        panelset = []
        # user entering a letter of their pin, password, passphrase..
        for c in passcode:

            # make a new set of random char panels
            p4 = gen_4panels()

            # user identifies which panel c exists in
            for panelnum in range(4):
                if t := c in p4[panelnum]:
                    # record panel number
                    entry.append(str(panelnum))

                    # record the panel in which correct pw char appeared
                    panelset.append(p4[panelnum])

                    break
            assert t

        # count occurrences of passed keypresses
        entries["".join(entry)] += 1
        iters += 1
        panelsets.append(panelset)

        # report a rise in repeats
        if iters % 10 == 0 and args.progress:
            print(iters, process.memory_info().rss)

    return entries, panelsets


def analyse_login_attempts(panelsets):
    pw_len = len(args.password)
    panels_merged = [set(panelsets[0][i]) for i in range(pw_len)]
    for panel_idx, panelset in enumerate(panelsets[1:]):
        for pn in range(pw_len):
            panels_merged[pn].intersection_update(panelset[pn])
        if (wut := sum(len(panels_merged[i]) for i in range(pw_len))) == pw_len:
            break

    return panels_merged, panel_idx + 1


def main(argv):
    global args
    args, parser = get_args(argv)

    # perform logins, snapshotting and collecting the panels
    buttons_pressed, panelsets = perform_many_logins(args.password, int(args.iters))

    # intersect snapshotted panels to find pw
    merged, actual_iters = analyse_login_attempts(panelsets)

    # print the password
    password_merged = "".join("".join(c for c in panel) for panel in merged)
    matched = password_merged == args.password
    print(f"Password discovered: {password_merged}, matches pw input? {matched}, cracked after n login sessions: {actual_iters}")


if __name__ == "__main__":
    main(sys.argv[1:])
