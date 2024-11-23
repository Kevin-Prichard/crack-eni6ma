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
    """ Return a random integer in the range: 0 .. upper_bound - 1
        Utilises *nix system random number generator,
        which is typically hardware-generated on modern CPUs,
        and presumed to be of more even distribution compared to PRNGs.
    """
    with open("/dev/random", "rb") as rand_raw:  # ash
        while True:
            rand_val = abs(struct.unpack("I", rand_raw.read(4))[0])
            yield int(rand_val / 2 ** 32 * upper_bound)


def gen_4panels():
    # container for the randomized charset that will become the four panels
    randchars = [EMPTY_STR] * 24 * 4
    cp = 0

    # randomize the charset
    while cp < ASCII_LEN:
        while True:
            ptr = next(rand_i32(PANELS_CHAR_LEN))
            if randchars[ptr] == EMPTY_STR:
                break
        randchars[ptr] = ASCII[cp]
        cp += 1

    # Now break the randomized character set into four panels of n/4 chars each
    return ["".join(randchars[i * PANEL_LEN:(i + 1) * PANEL_LEN]) for i in range(4)]


def perform_many_logins(passcode: str, end_after_iters: int) -> List[List[str]]:
    """ Run a bunch of login attempts, ending upon end_after_iters attempts """

    # collect the number of repeats of button press patterns (useless info as panels are randomized)
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
                # user's knowledge of their passcode and current character position is
                # emulated here by checking each panel for the current user-known character

                if did_find := c in p4[panelnum]:
                    # once we've found the correct panel, acting also as observer we-
                    # 1. record the button number the user pressed
                    entry.append(str(panelnum))

                    # 2. record the panel the user indicated with the button press
                    panelset.append(p4[panelnum])

                    """ This is the sort of info a hacker would collect with a camera, 
                        or a keyboard sniffer and screen-copy util etc. """

                    # panel found, exit early
                    break

            # ensure that a panel is always found (hasn't failed yet)
            assert did_find

        # count occurrences of keypress patterns
        entries["".join(entry)] += 1
        iters += 1

        # accumulate panelsets, where each len(panelset) is equal to len(args.password)
        panelsets.append(panelset)

        # report a rise in repeats
        if iters % 10 == 0 and args.progress:
            print(iters, process.memory_info().rss)

    return entries, panelsets


def analyse_login_attempts(panelsets):
    pw_len = len(args.password)

    # Convert the first login session's panels to a list of sets
    # one set per panel, one panel per password character position
    panels_merged = [set(panelsets[0][i]) for i in range(pw_len)]

    # Now, compare user-selected panels across sessions via set intersection
    for login_session_idx, panelset in enumerate(panelsets[1:]):
        for pn in range(pw_len):
            panels_merged[pn].intersection_update(panelset[pn])

        # How many characters left after intersection?
        intersected_charsset_len = sum(len(panels_merged[i]) for i in range(pw_len))

        # Have we reached the user's password length?  Then exit
        if intersected_charsset_len == pw_len:
            break

    # This should equal the user's password, and the number of login sessions reviewed
    return panels_merged, login_session_idx + 1


def main(argv):
    global args
    args, parser = get_args(argv)

    # perform logins, snapshotting and collecting the panels
    buttons_pressed, panelsets = perform_many_logins(args.password, int(args.iters))

    # intersect snapshotted panels to find pw
    merged, actual_iters = analyse_login_attempts(panelsets)

    # Join the sets resulting from analysis
    password_merged = "".join("".join(c for c in panel) for panel in merged)

    # Does the joined reduced sets match the supplied password?
    matched = password_merged == args.password

    # print the password and results
    print(f"Password discovered: {password_merged}, matches pw input? {matched}, "
          f"cracked after n login sessions: {actual_iters}")


if __name__ == "__main__":
    main(sys.argv[1:])
