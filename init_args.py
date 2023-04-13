from __future__ import print_function

import argparse


def init_argparse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="hnrd.py", description="hunting newly registered domains"
    )
    parser.add_argument(
        "-d",
        action="store",
        dest="dfile",
        help="File containing new domain names",
        required=False,
    )
    parser.add_argument(
        "-f",
        action="store",
        dest="date",
        help="date [format: year-month-date]",
        required=False,
    )

    parser.add_argument(
        "-t",
        action="store",
        dest="date_end",
        help='Ending date (get domain names since date to ending date) [format: year-month-date or "yesterday"]',
        required=False,
        default=None,
    )

    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "-s", action="store", dest="search", help="Search a keyword", default=None, nargs="+"
    )
    selection.add_argument(
        "-S",
        action="store",
        dest="search_file",
        help="File to read list of keywords from (One word per line).",
        default=None,
    )
    selection.add_argument(
        "-r", action="store", dest="regex", help="Regex to be matched", default=None
    )

    parser.add_argument("-v", action="version", version="%(prog)s v1.0")
    parser.add_argument("--output", help="path to output file")
    args = parser.parse_args()
    return args


args = init_argparse()
