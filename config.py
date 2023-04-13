import pathlib
from typing import Final

from init_args import args

ROOT_PATH: Final[pathlib.Path] = pathlib.Path(__file__).parent
RESULT_STORAGE: Final[pathlib.Path] = ROOT_PATH.joinpath("result_storage")
RESULT_STORAGE.mkdir(exist_ok=True)

RESULTS_OF_SCAN_STORAGE: Final[pathlib.Path] = RESULT_STORAGE.joinpath("result_of_scan_storage")
RESULTS_OF_SCAN_STORAGE.mkdir(exist_ok=True)

DNS_FILE: Final[pathlib.Path] = RESULTS_OF_SCAN_STORAGE.joinpath("dns_scan.json")
IP2ASN_FILE: Final[pathlib.Path] = RESULTS_OF_SCAN_STORAGE.joinpath("ip2asn_scan.json")
CERTIFICATES_FILE: Final[pathlib.Path] = RESULTS_OF_SCAN_STORAGE.joinpath("certificates_scan.json")
VIRUS_TOTAL_FILE: Final[pathlib.Path] = RESULTS_OF_SCAN_STORAGE.joinpath("virus_total_scan.json")
QUAD9_FILE: Final[pathlib.Path] = RESULTS_OF_SCAN_STORAGE.joinpath("quad9_scan.json")
SHANNON_ENTROPY_FILE: Final[pathlib.Path] = RESULTS_OF_SCAN_STORAGE.joinpath("shannon_entropy_scan.json")

FINAL_RESULT_FILE: Final[pathlib.Path] = RESULT_STORAGE.joinpath(args.output)
