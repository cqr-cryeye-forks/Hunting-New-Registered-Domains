from __future__ import print_function

import base64
import concurrent.futures
import datetime
import json
import os
import os.path
import re
import sys
import time
import warnings
import zipfile

# import Levenshtein
import dns.resolver
import requests
# import tldextract
# import whois
from bs4 import BeautifulSoup
from colorama import init
from termcolor import colored

from config import DNS_FILE, IP2ASN_FILE, CERTIFICATES_FILE, VIRUS_TOTAL_FILE, QUAD9_FILE, SHANNON_ENTROPY_FILE, \
    FINAL_RESULT_FILE, RESULTS_OF_SCAN_STORAGE
from init_args import args

init()

warnings.filterwarnings("ignore")


def DNS_Records(domain):
    RES = {}
    MX = []
    NS = []
    A = []
    AAAA = []
    SOA = []
    CNAME = []

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1

    rrtypes = ["A", "MX", "NS", "AAAA", "SOA"]
    for r in rrtypes:
        try:
            Aanswer = resolver.query(domain, r)
            for answer in Aanswer:
                if r == "A":
                    A.append(answer.address)
                    RES.update({r: A})
                if r == "MX":
                    MX.append(answer.exchange.to_text()[:-1])
                    RES.update({r: MX})
                if r == "NS":
                    NS.append(answer.target.to_text()[:-1])
                    RES.update({r: NS})
                if r == "AAAA":
                    AAAA.append(answer.address)
                    RES.update({r: AAAA})
                if r == "SOA":
                    SOA.append(answer.mname.to_text()[:-1])
                    RES.update({r: SOA})
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.name.EmptyLabel:
            pass
        except dns.resolver.NoNameservers:
            pass
        except dns.resolver.Timeout:
            pass
        except dns.exception.DNSException:
            pass
    return RES


def get_DNS_record_results():
    global IPs
    dns_result: list[dict] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(DOMAINS)
        ) as executor:
            future_to_domain = {
                executor.submit(DNS_Records, domain): domain for domain in DOMAINS
            }
            for future in concurrent.futures.as_completed(future_to_domain):

                dom = future_to_domain[future]
                print("---", colored(dom, "cyan"))

                try:
                    DNSAdata = future.result()
                    DNSAdata_2 = {}
                    for dns_record_type, dns_record_details in DNSAdata.items():
                        if dns_record_type == "A":
                            DNSAdata_2["address_record_ipv4"] = dns_record_details
                        elif dns_record_type == "AAAA":
                            DNSAdata_2["address_record_ipv6"] = dns_record_details
                        elif dns_record_type == "MX":
                            DNSAdata_2["mail_exchanger_record"] = dns_record_details
                        elif dns_record_type == "NS":
                            DNSAdata_2["nameserver_record"] = dns_record_details
                        elif dns_record_type == "SOA":
                            DNSAdata_2["start_of_authority_record"] = dns_record_details

                    dns_result.append(
                        {
                            "domain": dom,
                            "dns_details": DNSAdata_2,
                        }
                    )
                    for k, v in DNSAdata.items():

                        print("+", k, colored(",".join(v), "yellow"))
                        for ip in v:
                            aa = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)
                            if aa:
                                IPs.append(ip)

                except Exception as exc:
                    print(("%r generated an exception: %s" % (dom, exc)))
    except ValueError:
        pass

    final_result_of_dns_scan: list[dict] = []

    for collected_domain in dns_result:
        if collected_domain in final_result_of_dns_scan:
            c = 1
        final_result_of_dns_scan.append(collected_domain)

    DNS_FILE.write_text(json.dumps(dns_result))
    return IPs


def diff_dates(date1, date2):
    return abs((date2 - date1).days)


# def whois_domain(domain_name):
#     import time
#     import datetime
#
#     RES = {}
#
#     try:
#         w_res = whois.query(domain_name)
#         name = w_res.name
#         creation_date = w_res.creation_date
#         emails = w_res.emails
#         registrar = w_res.registrar
#         updated_date = w_res.last_updated
#         expiration_date = w_res.expiration_date
#
#         if (
#                 isinstance(creation_date, datetime.datetime)
#                 or isinstance(expiration_date, datetime.datetime)
#                 or isinstance(updated_date, datetime.datetime)
#         ):
#             current_date = datetime.datetime.now()
#             res = diff_dates(current_date, creation_date)
#             RES.update(
#                 {
#                     "creation_date": creation_date,
#                     "creation_date_diff": res,
#                     "emails": emails,
#                     "name": name,
#                     "registrar": registrar,
#                     "updated_date": updated_date,
#                     "expiration_date": expiration_date,
#                 }
#             )
#
#         elif (
#                 isinstance(creation_date, list)
#                 or isinstance(expiration_date, list)
#                 or isinstance(updated_date, list)
#         ):
#             creation_date = w_res.creation_date[0]
#             updated_date = w_res.last_updated[0]
#             expiration_date = w_res.expiration_date[0]
#             current_date = datetime.datetime.now()
#             res = diff_dates(current_date, creation_date)
#
#             RES.update(
#                 {
#                     "creation_date": creation_date,
#                     "creation_date_diff": res,
#                     "emails": emails,
#                     "name": name,
#                     "registrar": registrar,
#                     "updated_date": updated_date,
#                     "expiration_date": expiration_date,
#                 }
#             )
#
#         time.sleep(2)
#     except TypeError:
#         pass
#     except Exception:
#         print(colored("No match for domain: {}.".format(domain_name), "red"))
#     except AttributeError:
#         pass
#     return RES


def IP2CIDR(ip):
    from ipwhois.net import Net
    from ipwhois.asn import IPASN

    net = Net(ip)
    obj = IPASN(net)
    results = obj.lookup()
    return results


def get_IP2CIDR():
    ip2asn_result: list[dict] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(IPs)) as executor:
            future_to_ip2asn = {executor.submit(IP2CIDR, ip): ip for ip in IPs}
            for future in concurrent.futures.as_completed(future_to_ip2asn):
                ipaddress = future_to_ip2asn[future]
                print("  \_", colored(ipaddress, "cyan"))
                try:
                    data = future.result()
                    ip2asn_result.append(
                        {
                            "ip": ipaddress,
                            "details": data,
                        }
                    )
                    for k, v in data.items():
                        print("    \_", k, colored(v, "yellow"))

                except Exception as exc:
                    print(("%r generated an exception: %s" % (ipaddress, exc)))
            IP2ASN_FILE.write_text(json.dumps(ip2asn_result))

    except ValueError:
        pass
    x = 1


# def get_WHOIS_results():
#     global NAMES
#     try:
#         with concurrent.futures.ThreadPoolExecutor(
#                 max_workers=len(DOMAINS)
#         ) as executor:
#             future_to_whois_domain = {
#                 executor.submit(whois_domain, domain): domain for domain in DOMAINS
#             }
#             for future in concurrent.futures.as_completed(future_to_whois_domain):
#                 dwhois = future_to_whois_domain[future]
#                 try:
#                     whois_data = future.result()
#                     if whois_data:
#                         for k, v in whois_data.items():
#                             if "creation_date" in k:
#                                 cd = whois_data.get("creation_date")
#                             if "updated_date" in k:
#                                 ud = whois_data.get("updated_date")
#                             if "expiration_date" in k:
#                                 ed = whois_data.get("expiration_date")
#                             if "creation_date_diff" in k:
#                                 cdd = whois_data.get("creation_date_diff")
#                             if "name" in k:
#                                 name = whois_data.get("name")
#                             if "emails" in k:
#                                 email = whois_data.get("emails")
#                             if "registrar" in k:
#                                 reg = whois_data.get("registrar")
#
#                         if isinstance(email, list):
#                             print(
#                                 "  \_",
#                                 colored(dwhois, "cyan"),
#                                 "\n    \_ Created Date",
#                                 colored(cd, "yellow"),
#                                 "\n    \_ Updated Date",
#                                 colored(ud, "yellow"),
#                                 "\n    \_ Expiration Date",
#                                 colored(ed, "yellow"),
#                                 "\n    \_ DateDiff",
#                                 colored(cdd, "yellow"),
#                                 "\n    \_ Name",
#                                 colored(name, "yellow"),
#                                 "\n    \_ Email",
#                                 colored(",".join(email), "yellow"),
#                                 "\n    \_ Registrar",
#                                 colored(reg, "yellow"),
#                             )
#
#                             if isinstance(name, list):
#                                 for n in name:
#                                     NAMES.append(n)
#                             else:
#                                 NAMES.append(name)
#                         else:
#                             print(
#                                 "  \_ ",
#                                 colored(dwhois, "cyan"),
#                                 "\n    \_ Created Date",
#                                 colored(cd, "yellow"),
#                                 "\n    \_ Updated Date",
#                                 colored(ud, "yellow"),
#                                 "\n    \_ Expiration Date",
#                                 colored(ed, "yellow"),
#                                 "\n    \_ DateDiff",
#                                 colored(cdd, "yellow"),
#                                 "\n    \_ Name",
#                                 colored(name, "yellow"),
#                                 "\n    \_ Email",
#                                 colored(email, "yellow"),
#                                 "\n    \_ Registrar",
#                                 colored(reg, "yellow"),
#                             )
#
#                 except Exception as exc:
#                     print(("%r generated an exception: %s" % (dwhois, exc)))
#     except ValueError:
#         pass
#     return NAMES


def EmailDomainBigData(name):
    url = "http://domainbigdata.com/name/{}".format(name)
    session = requests.Session()
    session.headers[
        "User-Agent"
    ] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:42.0) Gecko/20100101 Firefox/42.0"
    email_query = session.get(url)
    email_soup = BeautifulSoup(email_query.text, "html5lib")
    emailbigdata = email_soup.find("table", {"class": "t1"})
    return emailbigdata


def get_EmailDomainBigData():
    CreatedDomains = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(NAMES)) as executor:
            future_to_rev_whois_domain = {
                executor.submit(EmailDomainBigData, name): name for name in set(NAMES)
            }
            for future in concurrent.futures.as_completed(future_to_rev_whois_domain):
                namedomaininfo = future_to_rev_whois_domain[future]
                try:
                    rev_whois_data = future.result()
                    print("  \_", colored(namedomaininfo, "cyan"))
                    CreatedDomains[:] = []
                    if rev_whois_data is not None:
                        for row in rev_whois_data.findAll("tr"):
                            if row:
                                cells = row.findAll("td")
                                if len(cells) == 3:
                                    CreatedDomains.append(
                                        colored(cells[0].find(text=True))
                                    )

                        print(
                            "    \_",
                            colored(
                                str(len(CreatedDomains) - 1)
                                + " domain(s) have been created in the past",
                                "yellow",
                            ),
                        )
                    else:
                        print(
                            "    \_",
                            colored(
                                str(len(CreatedDomains))
                                + " domain(s) have been created in the past",
                                "yellow",
                            ),
                        )
                except Exception as exc:
                    print(("%r generated an exception: %s" % (namedomaininfo, exc)))
    except ValueError:
        pass


def crt(domain_name):
    parameters = {"q": f"%.{domain_name}", "output": "json"}
    headers = {
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0",
        "content-type": "application/json",
    }
    response = requests.get("https://crt.sh/?", params=parameters, headers=headers)
    content = response.content.decode("utf-8")
    return json.loads("{}".format(content.replace("}{", "},{")))


def getcrt():
    try:
        certificates_result: list[dict] = []
        max_workers: int = len(NAMES) or 10
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_crt = {executor.submit(crt, domain_name): domain_name for domain_name in DOMAINS}
            for future in concurrent.futures.as_completed(future_to_crt):
                d = future_to_crt[future]
                print("  \_", colored(d, "cyan"))
                try:
                    crtdata = future.result()

                    if len(crtdata) > 0:

                        certificates_result.append(
                            {
                                "domain": d,
                                "details": crtdata,
                            }
                        )
                        for crtd in crtdata:
                            for k, v in crtd.items():
                                print("    \_", k, colored(v, "yellow"))
                    else:
                        print("    \_", colored("No CERT found", "red"))
                except Exception as exc:
                    print("    \_", colored(exc, "red"))
            CERTIFICATES_FILE.write_text(json.dumps(certificates_result))
    except ValueError:
        pass


def VTDomainReport(domain_name):
    headers = {
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:52.0) Gecko/20100101 Firefox/52.0",
        "x-apikey": "580eecdcf544f5bd8c31456739a2fb72993cdfee2a44c392ea9ce05c07ebcf5b",
    }
    response = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain_name}",
        # params=parameters,
        headers=headers,
    )
    response_dict = response.json()
    return response_dict


def getVTDomainReport():
    try:
        virus_total_results: list[dict] = []
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(DOMAINS)
        ) as executor:
            future_to_vt = {
                executor.submit(VTDomainReport, domain): domain for domain in DOMAINS
            }
            for future in concurrent.futures.as_completed(future_to_vt):
                d = future_to_vt[future]
                print("  \_", colored(d, "cyan"))
                try:
                    vtdata = future.result()
                    analis_results: dict[str, dict] = vtdata['data']['attributes']['last_analysis_results']
                    not_clean_antivirus_analize: dict = {}
                    for antivirus_name, antivirus_details in analis_results.items():
                        if antivirus_details["result"] != "clean":
                            not_clean_antivirus_analize[antivirus_name] = antivirus_details

                    if not_clean_antivirus_analize:
                        virus_total_results.append(
                            {
                                "domain": d,
                                "details": not_clean_antivirus_analize,
                            }

                        )
                    if vtdata["response_code"] == 1:
                        if "detected_urls" in vtdata:
                            if len(vtdata["detected_urls"]) > 0:
                                print("    \_", colored("Detected URLs", "red"))
                                for det_urls in vtdata["detected_urls"]:
                                    print(
                                        "      \_",
                                        colored(det_urls["url"], "yellow"),
                                        colored(det_urls["positives"], "yellow"),
                                        "/",
                                        colored(det_urls["total"], "yellow"),
                                        colored(det_urls["scan_date"], "yellow"),
                                    )
                        if "detected_downloaded_samples" in vtdata:
                            if len(vtdata["detected_downloaded_samples"]) > 0:
                                print(
                                    "    \_",
                                    colored("Detected Download Samples", "red"),
                                )
                                for det_donw_samples in vtdata[
                                    "detected_downloaded_samples"
                                ]:
                                    print(
                                        "      \_",
                                        colored(det_donw_samples["date"], "yellow"),
                                        colored(
                                            det_donw_samples["positives"], "yellow"
                                        ),
                                        "/",
                                        colored(det_donw_samples["total"], "yellow"),
                                        colored(det_donw_samples["sha256"], "yellow"),
                                    )
                        if "detected_communicating_samples" in vtdata:
                            if len(vtdata["detected_communicating_samples"]) > 0:
                                print(
                                    "    \_",
                                    colored("Detected Communication Samples", "red"),
                                )
                                for det_comm_samples in vtdata[
                                    "detected_communicating_samples"
                                ]:
                                    print(
                                        "      \_",
                                        colored(det_comm_samples["date"], "yellow"),
                                        colored(
                                            det_comm_samples["positives"], "yellow"
                                        ),
                                        "/",
                                        colored(det_comm_samples["total"], "yellow"),
                                        colored(det_comm_samples["sha256"], "yellow"),
                                    )
                        if "categories" in vtdata:
                            if len(vtdata["categories"]) > 0:
                                print("    \_", colored("categories", "red"))
                                for ctg in vtdata["categories"]:
                                    print("      \_", colored(ctg, "yellow"))
                        if "subdomains" in vtdata:
                            if len(vtdata["subdomains"]) > 0:
                                print("    \_", colored("Subdomains", "red"))
                                for vt_domain in vtdata["subdomains"]:
                                    print("      \_", colored(vt_domain, "yellow"))
                        if "resolutions" in vtdata:
                            if len(vtdata["resolutions"]) > 0:
                                print("    \_", colored("Resolutions (PDNS)", "red"))
                                for vt_resolution in vtdata["resolutions"]:
                                    print(
                                        "      \_",
                                        colored(
                                            vt_resolution["last_resolved"], "yellow"
                                        ),
                                        colored(vt_resolution["ip_address"], "yellow"),
                                    )
                    else:
                        print("    \_", colored(vtdata["verbose_msg"], "yellow"))

                except Exception as exc:
                    print("    \_", colored(exc, "red"))
            VIRUS_TOTAL_FILE.write_text(json.dumps(virus_total_results))
    except ValueError:
        pass


def quad9(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["9.9.9.9"]
    resolver.timeout = 1
    resolver.lifetime = 1

    try:
        Aanswers = resolver.query(domain, "A")
    except dns.resolver.NXDOMAIN:
        return "Blocked"
    except dns.resolver.NoAnswer:
        pass
    except dns.name.EmptyLabel:
        pass
    except dns.resolver.NoNameservers:
        pass
    except dns.resolver.Timeout:
        pass
    except dns.exception.DNSException:
        pass


def get_quad9_results():
    quad9_results: list[dict] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(DOMAINS)
        ) as executor:
            future_to_quad9 = {
                executor.submit(quad9, domain): domain for domain in DOMAINS
            }
            for future in concurrent.futures.as_completed(future_to_quad9):
                quad9_domain = future_to_quad9[future]
                print("  \_", colored(quad9_domain, "cyan"))
                try:
                    QUAD9NXDOMAIN = future.result()

                    if QUAD9NXDOMAIN is not None:
                        quad9_results.append(
                            {
                                "domain": quad9_domain,
                                "is_blocked": True
                            }
                        )
                        print("    \_", colored(QUAD9NXDOMAIN, "red"))
                    else:
                        print("    \_", colored("Not Blocked", "yellow"))
                        quad9_results.append(
                            {
                                "domain": quad9_domain,
                                "is_blocked": False
                            }
                        )
                except Exception as exc:
                    print(("%r generated an exception: %s" % (quad9_domain, exc)))
            QUAD9_FILE.write_text(json.dumps(quad9_results))
    except ValueError:
        pass


def shannon_entropy(domain):
    import math

    stList = list(domain)
    alphabet = list(set(domain))  # list of symbols in the string
    freqList = []

    for symbol in alphabet:
        ctr = 0
        for sym in stList:
            if sym == symbol:
                ctr += 1
        freqList.append(float(ctr) / len(stList))

    # Shannon entropy
    ent = 0.0
    for freq in freqList:
        ent = ent + freq * math.log(freq, 2)
    ent = -ent
    return ent


def download_nrd(d):
    if not os.path.isfile(d + ".zip"):
        b64 = base64.b64encode((d + ".zip").encode("ascii"))
        nrd_zip = "https://www.whoisds.com//whois-database/newly-registered-domains/{}/nrd".format(
            b64.decode("ascii")
        )
        try:
            resp = requests.get(nrd_zip, stream=True)

            print(
                "Downloading File {} - Size {}...".format(
                    d + ".zip", resp.headers["Content-length"]
                )
            )
            if resp.headers["Content-length"]:
                with open(d + ".zip", "wb") as f:
                    for data in resp.iter_content(chunk_size=1024):
                        f.write(data)
                try:
                    zip = zipfile.ZipFile(d + ".zip")
                    zip.extractall()
                except:
                    print("File is not a zip file.")
                    sys.exit()
        except:
            print("File {}.zip does not exist on the remote server.".format(d))
            sys.exit()


def download_nrds_from_to(date_from, date_to):
    d = "{}-{:02}-{:02}"
    date_i = date_from
    while date_i <= date_to:
        date_str = d.format(date_i.year, date_i.month, date_i.day)
        download_nrd(date_str)
        try:
            f = open(date_str + ".txt", "r")
        except:
            try:
                f = open("domain-names.txt", "r")
            except:
                "Fatal error: no domain-names found"
                sys.exit()
        with open("domain-names.tmp", "a") as fout:
            for row in f:
                fout.write(row)
        date_i = date_i + datetime.timedelta(days=1)

    os.rename("domain-names.tmp", "domain-names.txt")


def bitsquatting(search_word):
    out = []
    masks = [1, 2, 4, 8, 16, 32, 64, 128]

    for i in range(0, len(search_word)):
        c = search_word[i]
        for j in range(0, len(masks)):
            b = chr(ord(c) ^ masks[j])
            o = ord(b)
            if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
                out.append(search_word[:i] + b + search_word[i + 1:])
    return out


def hyphenation(search_word):
    out = []
    for i in range(1, len(search_word)):
        out.append(search_word[:i] + "-" + search_word[i:])
    return out


def subdomain(search_word):
    out = []
    for i in range(1, len(search_word)):
        if search_word[i] not in ["-", "."] and search_word[i - 1] not in ["-", "."]:
            out.append(search_word[:i] + "." + search_word[i:])
    return out


if __name__ == "__main__":
    DOMAINS = set()
    DOMAINS_DICT = {}
    IPs = []
    NAMES = []

    regexd = re.compile("([\d]{4})-([\d]{1,2})-([\d]{1,2})$")
    if args.date is not None:
        matchObj = re.match(regexd, args.date)
        if matchObj:
            if args.date_end is None:
                download_nrd(args.date)
            else:
                date_start = datetime.date(
                    int(matchObj[1]), int(matchObj[2]), int(matchObj[3])
                )
                if args.date_end.lower() == "yesterday":
                    date_end = datetime.date.today() - datetime.timedelta(days=1)
                else:
                    matchObj = re.match(regexd, args.date_end)
                    if matchObj:
                        date_end = datetime.date(
                            int(matchObj[1]), int(matchObj[2]), int(matchObj[3])
                        )

                    else:
                        print("Not a correct input (example: 2010-10-10)")
                        sys.exit()
                if date_end < date_start:
                    print("Ending date is earlier than starting date.")
                    sys.exit()
                else:
                    download_nrds_from_to(date_start, date_end)

        else:
            print("Not a correct input (example: 2010-10-10)")
            sys.exit()

        try:
            f = open(args.date + ".txt", "r")
        except:
            print(
                "No such file or directory {}.txt found. Trying domain-names.txt.".format(
                    args.date
                )
            )

            try:
                f = open("domain-names.txt", "r")
            except:
                print("No such file or directory domain-names.txt found")
                sys.exit()
    else:  # if we are given a file instead of a DATE
        if args.dfile:
            try:
                f = open(args.dfile, "r")
            except:
                print("No such file or directory " + args.dfile + " found")
                sys.exit()
        else:
            print("Error: need a file (-d) or a range of dates (-f [-t])")
            sys.exit()
    if args.search is not None:
        search = " ".join(args.search)
        # bitsquatting_search = bitsquatting(args.search)
        bitsquatting_search = bitsquatting(search)
        hyphenation_search = hyphenation(search)
        subdomain_search = subdomain(search)
        search_all = {
            search: bitsquatting_search + hyphenation_search + subdomain_search
        }
        search_all[search].append(search)
    elif args.search_file is not None:
        try:
            with open(args.search_file, "r") as flist:
                search_words = [r.replace("\n", "") for r in flist.readlines()]
        except:
            print("No such list file: {}.".format(args.search_file))
            sys.exit()
        search_all = {}
        for word in search_words:
            bitsquatting_search = bitsquatting(word)
            hyphenation_search = hyphenation(word)
            subdomain_search = subdomain(word)
            search_all[word] = (
                    bitsquatting_search + hyphenation_search + subdomain_search
            )
            search_all[word].append(word)
    elif args.regex is not None:
        for row in f:
            domain = row.strip("\r\n")
            try:
                match = re.search(args.regex, domain)
            except Exception as e:
                print(
                    "/!\ There might be an error in your regular expression. Please check on https://regex101.com/ that your regex matches what you want."
                )
                print("Python error: ", e.__class__, e)
                sys.exit()
            if args.regex not in DOMAINS_DICT:
                DOMAINS_DICT[args.regex] = []
            if match:
                DOMAINS_DICT[args.regex].append(domain)
                DOMAINS.add(domain)

        if os.path.exists("domain-names.txt"):
            os.remove("domain-names.txt")
        if os.path.exists(args.date + ".zip"):
            os.remove(args.date + ".zip")
        with open("domain-names.txt", "a") as fout:
            for d in DOMAINS:
                fout.write(d)
                fout.write("\n")

    else:
        print("Nothing to search.")
        sys.exit()
    if args.regex is None:
        for row in f:
            for key, argssearch_list in search_all.items():
                for argssearch in argssearch_list:
                    if key not in DOMAINS_DICT:
                        DOMAINS_DICT[key] = []
                    match = re.search(r"^" + argssearch, row)
                    if match:
                        DOMAINS_DICT[key].append(row.strip("\r\n"))
                        DOMAINS.add(row.strip("\r\n"))

    start = time.time()

    print("[*]-Retrieving DNS Record(s) Information")
    get_DNS_record_results()

    print("[*]-Retrieving IP2ASN Information")
    get_IP2CIDR()

    # print("[*]-Retrieving WHOIS Information")
    # get_WHOIS_results()

    print(
        "[*]-Retrieving Reverse WHOIS (by Name) Information [Source https://domainbigdata.com]"
    )
    get_EmailDomainBigData()

    print("[*]-Retrieving Certficates [Source https://crt.sh]")
    getcrt()

    print("[*]-Retrieving VirusTotal Information")
    getVTDomainReport()

    print("[*]-Check domains against QUAD9 service")
    get_quad9_results()

    print("[*]-Calculate Shannon Entropy Information")
    entropy_results: list[dict] = []
    for domain in DOMAINS:
        entropy_level: float = shannon_entropy(domain)
        if shannon_entropy(domain) > 4:
            entropy_results.append(
                {
                    "domain": domain,
                    "details": {
                        "entropy_level": entropy_level,
                        "random_domain_level": "high",
                    }
                }
            )
            print(
                "  \_", colored(domain, "cyan"), colored(shannon_entropy(domain), "red")
            )
        elif shannon_entropy(domain) > 3.5 and shannon_entropy(domain) < 4:
            entropy_results.append(
                {
                    "domain": domain,
                    "details": {
                        "entropy_level": entropy_level,
                        "random_domain_level": "medium",
                    }
                }
            )
            print(
                "  \_",
                colored(domain, "cyan"),
                colored(shannon_entropy(domain), "yellow"),
            )
        else:
            entropy_results.append(
                {
                    "domain": domain,
                    "details": {
                        "entropy_level": entropy_level,
                        "random_domain_level": "low",
                    }
                }
            )
            print("  \_", colored(domain, "cyan"), shannon_entropy(domain))
    SHANNON_ENTROPY_FILE.write_text(json.dumps(entropy_results))

    collect_results = {}

    for result_file in RESULTS_OF_SCAN_STORAGE.iterdir():
        scan_name = result_file.stem
        scan_content = json.loads(result_file.read_text())
        collect_results[scan_name] = scan_content
        result_file.unlink(missing_ok=True)

    RESULTS_OF_SCAN_STORAGE.rmdir()
    FINAL_RESULT_FILE.write_text(json.dumps(collect_results))

    # print("[*]-Calculate Levenshtein Ratio")
    # for word, dlist in DOMAINS_DICT.items():
    #     for domain in dlist:
    #         ext_domain = tldextract.extract(domain)
    #         LevWord1 = ext_domain.domain
    #         LevWord2 = word
    #         if Levenshtein.ratio(LevWord1, LevWord2) > 0.8:
    #             print(
    #                 "  \_",
    #                 colored(LevWord1, "cyan"),
    #                 "vs",
    #                 colored(LevWord2, "cyan"),
    #                 colored(Levenshtein.ratio(LevWord1, LevWord2), "red"),
    #             )
    #         if (
    #                 Levenshtein.ratio(LevWord1, LevWord2) < 0.8
    #                 and Levenshtein.ratio(LevWord1, LevWord2) > 0.4
    #         ):
    #             print(
    #                 "  \_",
    #                 colored(LevWord1, "cyan"),
    #                 "vs",
    #                 colored(LevWord2, "cyan"),
    #                 colored(Levenshtein.ratio(LevWord1, LevWord2), "yellow"),
    #             )
    #         if Levenshtein.ratio(LevWord1, LevWord2) < 0.4:
    #             print(
    #                 "  \_",
    #                 colored(LevWord1, "cyan"),
    #                 "vs",
    #                 colored(LevWord2, "cyan"),
    #                 colored(Levenshtein.ratio(LevWord1, LevWord2), "green"),
    #             )

    print((time.time() - start))
