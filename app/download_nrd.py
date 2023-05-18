from __future__ import print_function

import base64
import sys
import time
import zipfile
from datetime import datetime, timedelta

import requests

from app.config import FILES_STORAGE


def download_nrd(date_str: str, allowed_attempts: int = 5, wait_timeout: int = 5) -> None:
    """
    date_str: format: 2000-01-01
    """
    file_name = f'{date_str}.zip'
    file_path = FILES_STORAGE.joinpath(file_name)

    if file_path.is_file():
        # Already downloaded. Exit
        return

    b64 = base64.b64encode(file_name.encode("ascii"))
    # Double slash in "https://www.whoisds.com//" is important.
    nrd_zip = f'https://www.whoisds.com//whois-database/newly-registered-domains/{b64.decode("ascii")}/nrd'

    with requests.Session() as session:
        while allowed_attempts:
            # if we can't download file for given date, try previous day
            if allowed_attempts <= 3:
                date_str_as_date = datetime.strptime(date_str, "%Y-%m-%d")
                previous_day = date_str_as_date - timedelta(days=1)
                date_str = previous_day.strftime("%Y-%m-%d")
                file_name = f'{date_str}.zip'
                b64 = base64.b64encode(file_name.encode("ascii"))
                nrd_zip = f'https://www.whoisds.com//whois-database/newly-registered-domains/{b64.decode("ascii")}/nrd'
            try:
                resp = session.get(nrd_zip, stream=True)

                content_length = resp.headers['Content-length']

                print(
                    f"Downloading File {file_name} - Size {content_length}..."
                )

                if content_length:
                    with open(file_name, "wb") as f:
                        for data in resp.iter_content(chunk_size=1024):
                            f.write(data)

                    try:
                        zip = zipfile.ZipFile(file_name)
                        zip.extractall()
                    except (FileNotFoundError, zipfile.BadZipFile):
                        print("File is not a zip file.")

                        allowed_attempts -= 1
                        time.sleep(wait_timeout)
                        continue
            except:
                print(f"File {file_name} does not exist on the remote server.")

                allowed_attempts -= 1
                time.sleep(wait_timeout)
                continue
            else:
                return

        # Exit, if we can't download.
        sys.exit()
