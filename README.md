# Automated Web Scanner

**Cybersecurity Bootcamp Project**\
**Prepared by:** Shriti Kumari

## 1. Project Overview

Automated Web Scanner is a basic Python command-line tool that checks
selected HTTP security response headers and displays CORS (Cross-Origin
Resource Sharing) response-header information for a public website.

The tool is intended for educational use and basic configuration review.
It does not perform a full penetration test and cannot prove that a
website is secure or vulnerable.

## 2. Features

-   Accepts a website URL and adds `https://` when no scheme is
    provided.
-   Validates the URL and checks that the hostname resolves to public IP
    addresses.
-   Checks for these HTTP security headers:
    -   `Strict-Transport-Security`
    -   `Content-Security-Policy`
    -   `X-Content-Type-Options`
    -   `X-Frame-Options`
    -   `Referrer-Policy`
    -   `Permissions-Policy`
-   Displays selected CORS response headers:
    -   `Access-Control-Allow-Origin`
    -   `Access-Control-Allow-Credentials`
    -   `Access-Control-Allow-Methods`
    -   `Access-Control-Allow-Headers`
    -   `Vary`
-   Displays the HTTP status and explanatory notes in the terminal.
-   Optionally saves scan results to a timestamped JSON file in a
    `reports` folder.
-   Handles common URL validation, timeout, TLS, and connection errors.

## 3. Technologies Used

-   **Python** --- main programming language.
-   **requests** --- sends the HTTP request and reads response headers.
-   Python standard-library modules, including `ipaddress`, `json`,
    `socket`, `datetime`, `pathlib`, and `urllib.parse`.

## 4. Requirements

-   Python 3 installed.
-   An internet connection.
-   The Python package listed in `requirements.txt`.

## 5. Installation

1.  Place `app.py` and `requirements.txt` in the same project folder.

2.  Open a terminal in that folder.

3.  Install the dependency:

    ``` bash
    python -m pip install -r requirements.txt
    ```

If your system uses the `py` launcher on Windows, you can try:

``` bash
py -m pip install -r requirements.txt
```

## 6. How to Run

In the project folder, run:

``` bash
python app.py
```

On Windows, if needed, you can also try:

``` bash
py app.py
```

When prompted, enter a website URL, for example:

``` text
https://example.com
```

The scanner prints the HTTP status, security-header observations, CORS
response-header values, and limitations. It then asks whether you want
to save the results as a JSON report. Enter `y` or `yes` to save the
report.

## 7. Output

When JSON export is selected, the program creates a `reports` folder
beside the Python script if it does not already exist. The result is
saved in a timestamped file such as:

``` text
reports/scan_report_YYYYMMDD_HHMMSS.json
```

The actual filename contains the date and time of the scan.

## 8. Understanding the Results

-   **Present** means the response included the header.
-   **Missing** means the header was not observed in that response.
-   A missing header does **not** automatically mean the website is
    vulnerable.
-   CORS headers should be interpreted in the context of the website and
    the resource being accessed.
-   Results describe the response received at the time of the scan.

## 9. Limitations

-   The scanner makes one ordinary HTTP GET request and does not follow
    redirects.
-   It checks a limited set of response headers only.
-   It is not a complete browser-based CORS test.
-   It does not crawl the website, test authentication, inspect
    application logic, or detect all vulnerabilities.
-   It cannot prove that a website is completely secure.
-   Network conditions and server responses can affect results.

## 10. Ethical Use

Use this tool only on websites you own or have explicit permission to
assess. This is an educational, non-intrusive header-checking tool.
Follow applicable laws and the website owner's testing rules.

## 11. Project Files

``` text
Automated_Web_Scanner/
├── app.py
├── requirements.txt
├── README.md
└── reports/                 # Created when a JSON report is saved
```

The project report is submitted separately as a Word document.

## 12. Future Improvements

Possible improvements include adding unit tests, providing CSV or HTML
exports, improving report presentation, and adding further checks after
careful testing.

------------------------------------------------------------------------

**Note:** This README describes the supplied implementation. Test the
program and confirm its behaviour in your own environment before
presenting scan results as verified.
