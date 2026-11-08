
import copy
import requests
import sys
from urllib import parse

"""
Desenvolvendo um SQLi Scan para aplicações WEB
"""


# Realiza requisições HTTP
def request(url):

    headers = {
        "user-agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 Chrome/156.0.0.0 Safari/537.36"
        )
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        response.raise_for_status()
        return response.text

    except requests.exceptions.Timeout:
        print("[!] Request timeout")

    except requests.exceptions.ConnectionError:
        print("[!] Connection error")

    except requests.exceptions.HTTPError as error:
        print(f"[!] HTTP error: {error}")

    except requests.exceptions.RequestException as error:
        print(f"[!] Request error: {error}")

    return None


# Identifica possíveis mensagens de erro SQL
def is_vulnerable(html):

    errors = [

        # MySQL / MariaDB
        "mysql_fetch_array()",
        "mysql_fetch_assoc()",
        "mysql_num_rows()",
        "You have an error in your SQL syntax",
        "Warning: mysql_",
        "MySQL server version",
        "mysqli_fetch_array()",
        "mysqli_query()",
        "MariaDB server version",

        # PostgreSQL
        "PostgreSQL query failed",
        "pg_query()",
        "pg_exec()",
        "ERROR: syntax error at or near",
        "unterminated quoted string",

        # Microsoft SQL Server
        "Microsoft SQL Server",
        "ODBC SQL Server Driver",
        "SQLServer JDBC Driver",
        "Unclosed quotation mark after the character string",
        "Incorrect syntax near",

        # Oracle
        "ORA-00933",
        "ORA-00936",
        "ORA-01756",
        "ORA-00942",
        "Oracle error",
        "quoted string not properly terminated",

        # SQLite
        "SQLite3::query()",
        "SQLite error",
        "SQLITE_ERROR",
        'near "SELECT": syntax error',
        "unrecognized token",

        # IBM DB2
        "SQLCODE",
        "DB2 SQL error",
        "SQLSTATE",

        # Sybase
        "Sybase message",
        "Adaptive Server Enterprise",

        # Generic database errors
        "SQL syntax error",
        "SQL syntax",
        "database error",
        "invalid SQL statement",
        "SQL command not properly ended",
        "ODBC Driver",
        "JDBC exception",
        "SQLSTATE["
    ]

    if not html:
        return False

    html = html.lower()

    for error in errors:
        if error.lower() in html:
            return True

    return False


# Execução principal
if __name__ == "__main__":

    # Verifica os argumentos
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <URL>")
        sys.exit(1)

    # Recebe a URL
    url = sys.argv[1]

    # Analisa a URL
    url_parsed = parse.urlsplit(url)

    # Valida a URL
    if url_parsed.scheme not in ("http", "https") or not url_parsed.netloc:
        print("[!] Invalid URL")
        sys.exit(1)

    # Extrai os parâmetros GET
    params = parse.parse_qs(url_parsed.query)

    # Verifica se existem parâmetros
    if not params:
        print("[!] No URL parameters found")
        sys.exit(1)

    print("[*] Starting SQL Injection scan...")
    print(f"[*] Target: {url}")
    print(f"[*] Parameters found: {len(params)}")

    # Testa cada parâmetro
    for param in params:

        for c in "'\"":

            query = copy.deepcopy(params)

            query[param][0] = c

            # Codifica os parâmetros
            new_params = parse.urlencode(
                query,
                doseq=True
            )

            # Reconstrói a URL
            url_final = url_parsed._replace(
                query=new_params
            ).geturl()

            print(f"[*] Testing parameter: {param}")

            # Realiza a requisição
            html = request(url_final)

            # Verifica possíveis erros SQL
            if html:

                if is_vulnerable(html):

                    print(
                        f"[!] POSSIBLE SQL INJECTION: {param}"
                    )

                    sys.exit(0)

    print("[+] No SQL error signatures detected")
