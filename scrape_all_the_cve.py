#coding=utf8
import sys
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
import datetime
import ssl
import pandas as pd
import csv
import os
from scrape_owasp_cwe import scrap_CWEs
from itertools import chain

ssl._create_default_https_context = ssl._create_unverified_context

# Global Variables
vulnCount = 0
codeLinkCount = 0

# Error log writer
error_log = open("./Logs/main_log_all.log", "a+")


def log_data(result_dict):
    global vulnCount
    print("Logging cell data...")
    vulnCount = vulnCount + 1
    print("VULNERABILITIES FOUND: " + str(vulnCount))
    #data_log.write(str(result_dict))
    with open("CVE-Scraper_all.dat", "w+") as data_log:
        data_log.write('{\n\t"CVE ID":\"' + result_dict['CVEID'] + '\",\n\t"CVE Page":\"' +
                    result_dict['CVEPage'] + '\",\n\t"CWE ID":\"' + result_dict['CWEID'] +
                    '\",\n\t"Known Exploits":\"' + result_dict['knownExploits'] +
                    '\",\n\t"Vulnerability Classification":\"' +
                    result_dict['vulnClassification'] + '\",\n\t"Publish Date":\"' + result_dict['publishDate']
                    + '\",\n\t"Update Date":\"' + result_dict['updateDate'] +
                    '\",\n\t"Score":\"' + result_dict['score'] + '\",\n\t"Access Gained":\"' +
                    result_dict['accessGained'] + '\",\n\t"Attack Origin":\"' + result_dict['attackOrigin'] +
                    '\",\n\t"Complexity":\"' + result_dict['complexity'] +
                    '\",\n\t"Authentication Required":\"' +
                    result_dict['authenticationRequired'] + '\",\n\t"Confidentiality":\"' +
                    result_dict['confidentiality'] + '\",\n\t"Integrity":\"' + result_dict['integrity'] +
                    '\",\n\t"Availability":\"' + result_dict['availability'] +
                    '\",\n\t"Summmary":\"' + result_dict['summary'] +
                    '\",\n\t"codeLink":\"' + result_dict['codeLink'] + '\"\n}\n\n')
    print(result_dict)

    # save the row in the csv file
    if os.path.exists('./csv/cve_data.csv'):
        with open('./csv/cve_data.csv', 'a') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(list(result_dict.values()))
    else: 
        columns = list(result_dict.keys())
        with open('./csv/cve_data.csv', 'x') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(columns)
            writer.writerow(list(result_dict.values()))

    """print('{\n\t"CVE ID":\"' + CVEID + '\",\n\t"CVE Page":\"' +
          CVEPage + '\",\n\t"CWE ID":\"' + CWEID +
          '\",\n\t"Known Exploits":\"' + knownExploits +
          '\",\n\t"Vulnerability Classification":\"' +
           vulnClassification + '\",\n\t"Publish Date":\"' + publishDate
           + '\",\n\t"Update Date":\"' + updateDate +
           '\",\n\t"Score":\"' + score + '\",\n\t"Access Gained":\"' +
           accessGained + '\",\n\t"Attack Origin":\"' + attackOrigin +
           '\",\n\t"Complexity":\"' + complexity +
           '\",\n\t"Authentication Required":\"' +
           authenticationRequired + '\",\n\t"Confidentiality":\"' +
           confidentiality + '\",\n\t"Integrity":\"' + integrity +
           '\",\n\t"Availability":\"' + availability + '\"\n}\n\n')"""

def find_code_link(CVEPage):
    # get vulnerability code from GitHub link if avaiable 
    # each cve example on each page
    global codeLinkCount
    try:
        cveSoup = BeautifulSoup(urlopen(Request(CVEPage, headers={'User-Agent': 'Mozilla/5.0'})).read(), 'html.parser')
        linkStr = ""
        referTable = cveSoup.find('table', {'id': 'vulnrefstable'}, class_='listtable')
        row = referTable.findAll('td', class_="r_average")
        for cell in row:
            link = cell.find('a')['href']

            if "github.com" in link and "commit" in link:
                codeLinkCount += 1
                linkStr += cell.find('a')['href']
                print("codeLinkCount:" + str(codeLinkCount))
        return linkStr
    except:
        return ""

# Log errors to the file specified by error_log
def log_message(msg):
    timestamp = str(datetime.datetime.now())
    error_log.write(timestamp + ":\t" + msg + "\n")

def record_cve_data(pageURL):
    # Break down the CVE tables at the given pageURL
    log_message("scrape extracting from: " + pageURL + "\n")
    pageSoup = BeautifulSoup(urlopen(Request(pageURL,
                            headers={'User-Agent': 'Mozilla/5.0'})).read(),
                            'html.parser')
    
    # get CWE IDs relative to current OWASP top 10 ranking
    #owasp_cwe = scrap_CWEs()
    #CWEs = chain.from_iterable(owasp_cwe.values())

    pageTable = pageSoup.find('table', class_ = "searchresults sortable")
    for row, summarys in zip(pageTable.findAll('tr', class_ = "srrowns"), pageTable.findAll('td', class_ = "cvesummarylong")):
        #print(row)
        #print(CWEs)
        # define temp variables
        CVEID = None
        CVEPage = None
        owasp_vulnerability = None
        CWEID = None
        knownExploits = None
        vulnClassification = None
        publishDate = None
        updateDate = None
        score = None
        accessGained = None
        attackOrigin = None
        complexity = None
        authenticationRequired = None
        confidentiality = None
        integrity = None
        availability = None
        summary = None

        index = 0
        for cell in row.findAll('td'):
            print("<" + str(cell.next) + ">")
            # Push scraped cell data into organized variables
            if(index == 1):
                CVEPage = ("https://www.cvedetails.com" +
                        (cell.find('a'))['href'])
                CVEID = cell.find('a').next
            if(index == 2):
                try:
                    CWEID = "CWE-"+str(cell.find('a').next).strip("\r\n\t")
                except:
                    CWEID = str(cell.next).strip("\r\n\t")
                # # take only the vulnerabilities relative to the owasp top 10
                # # if CWE is not valid, reset previous values and interrupt 
                # # the scan of the current row
                # if CWEID == '' or CWEID not in CWEs: 
                #     CVEPage = None
                #     CVEID = None
                #     CWEID = None
                #     break      
                # for owasp_vuln, cwe_list  in owasp_cwe.items():
                #     if CWEID in cwe_list:
                #         owasp_vulnerability = owasp_vuln
                #         break
            if(index == 3):
                knownExploits = str(cell.next).strip("\r\n\t")
            if(index == 4):
                vulnClassification = str(cell.next).strip("\r\n\t")
            if(index == 5):
                publishDate = str(cell.next).strip("\r\n\t")
            if(index == 6):
                updateDate = str(cell.next).strip("\r\n\t")
            if(index == 7):
                score = cell.find('div').next
            if(index == 8):
                accessGained = str(cell.next).strip("\r\n\t")
            if(index == 9):
                attackOrigin = str(cell.next).strip("\r\n\t")
            if(index == 10):
                complexity = str(cell.next).strip("\r\n\t")
            if(index == 11):
                authenticationRequired = str(cell.next).strip("\r\n\t")
            if(index == 12):
                confidentiality = str(cell.next).strip("\r\n\t")
            if(index == 13):
                integrity = str(cell.next).strip("\r\n\t")
            if(index == 14):
                availability = str(cell.next).strip("\r\n\t")
            print("---")
            index += 1
        # if the CWE is not valid, skip the row
        if CWEID == None: 
            print('row not valid, jump tp the next\n')
            continue

        summary = str(summarys.next).strip("\r\n\t")
        # List all values gained from this row
        result_dict = {
            'CVEID': CVEID,
            'CVEPage': CVEPage,
            'OWASPVulnerability': owasp_vulnerability,
            'CWEID': CWEID,
            'knownExploits': knownExploits,
            'vulnClassification': vulnClassification,
            'publishDate': publishDate,
            'updateDate': updateDate,
            'score': score,
            'accessGained': accessGained,
            'attackOrigin': attackOrigin,
            'complexity': complexity,
            'authenticationRequired': authenticationRequired,
            'confidentiality': confidentiality,
            'integrity': integrity,
            'availability': availability,
            'summary': summary
        }

        print("\n\n")
        print("===")
        for key, value in result_dict.items():
            print(f"{key}:\t\t\t\t {value}\n")
        print("===\n\n")

        codeLink = find_code_link(CVEPage)
        result_dict['codeLink'] = codeLink

        log_data(result_dict)
        #df_values.append(list(result_dict.values()))

    #return list(result_dict.values())
    #return df_values

def save_data(value_list):
    columns = [
        'CVEID',
        'CVEPage',
        'OWASPVulnerability',
        'CWEID',
        'knownExploits',
        'vulnClassification',
        'publishDate',
        'updateDate',
        'score',
        'accessGained',
        'attackOrigin',
        'complexity',
        'authenticationRequired',
        'confidentiality',
        'integrity',
        'availability',
        'summary',
        'codeLink'
    ]
    dataframe = pd.DataFrame(value_list, columns=columns)
    dataframe.to_csv('./csv/cve_data.csv')

def scrape_cve_data():
    # grab the CVE Details page and throw it in beautifulSoup.
    pageURL = "https://www.cvedetails.com/browse-by-date.php"
    print("Scrape starting up... root page: " + pageURL)
    log_message("Scrape starting up... root page: " + pageURL)
    catalogSoup=BeautifulSoup(urlopen(Request(pageURL,
                              headers={'User-Agent': 'Mozilla/5.0'})).read(),
                              'html.parser')
    
    # Scrape the browse-by-date page to gather all of the different month's links
    catalogTable = catalogSoup.find('table', class_='stats')
    yearlyReports = []
    for row in catalogTable.findAll('th'):
        for year in row.findAll('a', href=True):
            print("Found year at: https://www.cvedetails.com" + year['href'] + "\n")
            # collect all the year page URLs
            yearlyReports.append("https://www.cvedetails.com" + year['href'])

    print("\n === Years discovered. Grabbing pages for each year ===\n\n")

    # discover the pages for each year and pass on those pages to be dissected
    #cve_year_list = []
    for yearURL in yearlyReports:
        yearTableSoup = BeautifulSoup(urlopen(Request(yearURL,
                                      headers={'User-Agent': 'Mozilla/5.0'}))\
                                      .read(), 'html.parser')

        pageIndex = yearTableSoup.find('div', {'id':'pagingb'}, class_='paging')
        #cve_page_list = []
        for page in pageIndex.findAll('a', href=True):
            # Break down the CVE tables
            pageURL = ("https://www.cvedetails.com" + page['href'])
            try:
                record_cve_data(pageURL)
            except:
                log_message(f"ERROR while scraping at: {pageURL}")
            #cve_page_list.append(record_cve_data(pageURL))
        #cve_year_list.append(chain.from_iterable(cve_page_list))
    #cve_list = chain.from_iterable(cve_year_list)
    #save_data()


###############################################################################
# MAIN
###############################################################################
def main(argv):
    print("\n==== CVE-Scraper ====")
    print("==== Main.py ====\n")
    print("PYTHON VERSION:\t\t" + sys.version)
    print("CVE-Scraper Starting up...")
    log_message("CVE-Scraper Starting up...")

    scrape_cve_data()
    print("Scrape complete")
    log_message("Scrape complete")

if __name__ == '__main__':
    main(sys.argv[1:])