import sys
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
import datetime

error_log = open("./Logs/main_log_all.log", "a+")

def log_message(msg):
    timestamp = str(datetime.datetime.now())
    error_log.write(timestamp + ":\t" + msg + "\n")


def scrap_owasp_urls():
    """
    Function that get the owasp top 10 urls to use for
    CWE parsing
    """
    owasp_top10_urls = []
    pageURL = "https://owasp.org/Top10/"
    log_message("Scrape starting up... root page: " + pageURL)
    catalogSoup=BeautifulSoup(urlopen(Request(pageURL,
                                headers={'User-Agent': 'Mozilla/5.0'})).read(),
                                'html.parser')

    for row in catalogSoup.findAll('strong'):
        for owasp_vul in row.findAll('a', href=True):
            owasp_top10_urls.append(pageURL + str(owasp_vul['href']))
    return owasp_top10_urls


def scrap_CWEs():
    """
    Function that extract the relative CWE IDs for every owasp 
    top 10 entry. return a dictionary with top 10 as keys and 
    lists of CWEs as values
    """
    owasp_top10_urls = scrap_owasp_urls()
    owasp_cwes = {}
    for url in owasp_top10_urls:
        catalogSoup=BeautifulSoup(urlopen(Request(url,
                                    headers={'User-Agent': 'Mozilla/5.0'})).read(),
                                    'html.parser')
        CWEs = []
        for line in catalogSoup.findAll('p'):
            for row in line.findAll('a', href=True):
                if 'CWE' in str(row):
                    #print(row.text)
                    for cwe in row.text.split('\n'):
                        if 'CWE' in str(cwe):
                            CWEs.append(cwe.split()[0])
                    owasp_cwes[url.split('/')[-2]] = CWEs
    return owasp_cwes

class OWASP_scraper(object):
    def __init__(self):
        self.owasp_top10_urls = scrap_owasp_urls()
        self.owasp_cwes = scrap_CWEs()

    def get_owasp_top10_urls(self):
        return self.owasp_top10_urls

    def get_owasp_cwes(self):
        return self.owasp_cwes

    def get_owasp_cwe(self, owasp):
        return self.owasp_cwes[owasp]

    def get_owasp_cwe_from_url(self, url):
        return self.owasp_cwes[url.split('/')[-2]]

    def get_owasp_cwe_from_index(self, index):
        return self.owasp_cwes[self.owasp_top10_urls[index].split('/')[-2]]

    def get_owasp_cwe_from_name(self, name):
        for owasp, cwe in self.owasp_cwes.items():
            if owasp == name:
                return cwe
        return None

    def get_owasp_cwe_from_name(self, name):
        for owasp, cwe in self.owasp_cwes.items():
            if owasp == name:
                return cwe
        return None

    def get_owasp_cwe_from_index(self, index):
        return self.owasp_cwes[self.owasp_top10_urls[index].split('/')[-2]]

    def get_owasp_cwe_from_url(self, url):
        return self.owasp_cwes[url.split('/')[-2]]

# def save_csv(cwe_dict):
#     pass

def main():
    scraper = OWASP_scraper()
    print("Scraping OWASP top 10 CWE IDs...\n")
    owasp_cwes = scraper.get_owasp_cwes()
    for owasp, cwe in owasp_cwes.items():
        print(f"{owasp}: {cwe}\n")

if __name__ == "__main__":
    main()