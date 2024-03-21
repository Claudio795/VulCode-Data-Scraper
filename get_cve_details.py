import sys
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
import csv
import os
from tqdm import tqdm


def scrape_CVEs() -> dict[str, list[str]]:
    pageURL = "https://www.cvedetails.com/browse-by-date.php"
    catalogSoup=BeautifulSoup(urlopen(Request(pageURL,
                                headers={'User-Agent': 'Mozilla/5.0'})).read(),
                                'html.parser')
    Yearslist = catalogSoup.findAll('li', class_="list-group-item border-0 p-0 text-nowrap mb-2 pe-4 font-monospace")

    yearlyReports = []
    years = []
    year_pageURLs = {}
    for year in Yearslist:
        yearName = year.find('a').text.strip()
        #print(f'Found year {yearName}')
        years.append(yearName)
        #print("Found year at: https://www.cvedetails.com" + year.find('a')['href'] + "\n")
        yearlyReports.append("https://www.cvedetails.com" + year.find('a')['href'])

    print(f"{len(yearlyReports)} yearly reports found")
    # print(f'Years: {[year for year in years]}')
    print("Getting CVE pages")
    for i, yearURL in enumerate(yearlyReports):
        yearTableSoup = BeautifulSoup(urlopen(Request(yearURL,
                                            headers={'User-Agent': 'Mozilla/5.0'}))\
                                            .read(), 'html.parser')
        pageIndex = yearTableSoup.find('div', {'id':'pagingb'}, class_='paging')
        pageURLs = ["https://www.cvedetails.com"+page['href'] for page in pageIndex.findAll('a', href=True)]
        print(f"Found {len(pageURLs)} pages for {years[i]}")
        year_pageURLs[years[i]] = pageURLs
    #    #get_cve_details(pageURLs)
    #key, _ = year_pageURLs.popitem()
    #print(f'removed {key} pair')
    #print(year_pageURLs['2024'][0])
    return year_pageURLs
        

def check_git_link(URLs: list) -> list | None:
    #codeLinkCount = 0
    gitUrls = []
    for url in URLs:
        if "github.com" in url and "commit" in url:
            #codeLinkCount += 1
            #print("codeLinkCount:" + str(codeLinkCount))
            gitUrls.append(url)
    if gitUrls == []:
        # if there are not git links, return 'None'
        gitUrls = 'None'
    return gitUrls


def get_cve_details(year_pageURLs: dict[str, list[str]]):
    """
    Given a list of URLs to pages with CVEs (specifically, very list report the URLs of the pages with the CVEs by year),
    this function scrapes the CVEs in the pages and saves the details in a csv file.

    Args:
        - pageURLs (list[str]): List of URLs to pages with CVEs
    """
    # cve details to scrape, None if not present
    keys = ["CVE_ID", "CVE_URL", "Summary", "Published_dates", "Updated_dates", "EPSS_scores", "CVSS_score", 
            "CVSS_severity", "CVSS_vector", "Attack Vector", "Attack Complexity", "Privileges Required", "User Interaction", 
            "Scope", "Confidentiality", "Integrity", "Availability", "exploitability_score", "impact_score", "score_source", 
            "CWE_ID", "Reference_links",
            ]
    values = ['None']*len(keys)
    #cve_dict = dict(zip(keys, values))
    total_cve = 0
    # year
    for year, pageURLs in year_pageURLs.items():
        year_cve = 0
        print(f"Scraping CVEs for {year}...")
        bar = tqdm(pageURLs, total=len(pageURLs))
        # page
        for pageURL in bar:
            numCVEs = 0 
            #print(f"Scraping {pageURL}...")
            pageSoup = BeautifulSoup(urlopen(Request(pageURL,
                                headers={'User-Agent': 'Mozilla/5.0'})).read(),
                                'html.parser')
            pageTable = pageSoup.find('div', id = "searchresults")
            cveURLs = ["https://www.cvedetails.com" + cveID.find('a')['href'] for cveID in pageTable.findAll('h3', class_="col-md-4 text-nowrap")] # len 25

            # iterate all the cve in the page
            for cveURL in cveURLs:
                cve_dict = dict(zip(keys, values))
                cveSoup = BeautifulSoup(urlopen(Request(cveURL,
                                headers={'User-Agent': 'Mozilla/5.0'})).read(),
                                'html.parser')
                # CVE ID
                cve_dict['CVE_ID'] = cveSoup.find('title').text.split(' :')[0]
                # CVE URL
                cve_dict['CVE_URL'] = cveURL
                # Summary
                cve_dict['Summary'] = cveSoup.find('div', class_="cvedetailssummary-text").text
                # Published date
                cve_dict['Published_dates'] = cveSoup.findAll('div', class_="d-inline-block py-1")[0].text.split(' ')[1].strip()
                # Updated data
                cve_dict['Updated_dates'] = cveSoup.findAll('div', class_="d-inline-block py-1")[1].text.split(' ')[1].strip()
                # EPSS score
                try:
                    cve_dict['EPSS_scores'] =cveSoup.find('div', class_="bg-white border-top py-2 px-3").find('span').text.strip()
                except AttributeError:
                    cve_dict['EPSS_scores'] = 'None'
                # Reference links
                reflinks_soup = cveSoup.find('ul', class_="list-group rounded-0")
                if reflinks_soup is not None:
                    reflinks = [ref['href'] for ref in cveSoup.find('ul', class_="list-group rounded-0").findAll('a', href=True)]
                    # if not to github commit, it will be ['None']
                    cve_dict['Reference_links'] = check_git_link(reflinks)
                # CWE 
                try:
                    cve_dict['CWE_ID'] = cveSoup.find('ul', class_="list-group border-0 rounded-0").find('a').text.split(' ')[0].strip()
                except AttributeError:
                    cve_dict['CWE_ID'] = 'None'

                # CVSS details
                CVSS_Scores_Soup = cveSoup.find('tbody')
                if CVSS_Scores_Soup is not None:
                    # CVSS scores - first half
                    CVSS_Scores_Soup = CVSS_Scores_Soup.findAll('td')
                    cve_dict['CVSS_score'] = CVSS_Scores_Soup[0].text.strip()
                    cve_dict['CVSS_severity'] = CVSS_Scores_Soup[1].text.strip()
                    cve_dict['CVSS_vector'] = CVSS_Scores_Soup[2].text.strip()
                    cve_dict['exploitability_score'] = CVSS_Scores_Soup[3].text.strip()
                    cve_dict['impact_score'] = CVSS_Scores_Soup[4].text.strip()
                    cve_dict['score_source'] = CVSS_Scores_Soup[5].text.strip()
                    # CVSS scores - second half
                    CVSS_vector = cveSoup.find("div", class_="d-flex flex-row justify-content-evenly text-secondary d-grid gap-3")
                    CVSS_vector = CVSS_vector.findAll('div')
                    for item in CVSS_vector:
                        if item.text.split(': ')[0] in keys:
                            cve_dict[item.text.split(': ')[0]] = item.text.split(': ')[1]

                # save vulnerability data
                numCVEs += 1
                year_cve += 1
                total_cve += 1
                # Save as csv file
                dict_values = list(cve_dict.values())
                if os.path.exists('./csv/cve_data_new.csv'):
                    with open('./csv/cve_data_new.csv', 'a') as csv_file:
                        writer = csv.writer(csv_file)
                        writer.writerow(dict_values)
                else: 
                    columns = list(cve_dict.keys())
                    with open('./csv/cve_data_new.csv', 'x') as csv_file:
                        writer = csv.writer(csv_file)
                        writer.writerow(columns)
                        writer.writerow(dict_values)
                num_page = pageURL.split('page=')[1].split('&')[0]
                bar.set_description(f"Scraped {year_cve}, page {num_page}, total {total_cve}")

    print(f"Done! Scraped {total_cve} CVEs in total")


def main():
    print('Starting CVE scraping...')
    pageURLs = scrape_CVEs()
    get_cve_details(pageURLs)

if __name__ == "__main__":
    main()