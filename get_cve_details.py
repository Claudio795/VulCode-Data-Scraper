import sys
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
import csv
import os
from tqdm import tqdm


def scrape_CVEs():
    pageURL = "https://www.cvedetails.com/browse-by-date.php"
    catalogSoup=BeautifulSoup(urlopen(Request(pageURL,
                                headers={'User-Agent': 'Mozilla/5.0'})).read(),
                                'html.parser')
    Yearslist = catalogSoup.findAll('li', class_="list-group-item border-0 p-0 text-nowrap mb-2 pe-4 font-monospace")

    yearlyReports = []
    years = []
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
        #get_cve_details(pageURLs)
    return pageURLs
        

def check_git_link(URLs: list) -> list | None:
    #codeLinkCount = 0
    gitUrls = []
    for url in URLs:
        if "github.com" in url and "commit" in url:
            #codeLinkCount += 1
            #print("codeLinkCount:" + str(codeLinkCount))
            gitUrls.append(url)
    if gitUrls == []:
        # if there are not git links, return None
        gitUrls.append('None')
    return gitUrls


def get_cve_details(pageURLs: list[str]):
    """
    Given a list of URLs to pages with CVEs (specifically, very list report the URLs of the pages with the CVEs by year),
    this function scrapes the CVEs in the pages and saves the details in a csv file.

    Args:
        - pageURLs (list[str]): List of URLs to pages with CVEs
    """
    keys = [
            "CVE_ID",
            "CVE_URL",
            "Summary",
            "EPSS_scores",
            "Published_dates",
            "Updated_dates",
            "CVSS_score",
            "CVSS_severity",
            "CVSS_vector",
            "exploitability_score",
            "impact_score",
            "score_source",
            "CWE_ID",
            "Reference_links"
            ]
    total_cve = 0
    bar = tqdm(pageURLs, total=len(pageURLs))
    for pageURL in bar:
        numCVEs = 0 
        #print(f"Scraping {pageURL}...")
        pageSoup = BeautifulSoup(urlopen(Request(pageURL,
                            headers={'User-Agent': 'Mozilla/5.0'})).read(),
                            'html.parser')
        pageTable = pageSoup.find('div', id = "searchresults")

        # take the first details from the page
        summaries = [summary.text for summary in pageTable.findAll('div', class_='cvesummarylong')] # len 25
        cveIDs = [cveID.text for cveID in pageTable.findAll('h3', class_="col-md-4 text-nowrap")] # len 25
        cveURLs = ["https://www.cvedetails.com" + cveID.find('a')['href'] for cveID in pageTable.findAll('h3', class_="col-md-4 text-nowrap")] # len 25

        EPSS_scores = []
        Published_dates = []
        Updated_dates = []

        for item in pageTable.findAll('div', class_="col-md-3"):
            for row in item.findAll('div', class_="row mb-1"):
                col = row.findAll('div', class_="col-6")
                if col[0].text == "EPSS Score":
                    EPSS_scores.append(col[1].text)         # len 25
                elif col[0].text == "Published":
                    Published_dates.append(col[1].text)     # len 25
                elif col[0].text == "Updated":
                    Updated_dates.append(col[1].text)       # len 25

        # take the next data from the CVE pages
        for i, cveURL in enumerate(cveURLs):
            cveSoup = BeautifulSoup(urlopen(Request(cveURL,
                             headers={'User-Agent': 'Mozilla/5.0'})).read(),
                             'html.parser')
            # Reference links: if not to github commit, it will be ['None']
            reflinks = [ref['href'] for ref in cveSoup.find('ul', class_="list-group rounded-0").findAll('a', href=True)]
            reflinks = check_git_link(reflinks)
            
            # Add the details previously gatered to the list
            values = [cveIDs[i], cveURL, summaries[i], EPSS_scores[i], Published_dates[i], Updated_dates[i]]
            # take new details from the cve page
            CVSS_Scores_Soup = cveSoup.find('tbody').findAll('td')[:-1]
            CVE_details_list = [td.text.strip() for td in CVSS_Scores_Soup]
            # cwe then
            cwe = cveSoup.find('ul', class_="list-group border-0 rounded-0").find('a').text.split(' ')[0].strip()
            # add cwe and reference links to list
            #print('cwe: ', cwe)
            CVE_details_list.append(cwe)
            CVE_details_list.extend(reflinks)
            #print("tdList: ", CVE_details_list)
            #print("ref links: ", reflinks)
            # finally, add the new details to the list
            values.extend(CVE_details_list)
            # build dict
            #print("keys: ", keys)
            #print("values: ", values)
            #
            cveDetails = dict(zip(keys, values))
            #print(cveDetails)
            CVSS_vector = cveSoup.find("div", class_="d-flex flex-row justify-content-evenly text-secondary d-grid gap-3").findAll('div')
            CVSS_vector = {CVSS_vector[i].text.split(': ')[0]: CVSS_vector[i].text.split(': ')[1] for i in range(0, len(CVSS_vector))}

            cveDetails.update(CVSS_vector)
            numCVEs += len(cveDetails)
            total_cve += len(cveDetails)
            # Save as csv file
            values = list(cveDetails.values())
            #print(list(cveDetails.keys()))
            if os.path.exists('./csv/cve_data_new.csv'):
                with open('./csv/cve_data_new.csv', 'a') as csv_file:
                    writer = csv.writer(csv_file)
                    writer.writerow(values)
            else: 
                columns = list(cveDetails.keys())
                with open('./csv/cve_data_new.csv', 'x') as csv_file:
                    writer = csv.writer(csv_file)
                    writer.writerow(columns)
                    writer.writerow(values)
            num_page = pageURL.split('page=')[1].split('&')[0]
            bar.set_description(f"Scraped {total_cve}, page {num_page}")

    print(f"Done! Scraped {total_cve} CVEs in total")


def main():
    print('Starting CVE scraping...')
    pageURLs = scrape_CVEs()
    get_cve_details(pageURLs)

if __name__ == "__main__":
    main()