import requests
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException
import pdb

def parse_talos_webpage_hashes(url):
    options = webdriver.ChromeOptions()
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    browser = webdriver.Chrome(options=options)
    browser.get(url)
    delay = 20 # seconds
    try:
        all_hashes = []
        myElem = WebDriverWait(browser, delay)
        blog_text = browser.find_element(By.XPATH, '//html').get_attribute('innerHTML')    
        text_divided_by_hashes = blog_text.split("Hashes")
        for i in range(1, len(text_divided_by_hashes)):
            #pdb.set_trace()
            hashes = text_divided_by_hashes[i].split('</code>')[0].split('<code>')[1].split('\n')
            hashes = [_hash.strip() for _hash in hashes]
            [all_hashes.append(_hash) for _hash in hashes if _hash != '']
        return all_hashes
    except TimeoutException:
        print ("Loading took too much time!")
	
	
url = input("Insert the url of the talos webpage whose IOCs you want to parse \n\n")
hashes = parse_talos_webpage_hashes(url)
print(hashes)
