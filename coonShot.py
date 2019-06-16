###########################################################################################
##                                                                                       ##
##          CoonShot v0.1                                                              ##
##          by @aetsu - 2019              												 ##
##                                                                                       ##
##          This program is free software: you can redistribute it and/or modify         ##
##          it under the terms of the GNU General Public License as published by         ##
##          the Free Software Foundation, either version 2 of the License, or            ##
##          (at your option) any later version.                                          ##
##                                                                                       ##
##          This program is distributed in the hope that it will be useful,              ##
##          but WITHOUT ANY WARRANTY; without even the implied warranty of               ##
##          MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                ##
##          GNU General Public License for more details.                                 ##
##                                                                                       ##
##          You should have received a copy of the GNU General Public License            ##
##          along with this program.  If not, see <http://www.gnu.org/licenses/>.        ##
##                                                                                       ##
###########################################################################################

import argparse
import json
import os
import re
import sys
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

import requests
import termcolor
from libnmap.parser import NmapParser
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.firefox.options import Options
import urllib3

# disable requests warnigns
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def checkFolder(foldername):
    """
    Checks if a folder exists
    """
    if not os.path.exists(foldername):
        os.makedirs(foldername)

def printError(errorMsg):
    termcolor.cprint(errorMsg, 'red', attrs=['bold'], file=sys.stderr)


def printGreen(infoMsg):
    termcolor.cprint(infoMsg, 'green', attrs=['bold'], file=sys.stderr)


def printBold(infoMsg):
    termcolor.cprint(infoMsg, attrs=['bold'], file=sys.stderr)


def printYellow(msg):
    termcolor.cprint(msg, 'yellow', attrs=['bold'], file=sys.stderr)


def printBlue(msg):
    termcolor.cprint(msg, 'blue', attrs=['bold'], file=sys.stderr)


def isOnline(site, timeout=15):
    '''
    Check if a site is online
    '''
    # requests config
    userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0'
    headers = {
        'User-Agent': userAgent
    }
    try:
        res = requests.get(site, headers=headers, verify=False, timeout=timeout)
        if res.status_code != 200:
            site = None
    except requests.exceptions.RequestException as e:
        print(e)
        site = None
    return site



def checkUrlSite(site):
    '''
    Check if a site from urls file is up, otherwise it returns None
    '''
    originalSite = site
    printYellow('   [+] Testing site: ' + site)
    p = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
    m = re.search(p, site)

    if 'http://' in site:
        site += ':' + str(m.group('port'))
        site = isOnline(site)
    elif 'https://' in site:
        site += ':' + str(m.group('port'))
        site = isOnline(site)
    else:
        # test for http
        site = 'http://' + site + ':' + m.group('port')
        site = isOnline(site)
        # test for https
        if site is None: 
            site = 'https://' + originalSite + ':' + m.group('port')
            site = isOnline(site)
    if site is not None and site[len(site)-1:] == ':':
        site = site[:-1]
    if site is None:
        printError('    [-] ' + originalSite + ' is down')
    else:
        printGreen('    [*] ' + site + ' is up')

    return site

def checkNmapSite(site):
    '''
    Check if a site from nmap file is up, otherwise it returns None
    '''
    originalSite = site
    printYellow('   [+] Testing site: ' + site)    
    site = isOnline(site)
    if site is None:
        printError('    [-] ' + originalSite + ' is down')
    else:
        printGreen('    [*] ' + site + ' is up')
    return site

def readTxtFile(filePath, nThreads=10):
    '''
    Read a file and check that the url addresses are valid
    '''
    pool = ThreadPoolExecutor(max_workers=nThreads)

    with open(filePath, 'r') as rf:
        sites = rf.readlines()
    
    sites = [x.strip() for x in sites]
    sites = list(filter(None, sites))
    tmpSize = len(sites)
    printBold('[+] Testing ' + str(tmpSize) + ' sites')
    sites = [pool.submit(checkUrlSite, x) for x in sites]
    pool.shutdown(wait=True)
    sites = [x.result() for x in sites]
    sites = [x for x in sites if x is not None]
    printBold('[+] Read ' + str(tmpSize) + ' urls')
    printGreen('     [-] ' + str(len(sites)) + ' sites up')
    printError('     [-] ' + str(tmpSize - len(sites)) +
               ' sites not responding')
    return sites

def screenshotList(siteList, outputFolder, nThreads=10):
    '''
    Scrolls through a site list and takes a snapshot of each one
    '''
    pool = ThreadPoolExecutor(max_workers=nThreads)
    printBold('[+] Taking ' + str(len(siteList)) +  ' screenshots')
    res = [pool.submit(screenshot, site, outputFolder) for site in siteList]
    pool.shutdown(wait=True)
    
def screenshot(site, outputFolder):
    '''
    Take a screenshot from a website
    '''
    options = Options()
    options.add_argument('--headless')
    printGreen('   [.] Taking a screenshot from ' + site)
    binary = 'firefox/firefox-bin'
    driver = webdriver.Firefox(options=options, firefox_binary=binary)
    driver.set_page_load_timeout(20)
    try:
        driver.get(site)
        screenshot = driver.save_screenshot(os.path.join(
            outputFolder, site.replace('/', '').replace(':', '_') + '.png'))
    except TimeoutException as e:
        print(e)
    driver.close()
    driver.quit()


def readNmapFile(fileName, nThreads=10):
    '''
    Read a nmap file and check that the url addresses are valid
    '''
    sites = []
    if fileName.endswith(".xml"):
        with open(fileName, 'r') as nmapFile:
            nmapData = nmapFile.read()
        nmap_report = NmapParser.parse_fromstring(nmapData, "XML")
        for host in nmap_report.hosts:
            for service in host.services:
                if 'http' == service.service or 'http-proxy' == service.service:
                    sites.append('http://' + host.address + ':' + str(service.port))
                elif 'https' in service.service:
                    sites.append('https://' + host.address + ':' + str(service.port))
                else:
                    sites.append('http://' + host.address + ':' + str(service.port))
                    sites.append('https://' + host.address + ':' + str(service.port))
    else:
        printError("    [+] Error parsing nmap file " + fileName + " ...")
    
    pool = ThreadPoolExecutor(max_workers=nThreads)
    tmpSize = len(sites)
    printBold('[+] Testing ' + str(tmpSize) + ' sites')
    sites = [pool.submit(checkNmapSite, x) for x in sites]
    pool.shutdown(wait=True)
    sites = [x.result() for x in sites]
    sites = [x for x in sites if x is not None]
    printBold('[+] Read ' + str(tmpSize) + ' urls')
    printGreen('     [-] ' + str(len(sites)) + ' sites up')
    printError('     [-] ' + str(tmpSize - len(sites)) +
               ' sites not responding')
    return sites

if __name__ == '__main__':
    banner = '''
        ▄████▄   ▒█████   ▒█████   ███▄    █   ██████  ██░ ██  ▒█████  ▄▄▄█████▓
        ▒██▀ ▀█  ▒██▒  ██▒▒██▒  ██▒ ██ ▀█   █ ▒██    ▒ ▓██░ ██▒▒██▒  ██▒▓  ██▒ ▓▒
        ▒▓█    ▄ ▒██░  ██▒▒██░  ██▒▓██  ▀█ ██▒░ ▓██▄   ▒██▀▀██░▒██░  ██▒▒ ▓██░ ▒░
        ▒▓▓▄ ▄██▒▒██   ██░▒██   ██░▓██▒  ▐▌██▒  ▒   ██▒░▓█ ░██ ▒██   ██░░ ▓██▓ ░ 
        ▒ ▓███▀ ░░ ████▓▒░░ ████▓▒░▒██░   ▓██░▒██████▒▒░▓█▒░██▓░ ████▓▒░  ▒██▒ ░ 
        ░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░ ▒░▒░▒░   ▒ ░░   
        ░  ▒     ░ ▒ ▒░   ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░▒  ░ ░ ▒ ░▒░ ░  ░ ▒ ▒░     ░    
        ░        ░ ░ ░ ▒  ░ ░ ░ ▒     ░   ░ ░ ░  ░  ░   ░  ░░ ░░ ░ ░ ▒    ░      
        ░ ░          ░ ░      ░ ░           ░       ░   ░  ░  ░    ░ ░           
        ░                                                                        
    '''
    print(banner)
    print()
    print('										CoonShot - v 0.1')
    print(' 											@aetsu')
    print()
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", dest="inputFile",
                        help="txt file (.txt)")
    parser.add_argument("-x", dest="nmapFile",
                        help="Nmap file (.xml)")
    parser.add_argument("-u", dest="siteUrl", help="url to take a screenshot")
    parser.add_argument("-o", dest="outputFolder", help="Output folder")
    parser.add_argument("-t", dest="threads", help="Number of threads (default 10)")
    params = parser.parse_args()
    if params.threads:
        nThreads = int(params.threads)
    else:
        nThreads = 10
    if params.inputFile:
        sites = readTxtFile(params.inputFile, nThreads)
        if params.outputFolder:
            outputFolder = params.outputFolder
        else:
            outputFolder = params.inputFile + '_screenshots'
        # adds custom driver path to PATH variable for use geckodriver
        tmpPath = os.environ['PATH']
        os.environ['PATH'] = tmpPath + ':' + 'driver'
        checkFolder(outputFolder)
        screenshotList(sites, outputFolder, nThreads)
    elif params.nmapFile:
        sites = readNmapFile(params.nmapFile)
        if params.outputFolder:
            outputFolder = params.outputFolder
        else:
            outputFolder = params.nmapFile + '_screenshots'
        # adds custom driver path to PATH variable for use geckodriver
        tmpPath = os.environ['PATH']
        os.environ['PATH'] = tmpPath + ':' + 'driver'
        checkFolder(outputFolder)
        screenshotList(sites, outputFolder, nThreads)
    elif params.siteUrl:
        if params.outputFolder:
            outputFolder = params.outputFolder
        else:
            outputFolder = params.siteUrl.replace('//', '_') + '_screenshots'
        # adds custom driver path to PATH variable for use geckodriver
        tmpPath = os.environ['PATH']
        os.environ['PATH'] = tmpPath + ':' + 'driver'
        checkFolder(outputFolder)
        screenshotList([checkUrlSite(params.siteUrl)], outputFolder, nThreads)
