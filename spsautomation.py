import configparser
import os
import re
import requests
import time

from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC

def load_config(config_path = None):

    global config
    config = configparser.ConfigParser()

    if config_path is None:
        config.read("./config.ini")
    else:
        config.read(config_path)

def config_section_map(section):
    dict1 = {}
    options = config.options(section)
    for option in options:
        try:
            dict1[option] = config.get(section, option)
            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1

def configure_selenium(wait_time = None, file_download_type = None, download_directory = None):

    # create firefox profile
    profile = webdriver.FirefoxProfile()
    profile.set_preference('browser.download.manager.showWhenStarting', False)

    if file_download_type is not None:
        profile.set_preference('browser.helperApps.neverAsk.saveToDisk', file_download_type)

    if download_directory is not None:
        dl_directory = download_directory

        # create directory if it does not exist
        if not os.path.exists(dl_directory):
            os.makedirs(dl_directory)

        # get the absolute path of the download directory
        dl_directory = os.path.abspath(dl_directory)

        # set options to download file to the specified directory
        profile.set_preference('browser.download.folderList', 2) # custom location
        profile.set_preference('browser.download.dir', dl_directory)

    # create driver
    driver = webdriver.Firefox(profile)

    if wait_time is not None:
        driver.implicitly_wait(wait_time)

    return driver

def login_to_schoolmint_selenium(driver, host, username, password):
    sign_in_url = host + '/signin'
    driver.get(sign_in_url)
    time.sleep(5)
    assert "SchoolMint" in driver.title
    elem = driver.find_element_by_id("login")
    elem.clear()
    elem.send_keys(username)
    elem = driver.find_element_by_id("password")
    elem.send_keys(password)
    elem.send_keys(Keys.RETURN)
    time.sleep(4)

def login_to_illuminate_selenium(driver, host, username, password):
    sign_in_url = host + '/isi/&page=SisLogin'
    driver.get(sign_in_url)
    time.sleep(5)
    assert "Illuminate Education" in driver.title
    elem = driver.find_element_by_id("username")
    elem.clear()
    elem.send_keys(username)
    elem = driver.find_element_by_id("password")
    elem.send_keys(password)
    elem.send_keys(Keys.RETURN) # actuate the 'next' key that shows which school site to log in to
    time.sleep(3)
    elem = driver.find_element_by_id("button_login") # actuate the 'login' key (we can just log in using the default site)
    elem.click()
    time.sleep(3)

def login_to_mealtime_selenium(driver, host, username, password):
    sign_in_url = host + '/Base/SignIn.aspx'
    driver.get(sign_in_url)
    time.sleep(3)
    assert "Sign In" in driver.title
    elem = driver.find_element_by_id("username")
    elem.clear()
    elem.send_keys(username)
    elem = driver.find_element_by_id("password")
    elem.send_keys(password)
    elem.send_keys(Keys.RETURN)
    time.sleep(3)

def login_to_nwea_selenium(driver, host, username, password):
    sign_in_url = host + '/admin'   # redirects to SSO, which is fine
    driver.get(sign_in_url)
    time.sleep(3)
    assert "NWEA UAP Login" in driver.title
    elem = driver.find_element_by_id("username")
    elem.clear()
    elem.send_keys(username)
    elem = driver.find_element_by_id("password")
    elem.send_keys(password)
    elem.send_keys(Keys.RETURN)
    time.sleep(3)

def login_to_chalk_selenium(driver, host, username, password):
    sign_in_url = host + '/signin'
    driver.get(sign_in_url)
    time.sleep(4)
    assert "Sign In" in driver.title
    assert "Chalk Schools" in driver.title
    elem = driver.find_element_by_id("session_email")
    elem.clear()
    elem.send_keys(username)
    elem = driver.find_element_by_id("password")
    elem.send_keys(password)
    elem.send_keys(Keys.RETURN)
    time.sleep(3)

def login_to_chalk_requests(driver, host, username, password):
    sign_in_url = host + '/signin'

    session = requests.Session()

    # get authenticity token
    s = session.get(sign_in_url)
    sign_in_html = BeautifulSoup(s.text, 'html.parser')
    authenticity_token = sign_in_html.find(class_="well well-form").form.contents[1]['value']

    # This will be posted to Chalk to login
    login_payload = {
        'authenticity_token': authenticity_token,
        'session[email]': username,
        'session[password]': password
    }

    login_response = s.post(host + '/sessions', data=login_payload)

    # get cookies to send with future get requests to keep the session alive
    cookies = requests.utils.dict_from_cookiejar(login_response.cookies)

    return {'session': session, 'cookies': cookies}

# the below is not yet working correctly
def unescape(text):
    regex = re.compile(b'\\\\(\\\\|[0-7]{1,3}|x.[0-9a-f]?|[\'"abfnrt]|.|$)')
    def replace(m):
        b = m.group(1)
        if len(b) == 0:
            raise ValueError("Invalid character escape: '\\'.")
        i = b[0]
        if i == 120:
            v = int(b[1:], 16)
        elif 48 <= i <= 55:
            v = int(b, 8)
        elif i == 34: return b'"'
        elif i == 39: return b"'"
        elif i == 92: return b'\\'
        elif i == 97: return b'\a'
        elif i == 98: return b'\b'
        elif i == 102: return b'\f'
        elif i == 110: return b'\n'
        elif i == 114: return b'\r'
        elif i == 116: return b'\t'
        else:
            s = b.decode('ascii')
            raise UnicodeDecodeError(
                'stringescape', text, m.start(), m.end(), "Invalid escape: %r" % s
            )
        return bytes((v, ))
    result = regex.sub(replace, text)
