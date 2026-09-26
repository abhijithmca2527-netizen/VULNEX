
import pytest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys # Added the Keys import here!

@pytest.fixture(scope="module")
def browser():
    # Initialize the Chrome driver before tests run
    driver = webdriver.Chrome()
    driver.implicitly_wait(5)
    yield driver
    # Close the browser after tests finish
    driver.quit()

def test_user_login(browser):
    """Test Case 1: Validate User Authentication"""
    browser.get("http://127.0.0.1:8000/login") 
    
    # Fill in credentials
    browser.find_element(By.NAME, "email").send_keys("jowinlalu100@gmail.com")
    browser.find_element(By.NAME, "password").send_keys("Jowinlalu@123")
    
    # Click Login 
    browser.find_element(By.XPATH, "//button[@type='submit']").click()
    
    # Wait until the URL explicitly contains the word "dashboard"
    WebDriverWait(browser, 10).until(
        EC.url_contains("dashboard")
    )
    
    # Verify login was successful
    assert "dashboard" in browser.current_url

def test_vulnex_scan_pipeline(browser):
    """Test Case 2: Validate Target URL Submission & AI Processing"""
    # Wait for the target input field to load
    url_input = WebDriverWait(browser, 10).until(
        EC.presence_of_element_located((By.NAME, "target_url"))
    )
    
    # Type the URL
    url_input.send_keys("http://testphp.vulnweb.com/")
    
    # Press ENTER directly on the input box (No button click needed)
    url_input.send_keys(Keys.RETURN)

    # Wait for Celery and the AI engine to process the vector
    # We give it up to 60 seconds to finish and redirect to the report page
    WebDriverWait(browser, 60).until(
        EC.url_contains("report")
    )
    
    # Verify the report loaded by checking the URL 
    assert "report" in browser.current_url