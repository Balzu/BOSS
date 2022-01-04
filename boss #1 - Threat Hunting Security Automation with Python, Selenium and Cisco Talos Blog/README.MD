# Threat Hunting Security Automation with Python, Selenium and Cisco Talos Blog
### A Security Automation tool to extract IOC from Cisco Talos Blog

![pyseleniumtalos](https://user-images.githubusercontent.com/24792152/146275139-e196e906-5b3f-4182-994d-2d0ce867726d.png)

### Goal of the tool
This tool uses python, a powerful scripting language that runs on all platforms, Selenium, a python module to make browser automation, and Cisco Talos Blog series,
in order to extract valuable threat hunting information from open-source cybersecurity feeds.

### How to Run
All the code is packed inside a Python script, so you basically need to download [Python 3](https://www.python.org/downloads/), and to ensure that 
the *selenium* module is installed (`pip install selenium`). 
Since the Talos blog page is dinamically loaded via Javascript, si ply downloading the raw HTML won't be sufficient to download the data we are interested in. Instead, we will use Chrome to run the javascript and build the functional HTML page on our behalf. To link Chrome execution to our python script we will need WebDriver, an open source tool for the automated testing of web apps. You can download it from [here](https://chromedriver.chromium.org/home). Then, the webdriver should be in PATH in order to be executable. The easiest way is to copy it in the same folder of your script.
Finally, simply run with `Python talos_ioc_extractor.py`

### Blog Post

There is an associated blog post, where I better explain some technical details.
Take a look [here!](http://thebytemachine.com/security_automation_with_python_selenium_and_talos_blog)

### What's next?

- Once the IOC are programmatically extracted, you may want to continue the automation by feeding them to your Cyber Security platform 
  (do you have REST APIs?)
- We can simply extend the script to parse and extract malicious domains and IP addresses (good exercise!)


### Demo
In the following Demo, I feed the tool with a valid url from Talos Blog (any blog whose title starts with "Threat Roundup")
and the tool extracts the IOC hashes from the blog.

![Alt Text](https://github.com/Balzu/BOSS/blob/main/boss%20%231%20-%20Threat%20Hunting%20Security%20Automation%20with%20Python%2C%20Selenium%20and%20Cisco%20Talos%20Blog/demo.gif)
