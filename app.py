from ast import main
from glob import escape
import re
from urllib.parse import urlparse
from tld import get_tld
from flask import Flask
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report,confusion_matrix,accuracy_score
# from lightgbm import LGBMClassifier
import sklearn as sl
import numpy as np
import pickle
app = Flask(__name__)

@app.route('/<test_url>')
def hello_world(test_url):
    features_test = main(test_url)
    # print("=====--------",test_url,features_test)
    features_test = np.array(features_test).reshape(1,-1)
    
    filename = 'phishing_detection_model'
    lgb = pickle.load(open(filename,'rb'))
    pred = lgb.predict(features_test)
    if int(pred[0]) == 0:
        res="Phishing"
        return res

    elif int(pred[0]) == 1.0:
        res="phishing "
        return res

    elif int(pred[0]) == 2.0:
        res="phishing"
        return res

    elif int(pred[0]) == 3.0:
        res="BENIGN,IT'S SAFE TO USE"
        return res
    



def main(url):
  status = []

  status.append(having_ip_address(url))
  status.append(abnormal_url(url))
  status.append(count_dot(url))
  status.append(count_www(url))
  status.append(count_atrate(url))
  status.append(no_of_dir(url))
  status.append(no_of_embed(url))

  status.append(shortening_services(url))
  status.append(count_https(url))
  status.append(count_http(url))

  #status.append(count_per(url))
  #status.append(count_ques(url))
  #status.append(count_hyphen(url))
  #status.append(count_equal(url))

  #status.append(url_length(url))
  #status.append(hostname_length(url))
  #status.append(suspicious_words(url))
  #status.append(digit_count(url))
  #status.append(letter_count(url))
  #status.append(fd_length(url))
#   tld = get_tld(url,fail_silently=True)

#   status.append(tld_length("com"))
  status.append(len("com"))


  return status


def having_ip_address(url):
    match =  re.sub(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
        r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
        r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\))'
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', '',str(url))
    if match == url:
          return 1
    else:
          return 0
    


def abnormal_url(url):
    # Get the hostname from the URL
    hostname = urlparse(url).hostname
    hostname = str(hostname)

    # Check if the hostname contains any unusual patterns (customize this logic)
    match = re.search(r'your_pattern_here', hostname)

    # Check if a match was found
    if match:
        return 1  # Abnormal URL
    else:
        return 0
    

def count_dot(url):
  count_dot = url.count('.')
  return count_dot

def count_www(url):
    return url.count('www')

# Function to count the occurrence of '@' in the URL
def count_atrate(url):
    return url.count('@')

# Function to count the number of directories in the URL
def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

# Function to count the occurrence of '//' in the URL
def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')


def shortening_services(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gd|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipur1\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|just\.as|bkite\.com|snipr\.com|fic\.kr|1oopt\.us|'
                      'doiop\.com|short\.ie|k1\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|1nkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.1v|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzur1\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|preetylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|lurl\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)

    if match:
        return 1
    else:
        return 0
    
def count_https(url):
    return url.count('https')

def count_http(url):
  return url.count('http')

def tld_length(tld):
  try:
      return len(tld)
  except:
      return -1