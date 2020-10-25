import math
import ipaddress
from zipfile import ZipFile


import tldextract


def get_top_n_alexa(zip_path, filepath='top-1m.csv', n=1000):
    input_zip = ZipFile(zip_path)
    extract_alexa_entries = []
    with input_zip.open(filepath, 'r') as f:
        for i, row in enumerate(f.readlines()):
            extract_alexa_entries.append(row.decode('utf-8').split(',')[1].strip())
            if i == n - 1:
                break
    return extract_alexa_entries


def is_ip_address(string):
    try:
        ipaddress.ip_address(string)
    except ValueError:
        return False
    return True


def is_ip_address_public(string):
    try:
        ipaddr = ipaddress.ip_address(string)
        return ipaddr.is_global
    except ValueError:
        return False


def shannon_entropy(string):
    # get probability of chars in string
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    # calculate the entropy
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


def clean_domain(domain):
    ext = tldextract.extract(domain)
    if ext.suffix:  # If we don't have suffix either IP address or 'local/home/lan/etc'
        return ext.subdomain, ext.domain, ext.suffix
    return domain


def calculate_suspicious_score(row):
    """
    :param row: Row of a DataFrame
    :return: Score between -1...1 (-1 = not_suspicious, 1 = suspicious)
    """
    score = 0
    if row['host_is_ip']:
        score += 5
    else:
        score -= 5
    if row['common_host_domain']:
        score -= 5
    else:
        score += 5
    if not row['host_is_ip']:
        score += row['host_entropy']
    else:
        if row['host_is_public_ip']:
            score += 5
        else:
            score -= 5
    return float(score)/20
