import time
import requests
import re
import base64


rules_url = 'https://raw.githubusercontent.com/buzhangjiuzhou/mygfwlist/master/gfwlist.txt'

unhandle_rules = []


open('gfwlist_raw.txt', 'w', encoding='utf-8') \
    .read()


def clear_format(rule):
    rules = []

    rule = rule.split('\n')
    for row in rule:
        row = row.strip()

        # 注释 直接跳过
        if row == '' or row.startswith('!') or row.startswith('@@') or row.startswith('[AutoProxy'):
            continue

        # 清除前缀
        row = re.sub(r'^\|?https?://', '', row)
        row = re.sub(r'^\|\|', '', row)
        row = row.lstrip('.*')

        # 清除后缀
        row = row.rstrip('/^*')

        rules.append(row)

    return rules


def filtrate_rules(rules):
    ret = []

    for rule in rules:
        rule0 = rule

        # only hostname
        if '/' in rule:
            split_ret = rule.split('/')
            rule = split_ret[0]

        if not re.match('^[\w.-]+$', rule):
            unhandle_rules.append(rule0)
            continue

        ret.append(rule)

    ret = list( set(ret) )
    ret.sort()

    return ret



# main

rule = get_rule(rules_url)

rules = clear_format(rule)

rules = filtrate_rules(rules)

open('shadowRocket.list', 'w', encoding='utf-8') \
    .write('\n'.join(rules))
