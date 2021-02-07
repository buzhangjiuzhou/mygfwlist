# -*- coding: utf-8 -*-

import time
import re
import base64


# unhandle_rules = []


# def clear_format(rule):
#     rules = []

#     rule = rule.split('\n')
#     for row in rule:
#         row = row.strip()

#         # 注释 直接跳过
#         if row == '' or row.startswith('!') or row.startswith('@@') or row.startswith('[AutoProxy'):
#             continue

#         # 清除前缀
#         row = re.sub(r'^\|?https?://', '', row)
#         row = re.sub(r'^\|\|', '', row)
#         row = row.lstrip('.*')

#         # 清除后缀
#         row = row.rstrip('/^*')

#         rules.append(row)

#     return rules


# def filtrate_rules(rules):
#     ret = []

#     for rule in rules:
#         rule0 = rule

#         # only hostname
#         if '/' in rule:
#             split_ret = rule.split('/')
#             rule = split_ret[0]

#         if not re.match('^[\w.-]+$', rule):
#             unhandle_rules.append(rule0)
#             continue

#         ret.append(rule)

#     ret = list( set(ret) )
#     ret.sort()

#     return ret
def sort_list(path):
    ret = []
    rules = open(path, 'r', encoding='utf-8').readlines()
    # for rule in rules:
    #    ret.append(rule)
    # ret = list( set(ret) )
    ret = [rule for rule in rules if rule]
    ret.sort()
    open(path, 'w', encoding='utf-8').write(''.join(ret))
    

def getRulesStringFromFile(path, kind, ret):
    file = open(path, 'r', encoding='utf-8')
    contents = file.readlines()
    # ret = ''

    for content in contents:
        content = content.strip('\r\n')
        if not len(content):
            continue
        if content.startswith('!'):
            continue

        if content.startswith('#'):
            ret += content + '\n'
        else:
            prefix = 'DOMAIN-SUFFIX'
            temp_kind = kind
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content):
                prefix = 'IP-CIDR'
                temp_kind = kind + ',no-resolve'
                if '/' not in content:
                    content += '/32'
            elif '.' not in content:
                prefix = 'DOMAIN-KEYWORD'
            ret += prefix + ',%s,%s\n' % (content, temp_kind)

    return ret

def getRulesStringFromFile_ap(path, ip_flag, ret):
    file = open(path, 'r', encoding='utf-8')
    contents = file.readlines()
    # ret = ''

    for content in contents:
        content = content.strip('\r\n')
        if not len(content):
            continue
        
        if ip_flag is True:
            if content.startswith('!'):
                continue
            else:
                ret += content + '\n'
            continue

        if content.startswith('#'):
            ret += content + '\n'
        else:
            prefix = '||'

            ret += prefix + '%s\n' % content

    return ret


# main
# -------------------auto proxy------------------------------
ap_head = open('template/ap_head.txt', 'r', encoding='utf-8').read()
ap_template = open('template/ap_template.txt', 'r', encoding='utf-8')

ap_template = ap_template.read()

ap_template = ap_head + ap_template


# ----------shadowRocket--------------------------

str_head = open('template/sr_head.txt', 'r', encoding='utf-8').read()
str_foot = open('template/sr_foot.txt', 'r', encoding='utf-8').read()
file_template = open('template/banlist.txt', 'r', encoding='utf-8')

template = file_template.read()

template = str_head + template + str_foot

# ----------------------------------------------------------

marks = re.findall(r'{{(.+)}}', template)
ap_mark = 'aplist'
ap_value = ''
ap_value = getRulesStringFromFile_ap('./gfwlist_raw.txt', ip_flag=False, ret=ap_value)
ap_value = getRulesStringFromFile_ap('./gfwlist_ip.txt', ip_flag=True, ret=ap_value)

values = {}
values['build_time'] = time.strftime("%Y-%m-%d %H:%M:%S")
values['gfwlist'] = ''
values['gfwlist'] = getRulesStringFromFile('./gfwlist_raw.txt', 'Proxy', values['gfwlist'])
values['gfwlist'] = getRulesStringFromFile('./gfwlist_ip.txt', 'Proxy', values['gfwlist'])

for mark in marks:
    template = template.replace('{{'+mark+'}}', values[mark])
ap_template = ap_template.replace('{{'+ap_mark+'}}', ap_value)

open('shadowRocket.conf', 'w', encoding='utf-8').write(template)
open('gfwlist_ap.txt', 'w', encoding='utf-8').write(ap_template)
# sort_list('gfwlist_ip.txt')
sort_list('gfwlist_raw.txt')
