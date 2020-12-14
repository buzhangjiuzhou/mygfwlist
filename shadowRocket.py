import time
import re
import base64


unhandle_rules = []


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


def getRulesStringFromFile(path, kind):
    file = open(path, 'r', encoding='utf-8')
    contents = file.readlines()
    ret = ''

    for content in contents:
        content = content.strip('\r\n')
        if not len(content):
            continue

        if content.startswith('#'):
            ret += content + '\n'
        else:
            prefix = 'DOMAIN-SUFFIX'
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content):
                prefix = 'IP-CIDR'
                if '/' not in content:
                    content += '/32'
            elif '.' not in content:
                prefix = 'DOMAIN-KEYWORD'

            ret += prefix + ',%s,%s\n' % (content, kind)

    return ret


# main

rule = open('./gfwlist_raw.txt', 'r', encoding='utf-8').read()

rules = clear_format(rule)

rules = filtrate_rules(rules)

open('shadowRocket.list', 'w', encoding='utf-8') \
    .write('\n'.join(rules))

str_head = open('template/sr_head.txt', 'r', encoding='utf-8').read()
str_foot = open('template/sr_foot.txt', 'r', encoding='utf-8').read()
file_template = open('template/banlist.txt', 'r', encoding='utf-8')

template = file_template.read()

template = str_head + template + str_foot

marks = re.findall(r'{{(.+)}}', template)

values = {}
values['build_time'] = time.strftime("%Y-%m-%d %H:%M:%S")
values['gfwlist'] = getRulesStringFromFile('./shadowRocket.list', 'Proxy')

for mark in marks:
    template = template.replace('{{'+mark+'}}', values[mark])
open('shadowRocket.conf', 'w', encoding='utf-8').write(template)