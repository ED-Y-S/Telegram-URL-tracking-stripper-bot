import re
from typing import Tuple

import requests
import logging
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)


class Rule:
    BINARY_OPTIONS = [
        "script",
        "image",
        "stylesheet",
        "object",
        "xmlhttprequest",
        "object-subrequest",
        "subdocument",
        "document",
        "elemhide",
        "other",
        "background",
        "xbl",
        "ping",
        "dtd",
        "media",
        "third-party",
        "match-case",
        "collapse",
        "donottrack",
        "websocket",
        "removeparam",
        "follow302",
    ]
    OPTIONS_SPLIT_PAT = ',(?=~?(?:%s))' % ('|'.join(BINARY_OPTIONS + ["domain"]))
    OPTIONS_SPLIT_RE = re.compile(OPTIONS_SPLIT_PAT)

    def __init__(self, line: str) -> None:
        line = line.strip()
        if len(line) == 0 or line.startswith('!'):
            # logging.debug(f'Ignore comment/empty line: {line}')
            return

        s = line.split('$', maxsplit=1)
        if len(s) != 2:
            logging.error(f'Not a valid rule line: {line}')
            return

        pattern_text, modifier_text = s

        # logging.debug(f'Pattern Text: {pattern_text}')

        if pattern_text.startswith('@@'):
            self.type = 'whitelist'
            pattern_text = pattern_text[2:]
        else:
            self.type = 'blacklist'

        self.pattern = self.parse_pattern_text(pattern_text)

        # logging.debug(f'Modifier Text: {modifier_text}')
        modifier_text_split = self.OPTIONS_SPLIT_RE.split(modifier_text)

        # logging.debug(f'Modifier text split: {modifier_text_split}')

        # 只关注 removeparam 和 domain
        for m in modifier_text_split:
            s = m.split('=', maxsplit=1)
            if len(s) == 2:
                cmd, arg = s
            elif len(s) == 1:
                cmd, arg = s[0], ''
            else:
                raise RuntimeError(f'Invalid modifier: {m}')
            if cmd == 'removeparam':
                assert not hasattr(self, 'removeparam')
                self.removeparam = self.parse_pattern_text(arg)
                logging.debug(f'Remove param: {self.removeparam}')
            elif cmd == 'domain':
                assert not hasattr(self, 'domain')
                self.domain = self.parse_pattern_text(arg)
                # logging.debug(f'Domain: {self.domain}')
            elif cmd == 'follow302':
                self.follow302 = True

    # https://github.com/scrapinghub/adblockparser/blob/master/adblockparser/parser.py#L221
    @classmethod
    def parse_pattern_text(cls, pattern_text: str):
        # 先检查是否已经是正则表达式了
        if pattern_text.startswith('/') and pattern_text.endswith('/'):
            if len(pattern_text) > 1:
                return re.compile(pattern_text[1:-1])
            else:
                logging.error(f'Not a valid pattern: {pattern_text}')
                return None

        if len(pattern_text) == 0:
            return re.compile('')

        pattern = re.sub(r"([.$+?{}()\[\]\\])", r"\\\1", pattern_text)
        pattern = pattern.replace("^", r"(?:[^\w\d_\-.%]|$)")
        pattern = pattern.replace("*", r".*")
        if pattern[-1] == '|':
            pattern = pattern[:-1] + r'$'
        if pattern[:2] == '||':
            if len(pattern) > 2:
                pattern = r"^(?:[^:/?#]+:)?(?://(?:[^/?#]*\.)?)?" + pattern[2:]
        elif pattern[0] == '|':
            pattern = r'^' + pattern[1:]
        pattern = re.sub(r"(\|)[^$]", r"\|", pattern)

        return re.compile(pattern)

    def check_follow_302(self, url: str, domain: str) -> bool:
        if hasattr(self, 'pattern') and not self.pattern.match(url):
            return False
        if hasattr(self, 'domain') and not self.domain.match(domain):
            return False
        if hasattr(self, 'follow302'):
            return self.follow302
        return False

    def check_blacklist(self, url: str, domain: str, query_names: set) -> set:
        # 先黑名单再白名单
        if hasattr(self, 'pattern') and not self.pattern.match(url):
            return set()
        if hasattr(self, 'domain') and not self.domain.match(domain):
            return set()
        if not hasattr(self, 'removeparam'):
            return set()
        param_to_remove = set()
        for p in query_names:
            if self.removeparam.match(p):
                param_to_remove.add(p)
        return param_to_remove

    def check_whitelist(self, url: str, domain: str, query_names: set) -> set:
        # 先黑名单再白名单
        if hasattr(self, 'pattern') and not self.pattern.match(url):
            return set()
        if hasattr(self, 'domain') and not self.domain.match(domain):
            return set()
        if not hasattr(self, 'removeparam'):
            return set()
        param_to_add = set()
        for p in query_names:
            if self.removeparam.match(p):
                param_to_add.add(p)
        return param_to_add


class RuleList:

    def __init__(self, blacklist_lines, whitelist_lines) -> None:
        self.blacklist = [Rule(line) for line in blacklist_lines]
        self.whitelist = [Rule(line) for line in whitelist_lines]

    def check_follow_302(self, url: str, domain: str) -> bool:
        for rule in self.whitelist:
            if rule.check_follow_302(url, domain):
                return False
        for rule in self.blacklist:
            if rule.check_follow_302(url, domain):
                return True

    def get_params_to_remove(self, url: str, domain: str, query_names: set) -> set:
        params_to_remove = set()
        for rule in self.blacklist:
            params_to_remove = params_to_remove.union(rule.check_blacklist(url, domain, query_names))
        for rule in self.whitelist:
            params_to_remove = params_to_remove.difference(rule.check_whitelist(url, domain, query_names))
        return params_to_remove

    def strip_url(self, url: str) -> Tuple[bool, str]:
        parser = urlparse(url)
        domain = parser.hostname
        query = parse_qs(parser.query)

        if self.check_follow_302(url, domain):
            logging.debug(f'Follow 302: {url}')
            r = requests.get(url)
            return self.strip_url(r.url)

        params_to_remove = self.get_params_to_remove(url, domain, query.keys())

        for p in params_to_remove:
            query.pop(p)
        is_modified = len(params_to_remove) > 0

        if is_modified:
            parser = parser._replace(query=urlencode(query, doseq=True))
            url_stripped = urlunparse(parser)
            return True, url_stripped
        else:
            return False, url


extra_blacklist = """
||music.163.com^$removeparam
||bilibili.com^$removeparam
||twitter.com^$removeparam
||zhihu.com^$removeparam
||b23.tv^$follow302
||mp.weixin.qq.com^$removeparam=/abtest_cookie|lang|clicktime|ascene|version|sharer_sharetime|sharer_shareid|wx_header|subscene|pass_ticket|enterid/
"""

extra_whitelist = """
||music.163.com^$removeparam=id
"""

follow_302_domain_list = [
    re.compile(r'b23.tv')
]


def read_adguard_rules():
    general_url = 'https://github.com/AdguardTeam/AdguardFilters/raw/master/TrackParamFilter/sections/general_url.txt'
    specific = 'https://github.com/AdguardTeam/AdguardFilters/raw/master/TrackParamFilter/sections/specific.txt'
    whitelist = 'https://github.com/AdguardTeam/AdguardFilters/raw/master/TrackParamFilter/sections/whitelist.txt'
    general_url_text = requests.get(general_url).text
    specific_text = requests.get(specific).text
    whitelist_text = requests.get(whitelist).text
    #
    blacklist_lines = general_url_text.split('\n') + specific_text.split('\n') + extra_blacklist.split('\n')
    whitelist_lines = whitelist_text.split('\n') + extra_whitelist.split('\n')

    # blacklist_lines = extra_blacklist.splitlines()
    # whitelist_lines = extra_whitelist.splitlines()

    rulelist = RuleList(blacklist_lines, whitelist_lines)

    return rulelist


# extra_rules = {
#     r'music.163.com$': {
#         'reserve': ['id']
#     },
#     r'b23.tv$': {
#         'follow_302': True,
#     },
#     r'bilibili.com$': {
#         'remove_all': True,
#     },
#     r'twitter.com$': {
#         'remove_all': True,
#     },
#     r'zhihu.com$': {
#         'remove_all': True,
#     },
#     r'^example.com$': {
#         # 规则优先级由低到高
#         'reserve': ['query1', 'query2'],
#         'remove': ['query1', 'query2'],
#         'remove_all': True,
#         'follow_302': True,
#     }
# }
#
# extra_rules = {
#     re.compile(key): value for key, value in extra_rules.items()
# }

if __name__ == '__main__':
    rulelist = read_adguard_rules()

    urls = [
        'https://www.bilibili.com/video/BV15U4y1q7At',
        'https://b23.tv/Qbycogr',
        'https://twitter.com/mischiefanimals/status/1550962545447636992?s=20&t=1TceRpyMCVn04YYYGsXANA',
        'https://mp.weixin.qq.com/s?__biz=MjM5NTUxOTc4Mw==&mid=2650553807&idx=4&sn=edb6e9776ed009900041acd3d4d8a739&mpshare=1&srcid=0725spPGNGqu2XRovAVQuEsu&sharer_sharetime=1658719326929&sharer_shareid=6683ab9840407b83a27daddce5ec5c9e&from=singlemessage&scene=1&subscene=10000&clicktime=1658719351&enterid=1658719351&ascene=1&devicetype=android-29&version=28001541&nettype=WIFI&abtest_cookie=AAACAA%3D%3D&lang=zh_CN&exportkey=ATCOd%2FtPziseV6Yl7%2FsJPJo%3D&pass_ticket=55X0BS79V4XkNf8mqFKo5AsNhwvRsyg%2BqF7PXAKdkoGUADqBMunz0dfNmONNqyjq&wx_header=3',
        'https://y.music.163.com/m/song?id=116718&uct=I3BzueBE%2Flb0oWGnW4dB3Q%3D%3D&dlt=0846&app_version=8.7.61&sc=wmv&tn=',
    ]

    for url in urls:
        print(rulelist.strip_url(url))
