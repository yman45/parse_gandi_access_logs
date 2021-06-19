import re
import smtplib
from email.message import EmailMessage
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Union, List, Dict

# for 3.7 we need typing.List, typing.Dict, etc...
RebuiltLogLines = List[str]
ResultData = Union[int, RebuiltLogLines]
PerDayDict = Dict[str, ResultData]
ResultDict = Dict[str, PerDayDict]

FILE_LOCATION = "/home/yman/gandi_logs/access.log"
JUNK_AGENTS = frozenset([
    "googlebot", "wordpress", "yandexbot", "bingbot", "petalbot", "dotbot",
    "internal dummy connection", "semrushbot", "bytespider", "barkrowler",
    "telegrambot", "seznambot", "ccbot", "amazonbot", "mail.ru_bot",
    "go-http-client", "scaninfo@paloaltonetworks.com", "mauibot", "smtbot",
    "thinkbot", "go http package", "netsystemsresearch.com"
])
LOG_REGEX = re.compile(r"""(?:\S+)\s             # server name
                       (?P<clip>[0-9a-f:.]+)     # remote IP
                       \s-\s-\s                  # remote logname + user
                       \[(?P<ts>.+?)\]\s         # timestamp
                       \(\d+\ss\)\s              # processing time
                       \"(?P<req>.+?)\"\s        # request
                       (?P<status>\d+)\s         # status code
                       (?:-|\d+)\s               # response size
                       \".+?\"\s                 # referer
                       \"(?P<uagent>.+)\"        # user-agent""", re.VERBOSE)
SENDER = "parser@yman.site"
RECEIVER = "yman@protonmail.ch"


def agent_is_junk(agent: str) -> bool:
    """Filter user-agents that contain line from 'junk_agents' list, i.e. bots
    and some misc stuff."""
    agent = agent.lower()
    if any(word in agent for word in JUNK_AGENTS):
        return True
    return False


def parse_access_log(file_location: str) -> ResultDict:
    """Parse httpd access log (Gandi simple hosting instance config), filter
    out uninteresting requests, bogus, bots, etc. Good lines will be packed
    into per-day dict with hits count and altered log lines."""
    result = defaultdict(lambda: {"hits": 0, "lines": []})
    with open(file_location, "r", encoding="utf-8") as logfile:
        for line in logfile:
            match_result = LOG_REGEX.match(line)
            if not match_result:
                print("Can not parse line:", line)
                continue
            (clip, timestamp, request, status_code,
             uagent) = match_result.groups()
            status_code = int(status_code)
            # filter bots and maintenance requests
            if agent_is_junk(uagent):
                continue
            # filter additional data downloads and bogus requests
            if "wp-" in request or "xmlrpc" in request or "favicon" in request:
                continue
            # filter not successful status codes
            if status_code < 200 or status_code > 299:
                continue
            full_ts = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
            day = datetime.strftime(full_ts, "%d-%m-%Y")
            result[day]["hits"] += 1
            rebuilt_line = f"{clip} : {status_code} : {request} : {uagent}"
            result[day]["lines"].append(rebuilt_line)
    return result


def email_results(date: str, one_day_data: PerDayDict) -> None:
    """Email results of one day."""
    report_string = f"Results for {date}\nTotal hits: {one_day_data['hits']}\n"
    for line in one_day_data["lines"]:
        report_string = f"{report_string}{line}\n"
    msg = EmailMessage()
    msg.set_content(report_string[:-1])
    msg["Subject"] = "Daily dvjourney access.log parse results"
    msg["From"] = SENDER
    msg["To"] = RECEIVER
    server = smtplib.SMTP("localhost")
    server.set_debuglevel(1)
    server.send_message(msg)
    server.quit()


if __name__ == "__main__":
    res = parse_access_log(FILE_LOCATION)
    yesterday = datetime.now() - timedelta(days=1)
    yesterday_formatted = datetime.strftime(yesterday, "%d-%m-%Y")
    email_results(yesterday_formatted, res[yesterday_formatted])
