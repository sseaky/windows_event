#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Seaky
# @Date:   2023/11/20 9:56


import re
import win32evtlog
import win32api
import argparse
import socket
import pandas as pd
import datetime
from dingtalkchatbot.chatbot import DingtalkChatbot
from config import DING_TOKEN, DING_SECRET

HOSTNAME = socket.gethostname()

# print([x.split()[0] for x in s.split('\n') if x])
EventCols = {
    4624: ['SubjectUserSid', 'SubjectUserName', 'SubjectDomainName', 'SubjectLogonId', 'TargetUserSid',
           'TargetUserName', 'TargetDomainName', 'TargetLogonId', 'LogonType', 'LogonProcessName',
           'AuthenticationPackageName', 'WorkstationName', 'LogonGuid', 'TransmittedServices', 'LmPackageName',
           'KeyLength', 'ProcessId', 'ProcessName', 'IpAddress', 'IpPort', 'ImpersonationLevel', 'RestrictedAdminMode',
           'TargetOutboundUserName', 'TargetOutboundDomainName', 'VirtualAccount', 'TargetLinkedLogonId',
           'ElevatedToken'],
    4625: ['SubjectUserSid', 'SubjectUserName', 'SubjectDomainName', 'SubjectLogonId', 'TargetUserSid',
           'TargetUserName', 'TargetDomainName', 'Status', 'FailureReason', 'SubStatus', 'LogonType',
           'LogonProcessName', 'AuthenticationPackageName', 'WorkstationName', 'TransmittedServices', 'LmPackageName',
           'KeyLength', 'ProcessId', 'ProcessName', 'IpAddress', 'IpPort'],
    4634: ['TargetUserSid', 'TargetUserName', 'TargetDomainName', 'TargetLogonId', 'LogonType']
}


def notice(event):
    print(event['markdown']['title'])
    print(event['markdown']['text'])
    dingding(event)
    return


def dingding(event, is_at_all=False):
    if DING_TOKEN:
        webhook = 'https://oapi.dingtalk.com/robot/send?access_token=' + DING_TOKEN
        xiaoding = DingtalkChatbot(webhook, secret=DING_SECRET)
        if event['EventID'] == 4625:
            is_at_all = True
        if event['Time'].hour > 18 or event['Time'].hour < 9:
            is_at_all = True
        xiaoding.send_markdown(title=event['markdown']['title'], text=event['markdown']['text'], is_at_all=is_at_all)


def read_log(computer=None, logType='Security'):
    h = win32evtlog.OpenEventLog(computer, logType)
    numRecords = win32evtlog.GetNumberOfEventLogRecords(h)
    print('There are {} records'.format(numRecords))

    events = []
    logoff_events_by_logonid = {}
    while True:
        objects = win32evtlog.ReadEventLog(
            h, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
        if not objects:
            break
        for object in objects:
            event = {
                'Time': object.TimeGenerated,
                'ComputerName': object.ComputerName,
                'RecordNumber': object.RecordNumber,
                'EventID': object.EventID
            }
            if object.EventID not in EventCols.keys():
                continue
            cols = EventCols[object.EventID]
            event_data = dict(zip(cols, object.StringInserts))
            event.update(event_data)

            markdown_args = {k: event[k] for k in ['Time', 'ComputerName', 'EventID']}
            if object.EventID == 4624:
                if event.get('LogonProcessName', '').strip() not in ['User32', 'Advapi']:
                    continue
                brief = '{TargetUserName} 登录 {ComputerName} 成功'.format(**event)
                event['message'] = '{Time} {}，来源{IpAddress}{WorkstationName}'.format(brief, **event)
                markdown_args.update({k: event[k] for k in
                                      ['TargetUserName', 'IpAddress', 'WorkstationName', 'TargetLogonId', 'LogonType',
                                       'LogonProcessName', 'ProcessName']})
                text = '# [对勾] **{}** \n'.format(brief)
                for k, v in markdown_args.items():
                    text += '> **{}**: {}  \n'.format(k, v)
                event['markdown'] = {
                    'title': brief,
                    'text': text,
                    'args': markdown_args
                }
            elif object.EventID == 4625:
                brief = '{TargetUserName} 登录 {ComputerName} 失败'.format(**event)
                event['message'] = '{Time} {}，来源{IpAddress}{WorkstationName}'.format(brief, **event)
                markdown_args.update({k: event[k] for k in ['TargetUserName', 'IpAddress', 'WorkstationName']})
                text = '# [打叉] **{}** \n'.format(brief)
                for k, v in markdown_args.items():
                    text += '> **{}**: {}  \n'.format(k, v)
                event['markdown'] = {
                    'title': brief,
                    'text': text,
                    'args': markdown_args
                }
            elif object.EventID == 4634:
                brief = '{TargetUserName} 登出 {ComputerName} 成功'.format(**event)
                event['message'] = '{Time} {}'.format(brief, **event)
                markdown_args.update({k: event[k] for k in ['TargetLogonId', 'LogonType']})
                text = '# [时间] **{}** \n'.format(brief)
                for k, v in markdown_args.items():
                    text += '> **{}**: {}  \n'.format(k, v)
                event['markdown'] = {
                    'title': brief,
                    'text': text,
                    'args': markdown_args
                }
                logoff_events_by_logonid[event['TargetLogonId']] = event
            events.append(event)

    win32evtlog.CloseEventLog(h)

    for event in events:
        if event['EventID'] == 4624:
            TargetLogonId = event['TargetLogonId']
            event['LogonTime'] = event['Time']
            if TargetLogonId in logoff_events_by_logonid:
                logoff_event = logoff_events_by_logonid[TargetLogonId]
                event['LogoffTime'] = logoff_event['Time']
                event['LogonDuration'] = logoff_event['Time'] - event['Time']
                event['LogonDurationSeconds'] = int(event['LogonDuration'].total_seconds())
                logoff_event.update({k: event[k] for k in [
                    'LogonTime', 'LogoffTime', 'LogonDuration', 'LogonDurationSeconds', 'IpAddress', 'WorkstationName',
                    'LogonProcessName', 'ProcessName', 'SubjectLogonId'
                ]})
            else:
                event['LogoffTime'] = '-'
                event['LogonDuration'] = '-'
                event['LogonDurationSeconds'] = '-'
    for TargetLogonId, event in logoff_events_by_logonid.items():
        if not event.get('LogonTime'):
            for k in ['LogonTime', 'LogoffTime', 'LogonDuration', 'LogonDurationSeconds', 'IpAddress',
                      'WorkstationName', 'SubjectLogonId',
                      'LogonProcessName', 'ProcessName']:
                if k not in event:
                    event[k] = '-'

    return events


def main():
    # check if running on Windows NT, if not, display notice and terminate
    if win32api.GetVersion() & 0x80000000:
        print("This sample only runs on NT")
        return

    debug_filename = r'c:\{}_event.txt'.format(HOSTNAME)
    parser = argparse.ArgumentParser()
    parser.add_argument('--list', action='store_true', help='列出事件')
    parser.add_argument('--notice', type=int, help='提醒事件 4624/4625/4634')
    parser.add_argument('--debug', action='store_true', help=r'记录本地日志，{}'.format(debug_filename))
    args = parser.parse_args()

    events = read_log()

    if args.list:
        df1 = pd.DataFrame(events)
        fn = '{}.xlsx'.format(HOSTNAME)
        df1.to_excel(fn, index=False)
        print('输出到文件 {}'.format(fn))
        return

    lag = 20
    events1 = []
    logon_event = {}
    for event in events:
        if re.search('(UMFD|DWM)', event.get('TargetUserName', '')):
            continue
        if int(event.get('LogonType', -1)) in [4, 5]:
            continue
        if (datetime.datetime.now() - event['Time']).total_seconds() > lag:
            continue
        if event['EventID'] == 4624:
            logon_event[event['TargetLogonId']] = event
        events1.append(event)

    if args.notice == 4624:
        for event in events1:
            if event['EventID'] != 4624:
                continue
            notice(event)
            break
    elif args.notice == 4625:
        for event in events1:
            if event['EventID'] != 4625:
                continue
            notice(event)
            break
    elif args.notice == 4634:
        for event in events1:
            if event['EventID'] != 4634:
                continue
            TargetLogonId = event['TargetLogonId']
            # 解锁会产生一条相同TIme和TargetLogonId的4624和4634事件，忽略
            if TargetLogonId in logon_event and (event['Time'] - logon_event[TargetLogonId]['Time']) < 2:
                return
            notice(event)
            break


if __name__ == '__main__':
    main()
