#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Gophish command line interface to quickly setup a campaign.

@author: Martin Dubé
@organization: Gosecure inc.
@license: MIT License
@contact: mdube@gosecure.ca

Copyright (c) 2017, Gosecure
All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

						   
import sys
import csv
import json
import argparse
from datetime import datetime,timedelta
from urllib.request import urlopen

from gophish import Gophish
from gophish.models import *
from prettytable import PrettyTable

import config

DEBUG = False

if hasattr(config,'GophishClient'):
    api = Gophish(config.API_KEY,host=config.API_URL,client=config.GophishClient)
else:
    api = Gophish(config.API_KEY,host=config.API_URL)

class EventsFilter():
    def __init__(self, email=None, ip=None, group=None):
        self.email = email
        self.ip = ip
        self.group = group

def print_info(msg):
    print('[-] ' + msg)

def print_warning(msg):
    print('[-WARNING-] ' +msg)

def print_title(msg):
    print('')
    print('[] ' + msg)

def print_debug(msg):
    if DEBUG:
        print('[+] ' + msg)

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

# Currently using ip-api.com. ISSUE: Ban IP if doing more than 150 requests per minutes.
# To unban: http://ip-api.com/docs/unban
#
# Output format
#{
#    "as": "ASxxx Rogers Cable Communications Inc.",
#    "city": "Toronto",
#    "country": "Canada",
#    "countryCode": "CA",
#    "isp": "Rogers Cable",
#    "lat": 43.xxx5,
#    "lon": -79.xxx4,
#    "org": "Rogers Cable",
#    "query": "1.2.3.4",
#    "region": "ON",
#    "regionName": "Ontario",
#    "status": "success",
#    "timezone": "America/Toronto",
#    "zip": "G1Q"
#}
def get_geoip(ip_addr):
    url = 'http://ip-api.com/json/%s' % ip_addr
    out = urlopen(url).read()
    js_out = json.loads(out)
    return js_out

def timeline_to_csv(filePath, timeline):
    fields = ['email', 'time', 'message']

    # Setup csv writer
    csvfile = open(filePath, 'w', newline='')
    writer = csv.DictWriter(csvfile, fieldnames=fields)
    writer.writeheader()

    # Create dict with only desired fields
    # Write a row with this dict
    for entry in timeline:
        row = {}
        row['email'] = entry.email
        row['time'] = entry.time
        row['message'] = entry.message
        writer.writerow(row)
        row = None

    csvfile.flush()

def creds_to_csv(filePath, creds_list):
    fields = ['email', 'user', 'pass']

    # Setup csv writer
    csvfile = open(filePath, 'w', newline='')
    writer = csv.DictWriter(csvfile, fieldnames=fields)
    writer.writeheader()

    # Create dict with only desired fields
    # Write a row with this dict
    for creds in creds_list:
        writer.writerow(creds)
        creds = None

    csvfile.flush()

def create_group(i, batch_ct, campaign_name, targets):
    batch_num = (int)(i/batch_ct)
    batch_name = config.CAMPAIGN_NAME_TPL % (campaign_name,batch_num)
    print_info('Creating group "%s" with %i targets. First email is %s' 
          % (batch_name,len(targets),targets[0].email))
    group = Group(name=batch_name, targets=targets)
    group = api.groups.post(group)

def create_groups():
    group_to_create = []
    i = 0
    targets = []
    with open(config.EMAILS_PATH, 'r') as fh:
        for line in fh:
            # Create file when enough email are read
            if (i % config.GROUP_SIZE) == 0 and i != 0:
                group_to_create.append([i, config.GROUP_SIZE, config.CAMPAIGN_NAME, targets])
                targets = []
            targets.append(User(email=str(line.strip())))
            i=i+1
    
    if len(targets) > 0:
        group_to_create.append([i+config.GROUP_SIZE, config.GROUP_SIZE, config.CAMPAIGN_NAME, targets])

    print_info('Preparing new groups creation.')
    print_info('  Campaign Name: %s' % config.CAMPAIGN_NAME)
    print_info('  File Path: %s' % config.EMAILS_PATH)
    print_info('  Batch size: %i' % config.GROUP_SIZE)
    print_info('  Group count: %i' % len(group_to_create))
    ret = query_yes_no('Do you want to continue?',default='no')

    if not ret:
        return

    for row in group_to_create:
        create_group(row[0], row[1], row[2], row[3])

def delete_groups():
    groups = get_groups(config.CAMPAIGN_PREFIX)

    print_info('Preparing to delete groups')
    print_info('  Campaign Name: %s' % config.CAMPAIGN_NAME)
    print_info('  Group count: %i' % len(groups))
    ret = query_yes_no('Do you want to continue?',default='no')
    if not ret:
        return

    for g in groups:
        print_info('Deleting group %i' % g.id)
        api.groups.delete(group_id=g.id)
        
def print_groups():
    title = ['ID', 'Name', 'First User', 'Count']
    item_list = api.groups.get()
    x = PrettyTable(title)
    x.align['Name'] = 'l' 
    x.align['First User'] = 'l' 
    x.padding_width = 1 
    x.max_width = 40
    for row in item_list:
        x.add_row([row.id,row.name,row.targets[0].email,len(row.targets)])
    print(x.get_string())

def get_groups(prefix=None):
    groups_out = []
    groups = api.groups.get()
    for c in groups:
        if c.name.startswith(prefix):
            groups_out.append(c)
    return groups_out

def create_campaign(campaign_id, group_name, launch_date):
    campaign_name = config.CAMPAIGN_NAME_TPL % (config.CAMPAIGN_NAME, campaign_id)
    groups = [Group(name=group_name)]
    page = Page(name=config.LP_NAME)
    template = Template(name=config.ET_NAME)
    smtp = SMTP(name=config.SP_NAME)
    campaign = Campaign(
                name=campaign_name, groups=groups, page=page,
                template=template, smtp=smtp, url=config.CAMPAIGN_URL, launch_date=launch_date)
    
    print_info('Launching campaign "%s" at %s' % (campaign_name,launch_date))
    campaign = api.campaigns.post(campaign)

def create_campaigns():
    group_ct = len(get_groups(config.CAMPAIGN_PREFIX))
    launch_date = datetime.now(tzlocal()) + timedelta(minutes=config.START_INTERVAL)	
    interval = config.BATCH_INTERVAL

    print_info('Preparing to launch campaigns')
    print_info('  Campaign Name: %s' % config.CAMPAIGN_NAME)
    print_info('  Landing Page: %s' % config.LP_NAME)
    print_info('  Email Template: %s' % config.ET_NAME)
    print_info('  Sending Profile: %s' % config.SP_NAME)
    print_info('  URL: %s' % config.CAMPAIGN_URL)
    print_info('  Group count: %i' % group_ct)
    print_info('  Launch Date: %s' % launch_date)
    print_info('  Time interval: %i minute(s)' % interval)
    ret = query_yes_no('Do you want to continue?',default='no')
    if not ret:
        return

    for i in range(1, group_ct+1):
        group_name = config.CAMPAIGN_NAME_TPL % (config.CAMPAIGN_NAME, i)
        create_campaign(i, group_name, launch_date)
        launch_date += timedelta(minutes=interval)

def complete_campaign(campaign_id):
    print_info('Completing campaign %i' % campaign_id)
    api.campaigns.complete(campaign_id)

def complete_campaigns():
    campaigns = get_campaigns(config.CAMPAIGN_PREFIX)

    print_info('Preparing to complete campaigns')
    print_info('  Campaign Name: %s' % config.CAMPAIGN_NAME)
    print_info('  Campaign Count: %i' % len(campaigns))
    ret = query_yes_no('Do you want to continue?',default='no')
    if not ret:
        return

    for c in campaigns:
        complete_campaign(c.id)

def print_campaigns():
    title = ['ID', 'Name', 'Status', 'Timeline Entries', 'Creds']
    item_list = api.campaigns.get()
    x = PrettyTable(title)
    x.align['Name'] = 'l' 
    x.padding_width = 1 
    x.max_width = 40
    for row in item_list:
        creds_ct = sum([1 for entry in row.timeline if entry.message == 'Submitted Data'])
        x.add_row([row.id,row.name,row.status,len(row.timeline),creds_ct])
    print(x.get_string())

def delete_campaigns():
    campaigns = get_campaigns(config.CAMPAIGN_PREFIX)

    print_info('Preparing to delete campaigns')
    print_info('  Campaign Name: %s' % config.CAMPAIGN_NAME)
    print_info('  Group count: %i' % len(campaigns))
    ret = query_yes_no('Do you want to continue?',default='no')
    if not ret:
        return

    for c in campaigns:
        print_info('Deleting campaign %i' % c.id)
        api.campaigns.delete(campaign_id=c.id)

def get_campaigns(prefix=None):
    campaigns_out = []
    campaigns = api.campaigns.get()
    for c in campaigns:
        if c.name.startswith(prefix):
            campaigns_out.append(c)
    return campaigns_out

# Timeline entry format:
#{
#    'payload': {
#        '__original_url': ['https://someurl.com/'],
#        'btnSubmit': ['Log In'],
#        'hidLang': ['E'],
#        'rid': ['ea6612b9d939ffa1aaaaacc0a7bb4991b38aa3b60db2a541cab7d32a4f600b19'],
#        'selLanguage': ['E'],
#        'selRegion': ['2'],
#        'txtPassword': ['somepass'],
#        'txtUsername': ['someuser']
#    },
#    'browser': {
#        'address': '1.2.3.4',
#        'user-agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36'
#    }
#}
def filter_timeline(timeline, events_filter):
    out = []
    for entry in timeline:
        if events_filter.email and entry.email == events_filter.email:
            out.append(entry)
        # TODO: Support other type of filtering.
    return out

def filter_results(results, events_filter):
    out = []
    for entry in results:
        if events_filter.email and entry.email == events_filter.email:
            out.append(entry)
        # TODO: Support other type of filtering.
    return out

def get_timelines(events_filter=None):
    timeline = []
    campaigns = get_campaigns(config.CAMPAIGN_PREFIX)
    print_debug('Getting %i campaign timelines for %s' % (len(campaigns),config.CAMPAIGN_NAME))
    for c in campaigns:
        timeline += c.timeline
    if events_filter is not None:
        timeline = filter_timeline(timeline, events_filter)
    return timeline

def get_results(events_filter=None):
    results = []
    campaigns = get_campaigns(config.CAMPAIGN_PREFIX)
    print_debug('Getting %i campaign results for %s' % (len(campaigns),config.CAMPAIGN_NAME))
    for c in campaigns:
        results += c.results
    if events_filter is not None:
        results = filter_results(results, events_filter)
    return results

def print_timeline(events_filter=None):
    timeline = get_timelines(events_filter)
    title = ['Email', 'Time', 'Message', 'Source IP']
    x = PrettyTable(title)
    x.padding_width = 1 
    x.max_width = 40
    x.align['Message'] = 'l' 
    for entry in timeline:
        if entry.message in ['Clicked Link', 'Submitted Data']:
            source_ip = entry.details['browser']['address']
        else:
            source_ip = None
        x.add_row([entry.email, entry.time, entry.message, source_ip])
    print(x.get_string(sortby='Time'))

def get_creds_from_timeline(timeline, userField=config.LP_USER_FIELD, 
                            passField=config.LP_PWD_FIELD):
    creds_list = []
    for entry in timeline:
        if entry.message == 'Submitted Data' \
            and userField in entry.details['payload'] \
            and passField in entry.details['payload']:
           creds = {}
           creds['email'] = entry.email
           creds['user'] = entry.details['payload'][userField][0]
           creds['pass'] = entry.details['payload'][passField][0]
           creds_list.append(creds)
        elif entry.message == 'Submitted Data':
            print_warning('Invalid submitted data found. Check LP_USER_FIELD and LP_PWD_FIELD in config.py')
    return creds_list

def save_campaigns():
    timeline = get_timelines()
    timeline_to_csv(config.RESULTS_PATH, timeline)
    print_info('Exported %i timeline entries to %s' 
            % (len(timeline),config.RESULTS_PATH))

    creds = get_creds_from_timeline(timeline)
    creds_to_csv(config.CREDS_PATH, creds)
    print_info('Exported %i credentials to %s.' 
            % (len(creds), config.CREDS_PATH))

def print_creds(events_filter=None):
    title = ['Email', 'User', 'Pass']
    creds = get_creds_from_timeline(get_timelines(events_filter))
    x = PrettyTable(title)
    x.align['Email'] = 'l' 
    x.align['User'] = 'l' 
    x.align['Pass'] = 'l' 
    x.padding_width = 1 
    x.max_width = 40
    for row in creds:
        x.add_row([row['email'], row['user'], row['pass']])
    print(x.get_string())

def get_ips_from_results(results):
    ips_list = {}
    for r in results:
        if r.ip in ips_list.keys():
            ips_list[r.ip]+=1
        else:
            ips_list[r.ip]=1
    return ips_list

def print_targets_ip(events_filter=None, show_geoip=False):
    if show_geoip:
        title = ['IP Address', 'Hit Count', 'City', 'Region', 'Timezone']
    else:
        title = ['IP Address', 'Hit Count']

    ips = get_ips_from_results(get_results(events_filter))
    x = PrettyTable(title)
    x.align['IP Address'] = 'l' 
    x.padding_width = 1 
    x.max_width = 40
    for ip,count in ips.items():
        if ip == '':
            ip = 'No IP. Email Sent Only'
        elif show_geoip:
            js_out = get_geoip(ip)
            x.add_row([ip,count,js_out['city'],js_out['regionName'],\
                        js_out['timezone']])
        else:
            x.add_row([ip,count])
    print(x.get_string(sortby='Hit Count',reversesort=True))

def print_email_stats(email, show_geoip=False):
    ef = EventsFilter(email=email)

    # Print all user timeline
    print_title('All user timeline.')
    print_timeline(ef)

    # Print IP addresses used
    print_title('IP addresses used by this user.')
    print_targets_ip(ef,show_geoip=show_geoip)

    # Print submitted credentials
    print_title('Credentials sent by this user.')
    print_creds(ef)


# Get args
usage = 'usage: %prog action [options]'
description = 'Gophish cli. Use this tool to quickly setup a phishing campaign using your gophish infrastructure.'
parser = argparse.ArgumentParser(description=description)
parser.add_argument('-v','--version', action='version', version='%(prog)s 0.01 (2017-02-06)')
parser.add_argument('-c', '--config', action='store', dest='config', default=None, \
                    help='Alternative config file. Default is config.py (Not implemented yet)')
parser.add_argument('-d', '--debug', action='store_true', dest='debug', default=False, \
                    help='Run the tool in debug mode')

# Groups
subparsers = parser.add_subparsers(dest='action')
p_group_desc = '''\
types:
    UINT    Unsigned Integer value.
    STR     String.
    FILE    Path to a file.
'''
p_group_epilog = '''\
example: 
    --add --name Group_Name --targets-csv '/path/to/csv'    # Create a group and import a CSV file containing targets (users).

    --delete                                                # Delete all groups based on config.py.
    --delete --id 1                                         # Delete group id 1.
    --delete --name JohnDoe                                 # Delete group name "JohnDoe".
    --delete --prefix 'meh_'                                # Delete all groups that starts with 'meh_'.

    --list                                                  # List all groups of the database
    --list --prefix 'meh_'                                  # List groups that starts with 'meh_'
'''
p_group = subparsers.add_parser('group', description=p_group_desc, epilog=p_group_epilog, 
                              formatter_class=argparse.RawDescriptionHelpFormatter, 
                              help='Manage groups.')
p_group_action = p_group.add_argument_group("Action")
p_group_action.add_argument('--add', action='store_true', dest='add', \
                     help='Add a group.')
p_group_action.add_argument('--delete', action='store_true', dest='delete', \
                     help='Delete a group.')
p_group_action.add_argument('--list', '-l', action='store_true', dest='list', \
                     help='List groups.')

p_group_param = p_group.add_argument_group("Action Parameters")
p_group_param.add_argument('--name', action='store', dest='name', default=None, \
                          type=str, metavar='STR', \
                          help='For --add and --delete only. A group name. Mandatory for --add.')
p_group_param.add_argument('--targets-csv', action='store', dest='targets_csv', default=None, \
                          type=str, metavar='FILE', \
                          help='A CSV file with a list of users. Mandatory for --add.')
p_group_param.add_argument('--id', action='store', dest='id', default=None, \
                          type=int, metavar='UINT', \
                          help='For --delete only. A group id to delete. NOT IMPLEMENTED YET.')
p_group_param.add_argument('--prefix', action='store', dest='prefix', default=None, \
                          type=str, metavar='STR', \
                          help='A prefix filter. Can be used with --list and --delete. NOT IMPLEMENTED YET.')

# Campaign
p_campaign_desc = '''\
types:
    UINT    Unsigned Integer value.
    STR     String.
    FILE    Path to a file.
'''
p_campaign_epilog = '''\
example: 
    --start                           # Start a campaign. All parameters are in the config.py file.
    --start --new-groups              # Upload groups and then start the campaign. See config.py.
    --complete                        # End a campaign. All parameters are in the config.py file.

    --delete                          # Delete all batches based on config.py
    --delete --delete-groups          # Delete all campaigns and groups based on config.py
    --delete --id 1                   # Delete campaign id 1.
    --delete --name JohnDoe           # Delete campaign name "JohnDoe".
    --delete --prefix 'meh_'          # Delete all campaigns that starts with 'meh_'.

    --list                            # List all campaigns of the database
    --list --prefix 'meh_'            # List campaigns that starts with 'meh_'

    --results                         # Download and save Phishing results (Timeline + Credentials).
    --print-creds                     # Print the credentials retrieved
'''
p_campaign = subparsers.add_parser('campaign', description=p_campaign_desc, epilog=p_campaign_epilog, 
                              formatter_class=argparse.RawDescriptionHelpFormatter, 
                              help='Manage campaigns.')
p_campaign_action = p_campaign.add_argument_group("Action")
p_campaign_action.add_argument('--start', action='store_true', dest='start', \
                     help='Start a campaign.')
p_campaign_action.add_argument('--complete', action='store_true', dest='complete', \
                     help='Complete a campaign.')
p_campaign_action.add_argument('--delete', action='store_true', dest='delete', \
                     help='Delete a campaign.')
p_campaign_action.add_argument('--list', '-l', action='store_true', dest='list', \
                     help='List campaigns.')
p_campaign_action.add_argument('--results', action='store_true', dest='results', \
                     help='Download and save results.')
p_campaign_action.add_argument('--print-creds', action='store_true', dest='print_creds', \
                     help='Print credentials.')

p_campaign_param = p_campaign.add_argument_group("Action Parameters")
p_campaign_param.add_argument('--name', action='store', dest='name', default=None, \
                          type=str, metavar='STR', \
                          help='For --delete only. A campaign name to delete. NOT IMPLEMENTED YET.')
p_campaign_param.add_argument('--id', action='store', dest='id', default=None, \
                          type=int, metavar='UINT', \
                          help='For --delete only. A campaign id to delete. NOT IMPLEMENTED YET')
p_campaign_param.add_argument('--prefix', action='store', dest='prefix', default=None, \
                          type=str, metavar='STR', \
                          help='A prefix filter. Can be used with --list and --delete. NOT IMPLEMENTED YET.')
p_campaign_param.add_argument('--new-groups', action='store_true', dest='new_groups', 
                          help='Import new groups for the campaign.')
p_campaign_param.add_argument('--delete-groups', action='store_true', dest='delete_groups', 
                          help='Delete all groups with the same prefix.')

# Stats
p_stats_desc = '''\
types:
    UINT    Unsigned Integer value.
    STR     String.
    FILE    Path to a file.
'''
p_stats_epilog = '''\
example: 
    --targets-ip                      # Dump the list of IP addresses so you can do geolocalisation stats.
    --targets-ip --geoip              # Dump the list of IP addresses with geolocation information for each item.

    --email someone@example.org             # Print statistics of this user.
    --email someone@example.org --geoip     # Print statistics + geolocation info of this user.
'''
p_stats = subparsers.add_parser('stats', description=p_stats_desc, epilog=p_stats_epilog, 
                              formatter_class=argparse.RawDescriptionHelpFormatter, 
                              help='Manage statss.')
p_stats_action = p_stats.add_argument_group("Action")
p_stats_action.add_argument('--targets-ip', action='store_true', dest='targets_ip', \
                     help='Get a list of targets IP addresses.')
p_stats_action.add_argument('--email', action='store', dest='email', \
                     help='Get statistics of a single email address')

p_stats_param = p_stats.add_argument_group("Action Parameters")
p_stats_param.add_argument('--geoip', action='store_true', dest='geoip', default=None, \
                          help='Show geolocation information.')

args = parser.parse_args()

DEBUG = args.debug

print_debug('Arguments: ' + str(args))

if args.action == 'group':
    if args.add:
        create_groups()
    elif args.delete:
        delete_groups()
    elif args.list:
        print_groups()
    else:
        parser.print_help()
elif args.action == 'campaign':
    if args.start:
        if args.new_groups:
            create_groups()
        create_campaigns()
    elif args.complete:
        complete_campaigns()
    elif args.delete:
        delete_campaigns()
        if args.delete_groups:
            delete_groups()
    elif args.list:
        print_campaigns()
    elif args.results:
        save_campaigns()
    elif args.print_creds:
        print_creds()
    else:
        parser.print_help()
elif args.action == 'stats':
    if args.targets_ip:
        print_targets_ip(show_geoip=args.geoip)
    elif args.email:
        print_email_stats(args.email, show_geoip=args.geoip)
    else:
        parser.print_help()
else:
    parser.print_help()

