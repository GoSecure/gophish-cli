# Gophish Python CLI

This tool aim to perform huge phishing campaigns by using the very respected gophish toolkit. If you need to run a campaign for more than 10 000 email addresses or need to split a batch of email addresses into smaller groups for any reasons (lower risks with anti-Spam, avoid being banned by IPS, bypass Email service limitations, etc.), that tool could help you!

The tool is based the [api-client-python](https://github.com/gophish/api-client-python) library and require [PrettyTable](https://pypi.python.org/pypi/PrettyTable).


## Installation

You must have a gophish instance already running. Find more about the gophish project [here](https://github.com/gophish/gophish).

To install `gophish-cli`, simply run the command:

```bash
git clone --recursive https://github.com/gosecure/gophish-cli
cd api-client-python
python3 ./setup.py install --user
```

It is currently using a forked version of the [API library](https://github.com/gosecure/api-client-python/) for development purpose.


## Configuration

To begin, you will need the API key found in the [Settings page](https://gophish.gitbooks.io/user-guide/content/documentation/changing_user_settings.html#changing-your-password--updating-settings).

Then run `cp config.default.py config.py` and edit the `config.py` file using your favourite text editor.

### Step 1 - Connection to the gophish instance

```python
API_KEY = ''
API_URL = 'http://127.0.0.1:3333
```


### Step 2 - Define the campaign parameters

As mentionned earlier, `gophish-cli` true power is for campaign spliting. Thus, the objects below must be created using the webUI:

 * Landing Page
 * Email Template
 * Sending Profile

The tool will take care of the email groups and campaigns creation. It will also let you retrieve statistics and credentials from the same batch.

The three parameters below should be configured based on the number of email addresses:

 * GROUP_SIZE: Number of email addresses per group. 
 * START_INTERVAL: Interval before starting the first batch.
 * BATCH_INTERVAL: Interval between each batches.


### Step 3 - Spam!

The most automated way to run the tool is as follow:

```bash
$ python3 ./gophish-cli.py campaign --start --new-groups
[-] Preparing new groups creation.
[-]   Campaign Name: JohnDoe
[-]   File Path: /path/to/test_emails.txt
[-]   Batch size: 30
[-]   Group count: 4
Do you want to continue? [y/N] y
[-] Creating group "JohnDoe - Group 1" with 30 targets. First email is johndoe1@trash-mail.com
[-] Creating group "JohnDoe - Group 2" with 30 targets. First email is johndoe31@trash-mail.com
[-] Creating group "JohnDoe - Group 3" with 30 targets. First email is johndoe61@trash-mail.com
[-] Creating group "JohnDoe - Group 4" with 10 targets. First email is johndoe91@trash-mail.com
[-] Preparing to launch campaigns
[-]   Campaign Name: JohnDoe
[-]   Landing Page: LP - EN - aCampaign - JohnDoe
[-]   Email Template: ET - EN - aCampaign - JohnDoe
[-]   Sending Profile: imgonahackyou.com (provider X)
[-]   URL: https://johndoe.imgonahackyou.com
[-]   Group count: 4
[-]   Launch Date: 2017-02-06 17:54:46.813515-05:00
[-]   Time interval: 1 minute(s)
Do you want to continue? [y/N] y
[-] Launching campaign "JohnDoe - Group 1" at 2017-02-06 17:54:46.813515-05:00
[-] Launching campaign "JohnDoe - Group 2" at 2017-02-06 17:55:46.813515-05:00
[-] Launching campaign "JohnDoe - Group 3" at 2017-02-06 17:56:46.813515-05:00
[-] Launching campaign "JohnDoe - Group 4" at 2017-02-06 17:57:46.813515-05:00
```

## Help
```
$ python3 ./gophish-cli.py campaign -h       
usage: gophish-cli.py campaign [-h] [--start] [--complete] [--delete] [--list]
                               [--results] [--print-creds] [--name STR]
                               [--id UINT] [--prefix STR] [--new-groups]
                               [--delete-groups]

types:
    UINT    Unsigned Integer value.
    STR     String.
    FILE    Path to a file.

optional arguments:
  -h, --help       show this help message and exit

Action:
  --start          Start a campaign.
  --complete       Complete a campaign.
  --delete         Delete a campaign.
  --list, -l       List campaigns.
  --results        Download and save results.
  --print-creds    Print credentials.

Action Parameters:
  --name STR       For --delete only. A campaign name to delete. NOT
                   IMPLEMENTED YET.
  --id UINT        For --delete only. A campaign id to delete. NOT IMPLEMENTED
                   YET
  --prefix STR     A prefix filter. Can be used with --list and --delete. NOT
                   IMPLEMENTED YET.
  --new-groups     Import new groups for the campaign.
  --delete-groups  Delete all groups with the same prefix.

example: 
    --start                           # Start a campaign. All parameters are in the config.py file.
    --start --new-groups              # Upload groups and then start the campaign. See config.py.
    --complete                        # End a campaign. All parameters are in the config.py file.

    --delete                          # Delete all batches based on config.py

    --list                            # List all campaigns of the database

    --results                         # Download and save Phishing results (Timeline + Credentials).
    --print-creds                     # Print the credentials retrieved
```


## Post-campaign useful commands

To get results

```
$ python3 ./gophish-cli.py campaign --results
[-] Exported 2492 timeline entries to /some/path/campaign_results_JohnDoe.csv
[-] Exported 40 credentials to /some/path/campaign_creds_JohnDoe.csv.
```

To print credentials

```
$ python3 ./gophish-cli.py campaign --print-creds
+---------------------+--------------+------------+
| Email               | User         | Pass       |
+---------------------+--------------+------------+
| mdube@gosecure.ca   | mdube        | P@$$w0rd1! |
| somebody@gouv.qc.ca | lddoei       | Winter2017 |
| ...                 | ...          | ...        |
+---------------------+--------------+------------+
```


To get source IP addresses

```
$ python3 ./gophish-cli.py stats --targets-ip

+------------------------+-----------+
| IP Address             | Hit Count |
+------------------------+-----------+
| No IP. Email Sent Only |    1251   |
| 31.10.39.30            |     50    |
| 2.21.14.65             |     2     |
| ...                    |    ...    |
+------------------------+-----------+
```


## Troubleshooting

### Issues with Outlook 365

Outlook 365 limit the number of email sent per connection to 30. `GROUP_SIZE` must be set to 30 when using Outlook 365 as a provider.

### Issues with sendgrid

For unknown reasons, some email addresses are stuck with status "Sending" if too many emails are sent at once. For now, we have had success with `GROUP_SIZE=100` and `BATCH_INTERVAL=5`.


