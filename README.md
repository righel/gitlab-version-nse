# gitlab-version-nse
Nmap script to guess* a GitLab version. 

# Usage
```
git clone https://github.com/righel/gitlab-version-nse
cd gitlab-version-nse 
nmap <target> --script ./gitlab_version.nse [--script-args="showcves"]
```
* use `--script-args="showcves"` to get version CVEs via Vulners API.

sample output:
```
$ nmap REDACTED -p 443 --script ./gitlab_version.nse --script-args="showcves"
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-07 18:39 CET
Nmap scan report for REDACTED
Host is up (0.013s latency).

PORT     STATE SERVICE VERSION
8081/tcp open  http    nginx
| gitlab_version: 
|   cpe:/a:gitlab:gitlab:13.11.2:*:*:*:enterprise: 
|     CVE-2021-22181    4.0     https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-22181
|     CVE-2021-22213    4.3     https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-22213
|     CVE-2021-22214    4.3     https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-22214
...
Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds
```

## How
Created a dictionary of the webpack static assets manifest hash -> gitlab version. 
This is not 100% accurate as sometimes different minor versions have the same hash, still gives a good estimate.
The list of hashes is automagically updated every day via a github action.
