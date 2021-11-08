# gitlab-version-nse
Nmap script to guess* a GitLab version. 

# Usage
```
https://github.com/righel/gitlab-version-nse
cd gitlab-version-nse 
nmap <target> --script ./gitlab_version.nse [--script-args="showcves"] --script-args-file="/home/user/gitlab-version-nse/gitlab_versions_map.txt"
```
* use `--script-args="showcves"` to get version CVEs via Vulners API.

sample output:
```
$ nmap REDACTED -p 443 --script ./gitlab_version.nse -script-args="showcves" --script-args-file="/home/user/gitlab-version-nse/gitlab_versions_map.txt"
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-07 18:39 CET
Nmap scan report for REDACTED
Host is up (0.013s latency).

PORT    STATE SERVICE
443/tcp open  https
| gitlab_version: 
|   14.0.5
|     CVE-2021-22237            4.0             https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-22237
|     CVE-2021-22238            3.5             https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-22238
|     CVE-2021-22239            4.0             https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-22239
|     CVE-2021-22241            3.5             https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-22241
|     CVE-2021-22242            3.5             https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-22242
|     CVE-2021-22243            4.0             https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-22243
...
Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds
```

## How
Created a dictionary of the webpack static assets manifest hash -> gitlab version. 
This is not 100% accurate as sometimes different minor versions have the same hash, still gives a good estimate.

## TODO
* Improve the dictionary generation scripts.
* Automate the dictionary generation via a github cronned workflow.
* Show CVEs for the detected version.
