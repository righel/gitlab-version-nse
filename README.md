# gitlab-version-nse
Nmap script to guess* a GitLab version. 

# Usage
```bash
https://github.com/righel/gitlab-version-nse
cd gitlab-version-nse 
nmap <target> --script ./gitlab_version.nse --script-args-file="/home/user/gitlab-version-nse/gitlab_versions_map.txt"
```

sample output:
```bash
$ nmap REDACTED -p 443 --script ./gitlab_version.nse --script-args-file="/home/user/gitlab-version-nse/gitlab_versions_map.txt"
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-07 18:39 CET
Nmap scan report for REDACTED
Host is up (0.013s latency).

PORT    STATE SERVICE
443/tcp open  https
| gitlab_version: 
|_  gitlab-ee:13.11.4

Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds
```

## How
Created a dictionary of the webpack static assets manifest hash -> gitlab version. 
This is not 100% accurate as sometimes different minor versions have the same hash, still gives a good estimate.

## TODO
* Improve the dictionary generation scripts.
* Automate the dictionary generation via a github cronned workflow.
* Show CVEs for the detected version.
