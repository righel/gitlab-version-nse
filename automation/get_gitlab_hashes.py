#!/usr/bin/env python3

import json
import subprocess
import sys
import requests
import time

global builds
global ignore_list
builds = ["gitlab-ce", "gitlab-ee"]
ignore_list = ["rc", "nightly", "latest"]

def main(argv):
    if(len(argv) == 0):
        exit("hashes_dict_file file missing")
    hashes_dict_file = argv[0]

    fetch_all_tags = False
    if (len(argv) > 1):
        fetch_all_tags = argv[1] == "--fetch-all-tags"

    hashes = process_missing_tags(hashes_dict_file, fetch_all_tags)
    write_hashes_dict(hashes, hashes_dict_file)


def get_manifest_hashes(branch, version):
    try:
        subprocess.check_output("docker rm tmp_gitlab", shell=True)
    except:
        pass

    image = "gitlab/%s:%s" % (branch, version)
    print("Processing image: %s" % image)

    # pull tag
    subprocess.check_output("docker create --name='tmp_gitlab' %s" % image, shell=True)
    subprocess.check_output("docker export tmp_gitlab -o tmp_gitlab.tar", shell=True)

    # get version webpack assets hash
    try:
        subprocess.check_output("tar -xf tmp_gitlab.tar opt/gitlab/embedded/service/gitlab-rails/public/assets/webpack/manifest.json --strip-components=8", shell=True)
        with open("manifest.json", "r") as file:
            raw_manifest = file.read()
        manifest = json.loads(raw_manifest)
        webpack_hash = str(manifest["hash"])
        subprocess.check_output("rm manifest.json", shell=True)
    except:
        webpack_hash = None
        print("Failed to get webpack hash for %s" % image)

    try:        
        subprocess.check_output("tar -xf tmp_gitlab.tar opt/gitlab/version-manifest.json --strip-components=2", shell=True)
        # get version commit hash
        with open("version-manifest.json", "r") as file:
            raw_version_manifest = file.read()
        version_manifest = json.loads(raw_version_manifest)
        commit_hash = str(version_manifest["software"]["gitlab-rails"]["locked_version"])
        subprocess.check_output("rm version-manifest.json", shell=True)
    except:
        print("Failed to get commit hash for %s" % image)
        commit_hash = None


    # cleanup
    try:
        subprocess.check_output("rm tmp_gitlab.tar", shell=True)
        subprocess.check_output("docker system prune --all --force", shell=True)
        subprocess.check_output("docker rmi %s -f" % image, shell=True)
        subprocess.check_output("docker rm tmp_gitlab", shell=True)
    except:
        pass

    return {
        "webpack_hash": webpack_hash,
        "commit_hash": commit_hash
    }


def load_hashes_dict(hashes_dict_file):
    with open(hashes_dict_file, "r") as file:
        raw_hashes = file.read()
    hashes = json.loads(raw_hashes)

    return hashes


def write_hashes_dict(hashes, path):
    with open(path, "w") as output:
        json.dump(hashes, output, indent=4, sort_keys=True)


def load_tags(build, fetch_all_tags=False):
    # get tags from docker hub
    tags_endpoint = "https://registry.hub.docker.com/v2/repositories/gitlab/%s/tags?page_size=100" % build

    tags = []

    while True:
        response = requests.get(tags_endpoint)
        if response.status_code == 200:
            print("Fetching tags page %s" % tags_endpoint)
            tags.extend(response.json()["results"])

            if response.json()["next"] and fetch_all_tags:
                tags_endpoint = response.json()["next"]
                time.sleep(1)
            else:
                break
        else:
            print(response.json())
            exit("Failed to fetch tags for %s" % build)

    return tags


def load_processed_tags():
    with open("tags_processed.json", "r") as file:
        raw_processed_tags = file.read()
    processed_tags = json.loads(raw_processed_tags)

    return processed_tags


def write_processed_tags(processed):
    for build in builds:
        processed[build] = sorted(processed[build])

    with open("tags_processed.json", "w") as output:
        json.dump(processed, output, indent=4, sort_keys=True)


def process_missing_tags(hashes_dict_file, fetch_all_tags=False):
    hashes = load_hashes_dict(hashes_dict_file)
    processed = load_processed_tags()

    # process missing tags
    for build in builds:
        tags = load_tags(build, fetch_all_tags)
        for tag in tags:
            version = str(tag["name"])
            if(
                not any(ignore in version for ignore in ignore_list)
                and
                not any(processed in version for processed in processed[build])
            ):
                clean_version = version[:version.index('-')]
                hash = get_manifest_hashes(build, version)

                if hash['webpack_hash'] is not None:
                    if hashes.get(hash['webpack_hash']):
                        hashes[hash['webpack_hash']]["versions"].append(clean_version)
                        hashes[hash['webpack_hash']]["versions"] = list(set(hashes[hash['webpack_hash']]["versions"]))
                    else:
                        hashes[hash['webpack_hash']] = {"build": build, "versions": [clean_version]}

                if hash['commit_hash'] is not None:
                    if hashes.get(hash['commit_hash']):
                        hashes[hash['commit_hash']]["versions"].append(clean_version)
                        hashes[hash['commit_hash']]["versions"] = list(set(hashes[hash['commit_hash']]["versions"]))
                    else:
                        hashes[hash['commit_hash']] = {"build": build, "versions": [clean_version]}

                processed[build].append(version)

            # do partial writes to avoid losing progress
            write_processed_tags(processed)
            write_hashes_dict(hashes, hashes_dict_file)

    return hashes


if __name__ == "__main__":
    main(sys.argv[1:])
