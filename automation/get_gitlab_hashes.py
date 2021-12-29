#!/usr/bin/env python3

import json
import subprocess
import sys

global builds
global ignore_list
builds = ["gitlab-ce", "gitlab-ee"]
ignore_list = ["rc", "nightly", "latest"]


def main(argv):
    if(len(argv) == 0):
        exit("hashes_dict_file file missing")

    hashes_dict_file = argv[0]
    hashes = process_missing_tags(hashes_dict_file)

    write_hashes_dict(hashes, hashes_dict_file)


def get_manifest_hash(branch, version):
    try:
        subprocess.check_output("docker rm tmp_gitlab", shell=True)
    except:
        pass

    image = "gitlab/%s:%s" % (branch, version)
    print("Processing image: %s" % image)

    # pull tag
    subprocess.check_output("docker create --name='tmp_gitlab' %s" % image, shell=True)
    subprocess.check_output("docker export tmp_gitlab -o tmp_gitlab.tar", shell=True)
    subprocess.check_output("mkdir -p assets/", shell=True)
    subprocess.check_output("tar -xf tmp_gitlab.tar opt/gitlab/embedded/service/gitlab-rails/public/assets/ --strip-components=6", shell=True)

    # get version hash
    with open("./assets/webpack/manifest.json", "r") as file:
        raw_manifest = file.read()
    manifest = json.loads(raw_manifest)

    # cleanup
    try:
        subprocess.check_output("docker rmi %s -f" % image, shell=True)
        subprocess.check_output("docker rm tmp_gitlab", shell=True)
        subprocess.check_output("rm tmp_gitlab.tar", shell=True)
        subprocess.check_output("rm -rf assets/", shell=True)
    except:
        pass

    return str(manifest["hash"])


def load_hashes_dict(hashes_dict_file):
    with open(hashes_dict_file, "r") as file:
        raw_hashes = file.read()
    hashes = json.loads(raw_hashes)

    return hashes


def write_hashes_dict(hashes, path):
    with open(path, "w") as output:
        json.dump(hashes, output, indent=4, sort_keys=True)


def load_tags(build):
    with open("%s_tags.json" % build, "r") as file:
        raw_tags = file.read()
    tags = json.loads(raw_tags)

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


def process_missing_tags(hashes_dict_file):
    hashes = load_hashes_dict(hashes_dict_file)
    processed = load_processed_tags()

    # process missing tags
    for build in builds:
        tags = load_tags(build)
        for tag in tags:
            version = str(tag["name"])
            if(
                not any(ignore in version for ignore in ignore_list)
                and
                not any(processed in version for processed in processed[build])
            ):
                clean_version = version[:version.index('-')]
                hash = get_manifest_hash(build, version)

                if hashes.get(hash):
                    hashes[hash]["versions"].append(clean_version)
                else:
                    hashes[hash] = {"build": build, "versions": set([clean_version])}

                processed[build].append(version)

    write_processed_tags(processed)

    return hashes


if __name__ == "__main__":
    main(sys.argv[1:])
