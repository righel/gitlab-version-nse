local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"
local string = require "string"
local table = require "table"
local json = require "json"

description =
    [[
    Try to guess GitLab version using a dictionary of static assets hashes.
    Works for versions >= 9.x, can return multiple versions for a give instance.
]]
---
-- @usage nmap <target> -p PORT --script gitlab_version.nse [--script-args="showcves"]
---

categories = {"safe", "version"}

author = "Luciano Righetti"
license = "Apache License 2.0"

portrule = shortport.service({"http", "https"})

local cve_meta = {
    __tostring = function(me)
        return ("%s\t%s\t%s"):format(me.id, me.cvss, me.href)
    end
}

local function get_hashes_map()
    local response = http.get_url("https://raw.githubusercontent.com/righel/gitlab-version-nse/main/gitlab_hashes.json", {max_body_size = -1})
    if response.status == 200 then
        _, hashes = json.parse(response.body)
        return hashes
    end

    return nil
end

action = function(host, port)
    local options = {scheme = port.service, max_body_size = -1}

    manifest_url = "/assets/webpack/manifest.json"
    if stdnse.get_script_args("subdir") then
        manifest_url =  stdnse.get_script_args("subdir") .. manifest_url
    end

    local response = http.generic_request(host.targetname or host.ip, port, "GET", manifest_url, options)
    local manifest_hash = string.match(response["rawbody"], '"hash": "([%w]*)"')

    if manifest_hash == nil then
        return "ERROR: GitLab instance not found or running version < 9.x"
    end
    
    local manifest_hashes_map = get_hashes_map()
    local banner = manifest_hashes_map[manifest_hash]

    if banner == nil then
        return "ERROR: GitLab manifest hash not found in map: " .. manifest_hash
    end

    local build = banner["build"]
    local versions = banner["versions"]

    local edition = "*"
    if (build == "gitlab-ce") then
        edition = "community"
    end
    if (build == "gitlab-ee") then
        edition = "enterprise"
    end

    local output = {}

    if manifest_hash ~= nil then
        for _, version in ipairs(versions) do
            local cpe = ("cpe:/a:gitlab:gitlab:%s:*:*:*:%s"):format(version, edition)
            r = {
                version = version,
                edition = edition
            }
            if stdnse.get_script_args("showcves") then
                r["cves"] = get_vulners_results(build, version)
            end

            output[cpe] = r
        end
    end

    return output
end

function get_vulners_results(build, version)
    local api_version = "1.7"
    local option = {
        header = {
            ["User-Agent"] = string.format("Vulners NMAP Plugin %s", api_version),
            ["Accept-Encoding"] = "gzip, deflate"
        },
        any_af = true
    }
    local api_endpoint = "https://vulners.com/api/v3/burp/software/"

    response =
        http.get_url(("%s?software=%s&version=%s&type=%s"):format(api_endpoint, "gitlab", version, "software"), option)
    _, vulns = json.parse(response.body)

    if not vulns or not vulns.data or not vulns.data.search then
        return
    end

    local output = {}
    for _, vuln in ipairs(vulns.data.search) do
        if vuln._source.type == "cve" then
            local v = {
                id = vuln._source.id,
                type = vuln._source.type,
                href = vuln._source.href,
                cvss = vuln._source.cvss.score
            }

            setmetatable(v, cve_meta)
            output[#output + 1] = v
        end
    end

    return output
end
