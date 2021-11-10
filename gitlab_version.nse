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
-- @usage nmap <target> -p PORT --script gitlab_version.nse --script-args-file="/full/path/to/gitlab_versions_map.txt"
---

categories = {"safe", "version"}

author = "Luciano Righetti"
license = "Apache License 2.0"

portrule = shortport.service({"http", "https"})

action = function(host, port)
    local options = {scheme = port.service, max_body_size = -1}

    local response = http.generic_request(host.ip, port, "GET", "/assets/webpack/manifest.json", options)

    local manifest_hash = string.match(response["rawbody"], '"hash": "([%w]*)"')

    if manifest_hash == nil then
        return "ERROR: GitLab instance not found or running version < 9.x"
    end

    local banner = stdnse.get_script_args("manifest." .. manifest_hash)
    local build = string.match(banner, "([%w-]*):")
    local versions = string.match(banner, ".*:([%d.,]*)")

    local output = {}

    if manifest_hash ~= nil then
        for version in string.gmatch(versions, "[%d.]+") do
            table.insert(output, version)

            if stdnse.get_script_args("showcves") then
                local cves = get_vulners_results(build, version)
                table.insert(output, cves)
            end
        end
    end

    return stdnse.format_output(true, output)
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
            table.insert(
                output,
                ("%s\t\t%s\t\t%s"):format(vuln._source.title, vuln._source.cvss.score, vuln._source.href)
            )
        end
    end

    return output
end
