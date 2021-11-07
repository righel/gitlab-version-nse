local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"
local string = require "string"
local table = require "table"

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

portrule = shortport.service("https")

action = function(host, port)
    local options = {scheme = "https", max_body_size = -1}
    local response = http.generic_request(host.ip, port, "GET", "/assets/webpack/manifest.json", options)

    local manifest_hash = string.match(response["rawbody"], '"hash": "([%w]*)"')

    if manifest_hash == nil then
        return stdnse.format_output(true, "ERROR: GitLab instance not found or running version < 9.x")
    end

    local versions = {}

    if manifest_hash ~= nil then
        table.insert(versions, stdnse.get_script_args("manifest." .. manifest_hash))
    end

    return stdnse.format_output(true, versions)
end
