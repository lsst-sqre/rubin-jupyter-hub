#!/usr/bin/env python3
import json
import rubin_jupyter_utils.hub as rh

q = rh.Reaper(
    name="sciplat-lab",
    owner="lsstsqre",
    debug=True,
    cachefile="/tmp/reposcan.json",
    dry_run=True
)
print("Last scan: {}".format(q.last_scan.strftime('%Y-%m-%d %H:%M:%S')))
q._select_victims()
print(json.dumps(q.reapable, indent=4, sort_keys=True))
