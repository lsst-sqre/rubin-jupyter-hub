#!/usr/bin/env python3
import rubin_jupyter_utils.hub as rh

q = rh.SingletonScanner(
    name="sciplat-lab",
    owner="lsstsqre",
    debug=True,
    experimentals=2,
    dailies=3,
    weeklies=4,
    releases=3,
    cachefile="/tmp/reposcan.json",
)
q.scan()
q.get_all_tags()
