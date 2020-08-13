#!/usr/bin/env python3
import rubin_jupyter_utils.config as rc
import rubin_jupyter_utils.hub as rh

rrc = rc.RubinConfig()
args = rh.scanrepo.parse_args(cfg=rrc, component="prepuller")
q = rh.Prepuller(args=args)
q.update_images_from_repo()
