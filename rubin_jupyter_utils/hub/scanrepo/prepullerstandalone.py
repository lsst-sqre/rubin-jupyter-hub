#!/usr/bin/env python3
from rubin_jupyter_utils.config import RubinConfig
from .parse_args import parse_args
from .prepuller import Prepuller


def prepullerstandalone():
    """Run prepuller process as a standalone command.
    """
    lc = RubinConfig()
    args = parse_args(
        cfg=lc, desc="Set up DaemonSets to prepull.", component="prepuller"
    )
    prepuller = Prepuller(args=args)
    prepuller.update_images_from_repo()
    prepuller.build_nodelist()
    prepuller.build_pod_specs()
    prepuller.clean_completed_pods()
    prepuller.run_pods()


if __name__ == "__main__":
    prepullerstandalone()
