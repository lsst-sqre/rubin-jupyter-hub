#!/usr/bin/env python3
from .reaper import Reaper
from .parse_args import parse_args


def reaperstandalone():
    """Standalone command for scanning repo.
    """
    args = parse_args(desc="Remove obsolete lab images", component="reaper")
    wilford_grimly = Reaper(
        host=args.repo,
        path=args.path,
        owner=args.owner,
        name=args.name,
        keep_dailies=args.dailies,
        keep_weeklies=args.weeklies,
        keep_experimentals=args.experimentals,
        port=args.port,
        insecure=args.insecure,
        cachefile=args.cachefile,
        dry_run=args.dry_run,
        debug=args.debug,
    )
    wilford_grimly.more_cowbell()


if __name__ == "__main__":
    reaperstandalone()
