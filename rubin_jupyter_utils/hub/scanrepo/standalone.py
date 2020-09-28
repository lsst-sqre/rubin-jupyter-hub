#!/usr/bin/env python3
from .scanrepo import ScanRepo
from .parse_args import parse_args


def standalone():
    """Standalone command for scanning repo.
    """
    args = parse_args()
    scanner = ScanRepo(
        host=args.repo,
        path=args.path,
        owner=args.owner,
        name=args.name,
        dailies=args.dailies,
        weeklies=args.weeklies,
        releases=args.releases,
        experimentals=args.experimentals,
        recommended=args.recommended,
        insecure=args.insecure,
        sort_field=args.sort,
        cachefile=args.cachefile,
        debug=args.debug,
        username=args.username,
        password=args.password,
    )
    scanner.scan()
    scanner.report()


if __name__ == "__main__":
    standalone()
