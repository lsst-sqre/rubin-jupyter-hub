import argparse
import json
from rubin_jupyter_utils.config import RubinConfig
from eliot import start_action


def parse_args(
    cfg=RubinConfig(),
    desc="Get list of Lab Images for display or prepulling",
    component="scanner",
):
    """Parse command-line arguments.
    """
    with start_action(action_type="parse_args"):
        parser = argparse.ArgumentParser(description=desc)
        dbg = cfg.debug
        lrh = cfg.lab_repo_host
        lro = cfg.lab_repo_owner
        lrn = cfg.lab_repo_name
        kex = cfg.prepuller_experimentals
        kdl = cfg.prepuller_dailies
        kwk = cfg.prepuller_weeklies
        krl = cfg.prepuller_releases
        ppc = cfg.prepuller_cachefile
        pto = cfg.prepuller_timeout
        ppn = cfg.prepuller_namespace
        lid = cfg.lab_uid
        cmd = cfg.prepuller_command
        component = component.lower()
        allowed_components = ["scanner", "reaper", "prepuller"]
        if component not in allowed_components:
            raise ValueError(
                "Component {} not in {}!".format(component, allowed_components)
            )
        # These are larger for the reaper; there should be a number of not-
        #  displayed images we haven't destroyed yet.
        if component == "reaper":
            kex = cfg.reaper_keep_experimentals
            kdl = cfg.reaper_keep_dailies
            kwk = cfg.reaper_keep_weeklies

        parser.add_argument(
            "-d",
            "--debug",
            action="store_true",
            help="enable debugging [{}]".format(dbg),
            default=dbg,
        )
        parser.add_argument(
            "-f",
            "--cachefile",
            help="Cachefile for results [{}]".format(ppc),
            default=ppc,
        )
        parser.add_argument(
            "-r",
            "--repo",
            "--repository",
            help="Docker repository host [{}]".format(lrh),
            default=lrh,
        )
        parser.add_argument(
            "-o",
            "--owner",
            "--organization",
            "--org",
            help="repository owner [{}]".format(lro),
            default=lro,
        )
        parser.add_argument(
            "--username", help="Docker username", default=cfg.lab_repo_username
        )
        parser.add_argument(
            "--password", help="Docker password", default=cfg.lab_repo_password
        )
        parser.add_argument(
            "-n",
            "--name",
            help="repository name [{}]".format(lrn),
            default=lrn,
        )
        parser.add_argument(
            "-q",
            "--dailies",
            "--daily",
            "--quotidian",
            type=int,
            help="# of daily builds to keep [{}]".format(kdl),
            default=kdl,
        )
        parser.add_argument(
            "-w",
            "--weeklies",
            "--weekly",
            type=int,
            help="# of weekly builds [{}]".format(kwk),
            default=kwk,
        )
        parser.add_argument(
            "-e",
            "--experimentals",
            "--experimental",
            "--exp",
            type=int,
            help=("# of experimental builds to keep [{}]".format(kex)),
            default=kex,
        )
        if component != "reaper":
            parser.add_argument(
                "-b",
                "--releases",
                "--release",
                type=int,
                help=("# of release builds to keep [{}]".format(krl)),
                default=krl,
            )
        parser.add_argument(
            "-p",
            "--port",
            help="Repository port [443 for" + " secure, 80 for insecure]",
            default=None,
        )
        parser.add_argument(
            "-i",
            "--insecure",
            "--no-tls",
            "--no-ssl",
            help="Do not use TLS to connect [False]",
            action="store_true",
            default=False,
        )
        if component != "reaper":
            parser.add_argument(
                "-l",
                "--list",
                "--list-images",
                "--image-list",
                help=(
                    "Use supplied comma-separated list in"
                    + " addition to repo scan"
                ),
                default=None,
            )
            parser.add_argument(
                "-s",
                "--sort",
                "--sort-field",
                "--sort-by",
                help="Field to sort results by [name]",
                default="name",
            )
            parser.add_argument(
                "--recommended",
                help=("Pull image w/tag 'recommended' [True]"),
                type=bool,
                default=True,
            )
        if component == "prepuller":
            parser.add_argument(
                "--no-scan",
                action="store_true",
                help=(
                    "Do not do repo scan (only useful in"
                    + " conjunction with --list)"
                ),
                default=False,
            )
            parser.add_argument(
                "--command",
                help=(
                    "JSON representation of command "
                    + "to run when image is run as "
                    + "prepuller "
                    + "[{}]".format(str(cmd))
                ),
                default=cmd,
            )
            parser.add_argument(
                "-t",
                "--timeout",
                help=(
                    "Seconds allowed for process to "
                    + "complete "
                    + "(-1 for no timeout) [{}]".format(pto)
                ),
                type=int,
                default=pto,
            )
            parser.add_argument(
                "-u",
                "--uid",
                help=("UID to run as [{}]".format(lid)),
                type=int,
                default=lid,
            )
            parser.add_argument(
                "--namespace",
                help="Kubernetes namespace [{}]".format(ppn),
                default=ppn,
            )
        if component == "reaper":
            parser.add_argument(
                "--dry-run",
                action="store_true",
                help="Don't actually delete images",
                default=False,
            )
        results = parser.parse_args()
        results.path = (
            "/v2/repositories/" + results.owner + "/" + results.name + "/tags/"
        )
        if hasattr(results, "list") and results.list:
            results.list = list(set(results.list.split(",")))
        if (
            hasattr(results, "command")
            and results.command
            and type(results.command) is str
        ):
            results.command = json.loads(results.command)
        return results
