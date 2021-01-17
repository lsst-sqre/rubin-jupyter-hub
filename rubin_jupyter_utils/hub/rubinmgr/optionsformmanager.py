"""Class to manage an Rubin-specific options form.
"""
import datetime
import jinja2
import json
from collections import OrderedDict
from eliot import start_action
from time import sleep
from .. import SingletonScanner as SScan
from .. import LoggableChild

MAX_CACHE_AGE = 1200  # get a new tag list if it's more than 20 minutes old


class RubinOptionsFormManager(LoggableChild):
    """Class to create and read a spawner form.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sizemap = {}
        self._scanner = None
        self.options_form_data = None

    def get_options_form(self):
        """Create an Rubin Options Form from parent's config object.
        """
        with start_action(action_type="get_options_form"):
            # Make options form by scanning container repository, then cache.
            # For a single spawning session, you always get the same form.
            #
            # If that's not OK (long-lived tokens, for example) then in
            #  your authenticator's refresh_user(), clear options_form_data.
            uname = self.parent.user.escaped_name
            self.log.debug("Creating options form for '{}'".format(uname))
            cfg = self.parent.config
            scanner = SScan(
                host=cfg.lab_repo_host,
                owner=cfg.lab_repo_owner,
                name=cfg.lab_repo_name,
                experimentals=cfg.prepuller_experimentals,
                dailies=cfg.prepuller_dailies,
                weeklies=cfg.prepuller_weeklies,
                releases=cfg.prepuller_releases,
                cachefile=cfg.prepuller_cachefile,
                max_cache_age=MAX_CACHE_AGE,
                debug=cfg.debug,
            )
            # Scanner does a scan_if_needed, so either we have fresh data
            #  now, or we will in a little while, or something is broken.
            self._scanner = scanner
            now = datetime.datetime.utcnow()
            delta = datetime.timedelta(MAX_CACHE_AGE)
            if (scanner.last_scan + delta) < now:
                self.log.info("Tag data has expired.")
            else:
                if self.options_form_data:
                    self.log.debug("Returning cached options form.")
                    return self.options_form_data
            self.log.debug("Regenerating form_data for '{}'.".format(uname))
            self.log.debug("Calling _wait_for_scan() for '{}'.".format(uname))
            self._wait_for_scan()
            self.log.debug(
                "Back from _wait_for_scan() for '{}'.".format(uname)
            )
            lnames, ldescs = scanner.extract_image_info()
            desclist = []
            # Setting this up to pass into the Jinja template more easily
            for idx, img in enumerate(lnames):
                desclist.append({"name": img, "desc": ldescs[idx]})
            colon = lnames[0].find(":")
            custtag = lnames[0][:colon] + ":__custom"
            display_tags = scanner.get_display_tags()
            now = datetime.datetime.now()
            nowstr = now.ctime()
            if not now.tzinfo:
                # If we don't have tzinfo, assume it's in UTC
                nowstr += " UTC"
            self.log.debug(
                "About to call _make_sizemap() for '{}'.".format(uname)
            )
            self._make_sizemap()
            self.log.debug("Back from _make_sizemap() for '{}'.".format(uname))
            # in order to get the right default size index, we need to poke the
            #  quota manager, because different users may get different sizes
            #  by default
            cfg = self.parent.config
            qm = self.parent.quota_mgr
            qm.define_resource_quota_spec()
            defaultsize = (
                qm.custom_resources.get("size_index") or cfg.size_index
            )
            template_file = self.parent.config.form_template
            template_loader = jinja2.FileSystemLoader(searchpath="/")
            template_environment = jinja2.Environment(loader=template_loader)
            template = template_environment.get_template(template_file)
            optform = template.render(
                defaultsize=defaultsize,
                desclist=desclist,
                all_tags=display_tags,
                custtag=custtag,
                sizelist=list(self.sizemap.values()),
                nowstr=nowstr,
            )
            self.options_form_data = optform
            self.log.debug(
                "Generated options_form_data for '{}'.".format(uname)
            )
            return optform

    def resolve_tag(self, tag):
        """Delegate to scanner to resolve convenience tags.
        """
        with start_action(action_type="resolve_tag"):
            self.log.debug("Resolving tag for '{}'.".format(tag))
            rtag = self._scanner.resolve_tag(tag)
            self.log.debug("Resolved tag for '{}'->'{}'.".format(tag, rtag))
            return rtag

    def _wait_for_scan(self):
        with start_action(action_type="_wait_for_scan"):
            uname = self.parent.user.escaped_name
            self.log.debug("Entering _wait_for_scan() for '{}'.".format(uname))
            scanner = self._scanner
            cfg = self.parent.config
            delay_interval = cfg.initial_scan_interval
            max_delay_interval = cfg.max_scan_interval
            max_delay = cfg.max_scan_delay
            delay = 0
            now = datetime.datetime.utcnow()
            delta = datetime.timedelta(seconds=max_delay_interval)
            while (scanner.last_scan + delta) < now:
                if not scanner.scanning:
                    scanner.scan_if_needed()
                    continue
                self.log.info(
                    (
                        "Fresh scan results not available yet; sleeping "
                        + "{:02.1f}s ({:02.1f}s "
                        + "so far)."
                    ).format(delay_interval, delay)
                )
                sleep(delay_interval)
                delay = delay + delay_interval
                delay_interval *= 2
                if delay_interval > max_delay_interval:
                    delay_interval = max_delay_interval
                if delay >= max_delay:
                    errstr = (
                        "Fresh scan results did not become available in "
                        + "{}s.".format(max_delay)
                    )
                    if scanner._results:
                        self.log.error("Returning stale scan data.")
                    else:
                        raise RuntimeError(errstr)
            self.log.debug(
                "Completed _wait_for_scan() for '{}'.".format(uname)
            )

    def _make_sizemap(self):
        with start_action(action_type="_make_sizemap"):
            uname = self.parent.user.escaped_name
            self.log.debug("Entering _make_sizemap() for '{}'.".format(uname))
            sizemap = OrderedDict()
            # For supported Python versions, dict is ordered anyway...
            sizes = self.parent.config.form_sizelist
            tiny_cpu = self.parent.config.tiny_cpu_max
            mb_per_cpu = self.parent.config.mb_per_cpu
            size_range = float(self.parent.config.lab_size_range)
            # Each size doubles the previous one.
            cpu = tiny_cpu
            idx = 0
            for sz in sizes:
                mem_mb = int(mb_per_cpu * cpu)
                sizemap[sz] = {
                    "cpu": cpu,
                    "mem": "{}M".format(mem_mb),
                    "name": sz,
                    "index": idx,
                }
                min_cpu = float(cpu / size_range)
                sizemap[sz]["cpu_guar"] = min_cpu
                min_mem_mb = int(mb_per_cpu * min_cpu)
                sizemap[sz]["mem_guar"] = "{}M".format(min_mem_mb)
                desc = sz.title() + " (%.2f CPU, %dM RAM)" % (cpu, mem_mb)
                sizemap[sz]["desc"] = desc
                cpu = cpu * 2
                idx = idx + 1
            # Clean up if list of sizes changed.
            self.sizemap = sizemap
            self.log.debug("Finished _make_sizemap() for '{}'.".format(uname))

    def options_from_form(self, formdata=None):
        """Get user selections.
        """
        with start_action(action_type="options_from_form"):
            options = None
            if formdata:
                options = {}
                if "kernel_image" in formdata and formdata["kernel_image"]:
                    options["kernel_image"] = formdata["kernel_image"][0]
                if "size" in formdata and formdata["size"]:
                    options["size"] = formdata["size"][0]
                if "image_tag" in formdata and formdata["image_tag"]:
                    options["image_tag"] = formdata["image_tag"][0]
                if "clear_dotlocal" in formdata and formdata["clear_dotlocal"]:
                    options["clear_dotlocal"] = True
                if "enable_debug" in formdata and formdata["enable_debug"]:
                    options["enable_debug"] = True
            return options

    def dump(self):
        """Return contents dict for pretty-printing.
        """
        sd = {
            "parent": str(self.parent),
            "sizemap": self.sizemap,
            "scanner": str(self._scanner),
        }
        return sd

    def toJSON(self):
        return json.dumps(self.dump())
