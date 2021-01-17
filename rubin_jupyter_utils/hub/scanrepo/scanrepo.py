import base64
import concurrent.futures
import datetime
import json
import logging
import os
import re
import requests
import semver
import time
import urllib.error
import urllib.parse
import urllib.request

from eliot import start_action
from rubin_jupyter_utils.helpers import make_logger


class ScanRepo(object):
    """Class to scan repository and create results.

       Based on:
       https://github.com/shangteus/py-dockerhub/blob/master/dockerhub.py"""

    def __init__(
        self,
        host="hub.docker.com",
        path="",
        owner="",
        name="",
        experimentals=0,
        dailies=3,
        weeklies=2,
        releases=1,
        recommended=True,
        port=None,
        cachefile=None,
        insecure=False,
        debug=False,
        username=None,
        password=None,
    ):
        self.data = {}
        self.display_tags = []
        self._results = None
        self._results_map = {}
        self._name_to_manifest = {}
        self._all_tags = []
        self._reduced_results = []
        self.last_scan = datetime.datetime(1970, 1, 1)  # The Epoch
        self.debug = debug
        self.logger = make_logger()
        if self.debug:
            self.logger.setLevel(logging.DEBUG)
            self.logger.debug("Debug logging enabled.")
        self.host = host
        self.path = path
        self.owner = owner
        self.name = name
        self.username = username
        self.password = password
        self.experimentals = experimentals
        self.dailies = dailies
        self.weeklies = weeklies
        self.releases = releases
        self.recommended = recommended
        protocol = "https"
        self.insecure = insecure
        if self.insecure:
            protocol = "http"
        exthost = self.host
        reghost = exthost
        if reghost == "hub.docker.com":
            reghost = "registry.hub.docker.com"
        if port:
            exthost += ":" + str(port)
            reghost += ":" + str(port)
        self.reghost = reghost
        self.cachefile = cachefile
        if self.cachefile:
            self._read_cachefile()
        self.registry_url = (
            protocol
            + "://"
            + reghost
            + "/v2/"
            + self.owner
            + "/"
            + self.name
            + "/"
        )
        self.logger.debug("Registry URL: {}".format(self.registry_url))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        """Close the session.
        """
        if self._session:
            self._session.close()

    def extract_image_info(self):
        """Build image name list and image description list.
        """
        with start_action(action_type="extract_image_info"):

            cs = []
            if self.recommended and "recommended" in self.data:
                cs.extend(self.data["recommended"])
            self.logger.debug(cs)
            for k in ["weekly", "daily", "experimental", "release"]:
                if k in self.data:
                    cs.extend(self.data[k])
            ldescs = []
            self.logger.debug(cs)
            for c in cs:
                tag = c["name"]
                ld = c.get("description")
                if not ld:
                    ld, _, _, _ = self._describe_tag(tag)
                ldescs.append(ld)
            ls = [
                self.reghost
                + "/"
                + self.owner
                + "/"
                + self.name
                + ":"
                + x["name"]
                for x in cs
            ]
            return ls, ldescs

    def _read_cachefile(self):
        with start_action(action_type="_read_cachefile"):
            fn = self.cachefile
            try:
                with open(fn) as f:
                    data = json.load(f)
            except Exception as exc:
                self.logger.error(
                    "Failed to load cachefile '{}'; must rescan".format(fn)
                )
                self.logger.error("Error: {}".format(exc))
                return
            self.logger.debug("Loaded cachefile {}".format(fn))
            nm = self._name_to_manifest
            rm = self._results_map
            for tag in data.keys():
                ihash = data[tag].get("hash")
                if ihash:
                    if tag not in nm:
                        nm[tag] = {"hash": ihash}
                    if tag not in rm:
                        rm[tag] = {"name": tag}
            # Update last scan time with modification time of
            #  cachefile
            self.logger.debug("Updating last_scan from cachefile mtime.")
            self.last_scan = datetime.datetime.fromtimestamp(
                os.path.getmtime(fn)
            )

    def _describe_tag(self, tag):
        # This method started as a way to extract a human-friendly description
        #  from the tag name; it has been extended to extract a tag-derived
        #  semantic version from the name.  This will generally look like
        #  a date for non-release versions.
        #
        # Specifically, dailies and weeklies, and experimentals built
        #  from either of those, will have a known date, because it's
        #  in the tag (assuming that weeklies are always built on
        #  Saturday, which is generally a good assumption), and
        #  therefore we can easily create a semantic version for each of
        #  those (major/minor/patch) that corresponds to year/month/day, and
        #  that will sort them in production order.
        #
        # In general we don't build dailies on Saturday, so version collison
        #  will be rare, and furthermore the only place we'd have dailies,
        #  weeklies, and experimentals made from those all jammed together
        #  will be the all-tags dropdown.  In which case, well, maybe a
        #  weekly and daily will be reversed relative to their actual
        #  production order, but who really cares?
        #
        # Releases have numbers that let us assign a sort order to them.
        #  The question then becomes what to do with them relative to all
        #  other builds.  Fortunately this only matters in the all-tags
        #  dropdown; so I propose to just sort them at the end of the list.
        #  The easiest way to do this is to make *their* version just the
        #  semver of the release tags.  That means that releases will all
        #  have a much lower version than non-release builds.  If we don't
        #  like that, we can make their major version 9999, and tack the
        #  rest on after that.
        #
        # For experimental and resolved ("recommended" or "latest") tags
        #  we call this recursively, and fix up the descriptions and
        #  version components when we return from the inner call.
        #
        # New-style tags (since early 2019) have underscores separating
        #  components.
        #
        # This method is called far too often to log with eliot, because
        #  we pop in and out of it many, many times when scanning a repo.
        #
        ld = tag  # Default description is just the tag name
        components = None
        ttype = None
        major = 0
        minor = 0
        patch = 0
        rest = None
        if "_" in tag:  # New-style tag
            components = tag.split("_")
            btype = components[0]
            # Handle the r17_0_1 case.  Yeah, special-cased because, in fact,
            #  we have this tag which doesn't fit our pattern.
            ctm = re.search(r"\d+$", btype)
            if ctm is not None:
                mj = int(ctm.group())
                components.insert(1, mj)
                btype = btype[0]
            # Now a big if statement to categorize each
            if tag.startswith("recommended") or tag.startswith("latest"):
                ld = tag[0].upper() + tag[1:]
                restag = self.resolve_tag(tag)
                if restag:
                    res_ld, res_ver, _, res_rest = self._describe_tag(restag)
                    major = res_ver.major
                    minor = res_ver.minor
                    patch = res_ver.patch
                    rest = res_rest
                    ld += " ({})".format(res_ld)
                    ttype = "resolved"
            elif btype == "r":
                ttype = "release"
                major = int(components[1])
                try:
                    minor = int(components[2])
                except ValueError:
                    if (
                        components[2] == "flattened"
                        or components[2] == "layered"
                    ):
                        minor = 0  # Fallout from flattener
                if len(components) > 3:
                    patch = int(components[3])  # This will need work if
                    # we ever get "r_22_0_rc1" rather than "r_22_0_0_rc1"
                if len(components) > 4:
                    rest = components[4]
                    if len(components) > 5:
                        rest = rest + "+" + ".".join(components[5:])
                    if rest.startswith("rc"):  # Special-cased
                        rest = "rc." + rest[2:]  # put it in semver string fmt
                ld = "Release {}.{}".format(major, minor)
                if patch:
                    ld = ld + ".{}".format(patch)
                if rest:
                    ld = ld + "-" + rest
            elif btype == "w":
                ttype = "weekly"
                year = components[1]
                week = components[2]
                major, minor, patch = self._translate_week(year, week)
                if len(components) > 3:
                    rest = "_".join(components[3:])
                ld = "Weekly {}_{}".format(year, week)  # Those are strings.
                if rest:
                    ld = ld + "-" + rest
            elif btype == "d":
                ttype = "daily"
                major = int(components[1])
                minor = int(components[2])
                patch = int(components[3])
                if len(components) > 4:
                    rest = "_".join(components[4:])
                ld = "Daily {:04d}_{:02d}_{:02d}".format(major, minor, patch)
                if rest:
                    ld = ld + "-" + rest
            elif btype == "exp":
                ttype = "experimental"
                tagrest = components[1:]
                exprest = "_".join(tagrest)
                ld, ver, _, rest = self._describe_tag(exprest)
                major = ver.major
                minor = ver.minor
                patch = ver.patch
                ld = "Experimental " + ld
        else:  # old-style tag
            # We don't have any more dailies with the old-style tag, and
            #  very shortly we won't have any more weeklies (as long as the
            #  reaper runs).  However, we will never get rid of the releases
            #  between 'r130' and 'r170'.
            #
            # Also, unqualified "recommended" and "latest" end up here.
            if tag.startswith("recommended") or tag.startswith("latest"):
                ld = tag[0].upper() + tag[1:]
                restag = self.resolve_tag(tag)
                if restag:
                    rest_ld, ver, _, rest = self._describe_tag(restag)
                    major = ver.major
                    minor = ver.minor
                    patch = ver.patch
                    ld += " ({})".format(rest_ld)
                    ttype = "resolved"
                if rest:
                    ld += "-" + rest
            elif tag[0] == "r":
                # e.g. "r160", which is release 16.0, not 1.6.0.
                ttype = "release"
                major = int(tag[1:3])
                minor = int(tag[3:])
                patch = 0
                ld = "Release {}.{}".format(major, minor)
                if rest:
                    ld += "-" + rest
            elif tag[0] == "w":
                # e.g. "w201910"
                ttype = "weekly"
                year = tag[1:5]
                week = tag[5:7]
                rest = tag[7:]
                major, minor, patch = self._translate_week(year, week)
                ld = "Weekly {}_{}".format(year, week)
                if rest:
                    ld += "-" + rest
            else:
                self.logger.error("Obsolete tag {}!".format(tag))
        semver_str = "{}.{}.{}".format(major, minor, patch)
        if ttype == "release" and rest:
            semver_str += "-" + rest  # "rc.X" will become a prerelease version
            rest = None
        ver = semver.VersionInfo.parse(semver_str)
        return ld, ver, ttype, rest

    def _translate_week(self, year, week):
        # Conventionally, our weeklies are produced Saturday, so that's
        #  Day 6 of a week.
        #
        # Let's assume the weeks are ISO week dates, but if they're not,
        #  the strptime s_ftm needs to change to '%Y-W%W-%w'.
        #
        # The year number might change around the end of the year: day 6
        #   of week 52 could *really* be in the next year.
        s_fmt = "%G-W%V-%u"
        d_str = "{}-W{}-6".format(year, week)  # These are strings
        ddate = datetime.datetime.strptime(d_str, s_fmt)
        return ddate.year, ddate.month, ddate.day  # These are integers

    def resolve_tag(self, tag):
        """Resolve a tag (used for "recommended" or "latest*").
        """
        with start_action(action_type="resolve_tag"):
            mfest = self._name_to_manifest.get(tag)
            if not mfest:
                self.logger.debug("Did not find manifest for '{}'".format(tag))
                return None
            hash = mfest.get("hash")
            self.logger.debug("Tag '{}' hash -> '{}'".format(tag, hash))
            if not hash:
                return None
            for k in self._name_to_manifest:
                if k.startswith("recommended") or k.startswith("latest"):
                    continue
                if self._name_to_manifest[k].get("hash") == hash:
                    self.logger.debug(
                        "Found matching hash for tag '{}'".format(k)
                    )
                    return k

    def _data_to_json(self):
        with start_action(action_type="_data_to_json"):
            return json.dumps(
                self.data,
                sort_keys=True,
                indent=4,
                default=self._serialize_datetime_and_semver,
            )

    def _namemap_to_json(self):
        with start_action(action_type="_namemap_to_json"):
            modmap = {}
            nm = self._name_to_manifest
            for k in nm:
                ihash = nm[k].get("hash")
                if ihash:
                    modmap[k] = {"hash": ihash}
            return json.dumps(modmap, sort_keys=True, indent=4)

    def _serialize_datetime_and_semver(self, o):
        # Don't log this; it's way too noisy.
        if isinstance(o, datetime.datetime):
            dstr = o.__str__().replace(" ", "T")
            if dstr[-1].isdigit():
                dstr += "Z"  # Naive time, assume UTC
            return dstr
        if isinstance(o, semver.VersionInfo):
            return str(o)

    def report(self):
        """Print the tag data.
        """
        with start_action(action_type="report"):
            print(self._data_to_json())

    def get_data(self):
        """Return the tag data.
        """
        with start_action(action_type="get_data"):
            return self.data

    def get_all_tags(self):
        """Return all tags in the repository, sorted by semver.
        """
        with start_action(action_type="get_all_tags"):
            return self._all_tags

    def get_display_tags(self):
        """Return all tags in the repository, sorted by category and then
        semver.
        """
        with start_action(action_type="get_display_tags"):
            return self._display_tags

    def _get_url(self, url, headers, **kwargs):
        # Too noisy to log.
        params = None
        resp = None
        if kwargs:
            params = urllib.parse.urlencode(kwargs)
            url += "?%s" % params
        req = urllib.request.Request(url, None, headers)
        resp = urllib.request.urlopen(req)
        page = resp.read()
        return page

    def scan(self):
        """Perform the repository scan.
        """
        with start_action(action_type="scan"):
            headers = {"Accept": "application/json"}
            url = self.registry_url + "tags/list"
            self.logger.debug("Beginning repo scan of '{}'.".format(url))
            results = []
            page = 1
            resp_bytes = None
            while True:
                self.logger.debug("Scanning...")
                try:
                    resp_bytes = self._get_url(url, headers, page=page)
                except urllib.error.HTTPError as e:
                    if e.code == 401:
                        headers.update(self._authenticate_to_repo(e.hdrs))
                        self.logger.debug("Authenticated to repo")
                        continue
                except Exception as e:
                    message = "Failure retrieving %s: %s" % (url, str(e))
                    if resp_bytes:
                        message += " [ data: %s ]" % (
                            str(resp_bytes.decode("utf-8"))
                        )
                    raise ValueError(message)
                resp_text = resp_bytes.decode("utf-8")
                try:
                    j = json.loads(resp_text)
                except ValueError:
                    raise ValueError(
                        "Could not decode '%s' -> '%s' as JSON"
                        % (url, str(resp_text))
                    )
                for tag in j["tags"]:
                    results.append({"name": tag})
                if "next" not in j or not j["next"]:
                    break
                page = page + 1
            self._results = results
            self._update_results_map()
            self.process_resultmap()

    def process_resultmap(self):
        """Take the results from a scan and parse them into usable data.
        """
        if not self._results:
            self._synthesize_results_from_resultmap()
        self._map_names_to_manifests()
        self._reduce_results()
        self.logger.debug("Updating last_scan with current time.")
        self.last_scan = datetime.datetime.utcnow()

    def _synthesize_results_from_resultmap(self):
        self._results = list(self._results_map.values())

    def _update_results_map(self):
        with start_action(action_type="_update_results_map"):
            results = self._results
            rm = self._results_map
            for res in results:
                name = res["name"]
                if name not in rm:
                    rm[name] = {}
                rm[name].update(res)

    def _map_names_to_manifests(self):
        with start_action(action_type="_map_names_to_manifests"):
            results = self._results_map
            namemap = self._name_to_manifest
            check_names = []
            for tag in results:
                if not namemap.get(tag):
                    namemap[tag] = {
                        "layers": None,
                        "hash": None,
                    }
                if namemap[tag]["hash"]:
                    # We have a manifest
                    # Update results map with hash
                    results[tag]["hash"] = namemap[tag]["hash"]
                    continue
                check_names.append(tag)
            if not check_names:
                self.logger.debug("All images have current hash.")
                if self.cachefile:
                    cache = self.cachefile
                    st = os.stat(cache)
                    now = datetime.datetime.utcnow().timestamp()
                    os.utime(cache, times=(st.st_atime, now))
                return
            baseurl = self.registry_url
            url = baseurl + "manifests/recommended"
            i_resp = requests.head(url)
            authtok = None
            sc = i_resp.status_code
            if sc == 401:
                self.logger.debug("Getting token to retrieve layer lists.")
                magicheader = i_resp.headers["Www-Authenticate"]
                if magicheader[:7] == "Bearer ":
                    hd = {}
                    hl = magicheader[7:].split(",")
                    for hn in hl:
                        il = hn.split("=")
                        kk = il[0]
                        vv = il[1].replace('"', "")
                        hd[kk] = vv
                    if (
                        not hd
                        or "realm" not in hd
                        or "service" not in hd
                        or "scope" not in hd
                    ):
                        return None
                    endpoint = hd["realm"]
                    del hd["realm"]
                    tresp = requests.get(endpoint, params=hd, json=True)
                    jresp = tresp.json()
                    authtok = jresp.get("token")
            elif sc != 200:
                self.logger.warning("GET %s -> %d" % (url, sc))
            # https://docs.docker.com/registry/spec/api/ ,
            # "Deleting An Image"
            # Yep, I think that's the only place it tells you that you need
            #  this magic header to get the digest hash.
            headers = {
                "Accept": (
                    "application/vnd.docker.distribution" + ".manifest.v2+json"
                )
            }
            if authtok:
                headers.update({"Authorization": "Bearer {}".format(authtok)})
            tag_futures = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as xo:
                for name in check_names:
                    tag_futures[name] = xo.submit(
                        self._get_tag_hash, headers, baseurl, name
                    )
                timeout = 120
                i = 0
                while True:
                    for name in check_names:
                        if name in tag_futures:
                            fut = tag_futures[name]
                            if fut.done():
                                ihash = fut.result(timeout=1)
                                self.logger.debug(
                                    "Got tag for {}".format(name)
                                )
                                namemap[name]["hash"] = ihash
                                results[name]["hash"] = ihash
                                del tag_futures[name]
                    if not tag_futures:  # We have consumed them all
                        break
                    i = i + 1
                    if i > timeout:
                        raise RuntimeError(
                            "tag check didn't complete in {}s".format(i)
                        )
                    time.sleep(1)
            self._name_to_manifest.update(namemap)
            self._writecachefile()

    def _get_tag_hash(self, headers, baseurl, name):
        self.logger.debug(
            "Making request to {} for tag '{}'".format(baseurl, name)
        )
        resp = requests.head(
            baseurl + "manifests/{}".format(name), headers=headers
        )
        ihash = resp.headers["Docker-Content-Digest"]
        return ihash

    def _writecachefile(self):
        with start_action(action_type="_writecachefile"):
            if self.cachefile:
                try:
                    with open(self.cachefile, "w") as f:
                        f.write(self._namemap_to_json())
                except Exception as exc:
                    self.logger.error(
                        "Could not write to {}: {}".format(self.cachefile, exc)
                    )

    def _reduce_results(self):
        with start_action(action_type="_reduce_results"):
            results = self._results
            reduced_results = []
            for res in results:
                vname = res["name"]
                ld, ver, ttype, rest = self._describe_tag(vname)
                entry = {
                    "name": vname,
                    "description": ld,
                    "version": ver,
                    "type": ttype,
                    "rest": rest,
                }
                manifest = self._name_to_manifest.get(vname)
                if manifest:
                    entry["hash"] = manifest.get("hash")
                else:
                    entry["hash"] = None
                reduced_results.append(entry)
            # Sort list of reduced_results by semver
            reduced_results.sort(key=lambda x: x["version"], reverse=True)
            self._all_tags = [x["name"] for x in reduced_results]
            self._reduced_results = reduced_results
            self._create_display_tags()

    def _create_display_tags(self):
        """Create the displayed list of images, and all tags sorted
        by category and semver within category.
        """
        with start_action(action_type="_create_display_tags"):
            #
            # The order in which tags should be presented are:
            #
            # Recommended -- only if self.recommended is on
            # Latest (don't display separately, at least not for now)
            # Weekly
            # Daily
            # Experimental
            # Release (don't prune rcs for all-tags)
            # Other (should be empty in all circumstances--only in all-tags
            #  if they exist at all, but if they do, something is wrong)
            c_images = []
            l_images = []
            e_images = []
            d_images = []
            w_images = []
            r_images = []
            o_images = []
            all_r_images = []
            rresults = self._reduced_results
            for res in rresults:
                # Don't prepull "_layered" or "_flattened" images.
                #  This is an artifact from our flattener, which we
                #  need for containerd + K8s 1.18+
                rname = res["name"]
                if rname.endswith("_layered") or rname.endswith("_flattened"):
                    continue
                rtype = res["type"]
                if rtype == "release":
                    all_r_images.append(res)
                elif rtype == "weekly":
                    w_images.append(res)
                elif rtype == "daily":
                    d_images.append(res)
                elif rtype == "experimental":
                    e_images.append(res)
                elif rtype == "resolved":
                    rname = res["name"]
                    if rname.startswith("latest"):
                        l_images.append(res)
                    elif rname.startswith("recommended"):
                        c_images.append(res)
                    else:
                        o_images.append(res)
                else:
                    o_images.append(res)
            # Releases are special: see _prune_releases
            pruned_releases, _ = self._prune_releases()
            r_images.extend(pruned_releases)
            # We always want to show the first n *real releases*.  Any rcs
            #  that are more recent than that are shown too, but they do
            #  not count towards the total.
            extra_rcs = 0
            for img in r_images:
                sv = img["version"]
                if sv.prerelease:
                    extra_rcs += 1
                else:
                    break
            resultmap = {}
            if self.recommended:
                if c_images:
                    resultmap["recommended"] = [c_images[0]]
            if self.weeklies:
                resultmap["weekly"] = w_images[: self.weeklies]
            if self.experimentals:
                resultmap["experimental"] = e_images[: self.experimentals]
            if self.dailies:
                resultmap["daily"] = d_images[: self.dailies]
            if self.releases:
                resultmap["release"] = r_images[: (self.releases + extra_rcs)]
            self.data = resultmap
            self.display_tags = []
            for imglist in [
                w_images,
                d_images,
                e_images,
                all_r_images,
                o_images,
            ]:
                self.display_tags.extend([x["name"] for x in imglist])

    def _prune_releases(self):
        # How are releases special?  We never want to display release
        #  candidates *unless* they are newer (that is, have a higher
        #  semantic version number) than all of the *real* releases.
        rresults = self._reduced_results
        show_rc = True
        pruned = []
        old_prereleases = []  # We will use this in the reaper
        for res in rresults:
            if res["type"] != "release":
                continue
            ver = res["version"]
            if ver.prerelease:
                if show_rc:  # We haven't seen a non-prerelease
                    pruned.append(res)
                else:
                    old_prereleases.append(res)
            else:
                show_rc = False  # But now we have, so stop showing them
                pruned.append(res)
        return pruned, old_prereleases

    def _authenticate_to_repo(self, headers):
        with start_action(action_type="_authenticate_to_repo"):
            self.logger.warning("Authentication Required.")
            self.logger.warning("Headers: {}".format(headers))
            magicheader = headers.get(
                "WWW-Authenticate", headers.get("Www-Authenticate", None)
            )
            if magicheader.startswith("BASIC"):
                auth_hdr = base64.b64encode(
                    "{}:{}".format(self.username, self.password).encode(
                        "ascii"
                    )
                )
                self.logger.info("Auth header now: {}".format(auth_hdr))
                return {"Authorization": "Basic " + auth_hdr.decode()}
            if magicheader.startswith("Bearer "):
                hd = {}
                hl = magicheader[7:].split(",")
                for hn in hl:
                    il = hn.split("=")
                    kk = il[0]
                    vv = il[1].replace('"', "")
                    hd[kk] = vv
                if (
                    not hd
                    or "realm" not in hd
                    or "service" not in hd
                    or "scope" not in hd
                ):
                    return None
                endpoint = hd["realm"]
                del hd["realm"]
                # We need to glue in authentication for DELETE, and that alas
                #  means a userid and password.
                r_user = self.username
                r_pw = self.password
                auth = None
                if r_user and r_pw:
                    auth = (r_user, r_pw)
                    self.logger.warning("Added Basic Auth credentials")
                headers = {
                    "Accept": (
                        "application/vnd.docker.distribution."
                        + "manifest.v2+json"
                    )
                }
                self.logger.warning(
                    "Requesting auth scope {}".format(hd["scope"])
                )
                tresp = requests.get(
                    endpoint, headers=headers, params=hd, json=True, auth=auth
                )
                jresp = tresp.json()
                authtok = jresp.get("token")
                if authtok:
                    self.logger.info("Received an auth token.")
                    self.logger.warning("{}".format(authtok))
                    return {"Authorization": "Bearer {}".format(authtok)}
                else:
                    self.logger.error("No auth token: {}".format(jresp))
            return {}
