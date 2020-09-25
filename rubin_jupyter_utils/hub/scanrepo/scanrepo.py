import base64
import datetime
import json
import logging
import math
import os
import re
import requests
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
        json=False,
        port=None,
        cachefile=None,
        insecure=False,
        sort_field="sort_tag",
        debug=False,
        username=None,
        password=None,
    ):
        self.data = {}
        self._results = None
        self._results_map = {}
        self._name_to_manifest = {}
        self._all_tags = []
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
        self.json = json
        protocol = "https"
        self.insecure = insecure
        if self.insecure:
            protocol = "http"
        self.sort_field = sort_field
        exthost = self.host
        reghost = exthost
        if reghost == "hub.docker.com":
            reghost = "registry.hub.docker.com"
        if port:
            exthost += ":" + str(port)
            reghost += ":" + str(port)
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
            for k in ["experimental", "daily", "weekly", "release"]:
                if k in self.data:
                    cs.extend(self.data[k])
            ldescs = []
            for c in cs:
                tag = c["name"]
                ld = c.get("description")
                if not ld:
                    ld, datedict = self._describe_tag(tag)
                ldescs.append(ld)
            ls = [self.owner + "/" + self.name + ":" + x["name"] for x in cs]
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
            self.last_scan = datetime.datetime.fromtimestamp(
                os.path.getmtime(fn))

    def _describe_tag(self, tag):
        # This method has been further abused to extract a tag-derived
        #  date dict from the tag name.  This *should* be pretty close
        #  to the build date.  Assuming no rebuild shenanigans, the only
        #  cases we have to worry about are releases and straight-up
        #  don't-fit-our-scheme tags.
        #
        # So we're going to make up a build date for releases that's not
        #  too bad for r20 (current when the new sort code was done) and
        #  gets less accurate the farther from it you go, but assuming
        #  we keep using sequential numbers, it'll still sort in the right
        #  order, even if our date is inaccurate.
        #
        # New-style tags have underscores separating components.
        # Don't log it; way too noisy.
        ld = tag  # Default description is just the tag name
        components = None
        ttype = None
        year = None
        week = None
        month = None
        day = None
        rest = None
        rmaj = None
        rmin = None
        rpatch = None
        if tag.find("_") != -1:  # New-style tag
            components = tag.split("_")
            btype = components[0]
            # Handle the r17_0_1 case.
            ctm = re.search(r"\d+$", btype)
            if ctm is not None:
                mj = int(ctm.group())
                components.insert(1, mj)
                btype = btype[0]
            if tag.startswith("recommended") or tag.startswith("latest"):
                ld = tag[0].upper() + tag[1:]
                restag = self.resolve_tag(tag)
                if restag:
                    rest_ld, datedict = self._describe_tag(restag)
                    year, month, day, rest, rmaj, rmin, \
                        rpatch, ttype = self._expand_datedict(datedict)
                    ld += " ({})".format(rest_ld)
            elif btype == "r":
                ttype = "release"
                rmaj = components[1]
                rmin = components[2]
                rpatch = None
                if len(components) > 3:
                    rpatch = components[3]
                if len(components) > 4:
                    rest = "_".join(components[4:])
                ld = "Release %s.%s" % (rmaj, rmin)
                if rpatch:
                    ld = ld + "." + rpatch
                if rest:
                    ld = ld + "-" + rest
            elif btype == "w":
                ttype = "weekly"
                year = components[1]
                week = components[2]
                year, month, day = self._translate_week(year, week)
                if len(components) > 3:
                    rest = "_".join(components[3:])
                ld = "Weekly %s_%s" % (year, week)
            elif btype == "d":
                ttype = "daily"
                year = components[1]
                month = components[2]
                day = components[3]
                if len(components) > 4:
                    rest = "_".join(components[4:])
                ld = "Daily %s_%s_%s" % (year, month, day)
            elif btype == "exp":
                ttype = "experimental"
                tagrest = components[1:]
                exprest = "_".join(tagrest)
                ld, datedict = self._describe_tag(exprest)
                year, month, day, rest, rmaj, rmin, \
                    rpatch, ttype = self._expand_datedict(datedict)
                ld = "Experimental " + ld
                if rest:
                    ld = ld + "_" + rest
        else:  # old-style tag -- thoroughly obsolete now.
            if tag.startswith("recommended") or tag.startswith("latest"):
                ld = tag[0].upper() + tag[1:]
                restag = self.resolve_tag(tag)
                if restag:
                    rest_ld, datedict = self._describe_tag(restag)
                    year, month, day, rest, rmaj, rmin, \
                        rpatch, ttype = self._expand_datedict(datedict)
                    ld += " ({})".format(rest_ld)
            elif tag[0] == "r":
                ttype = "release"
                rmaj = tag[1:3]
                rmin = tag[3:]
                ld = "Release %s.%s" % (rmaj, rmin)
            elif tag[0] == "w":
                ttype = "weekly"
                year = tag[1:5]
                week = tag[5:7]
                year, month, day = self._translate_week(year, week)
                ld = "Weekly %s_%s" % (year, week)
            elif tag[0] == "d":
                ttype = "daily"
                year = tag[1:5]
                month = tag[5:7]
                day = tag[7:]
                ld = "Daily %s_%s_%s" % (year, month, day)
            elif tag[0] == "e":
                ttype = "experimental"
                rest = tag[1:]
                ld, datedict = self._describe_tag(rest)
                year, month, day, rest, rmaj, rmin, \
                    rpatch, ttype = self._expand_datedict(datedict)
                ld = "Experimental " + ld
        datedict = {"year": year,
                    "month": month,
                    "day": day,
                    "rest": rest,
                    "rmaj": rmaj,
                    "rmin": rmin,
                    "rpatch": rpatch,
                    "type": ttype,
                    "sort_tag": None}
        datedict["sort_tag"] = self._get_sort_tag(datedict)
        return ld, datedict

    def _expand_datedict(self, datedict):
        year = datedict["year"]
        month = datedict["month"]
        day = datedict["day"]
        rest = datedict["rest"]
        rmaj = datedict["rmaj"]
        rmin = datedict["rmin"]
        rpatch = datedict["rpatch"]
        ttype = datedict["type"]
        return year, month, day, rest, rmaj, rmin, rpatch, ttype

    def _get_sort_tag(self, datedict):
        year = datedict["year"]
        month = datedict["month"]
        day = datedict["day"]
        rest = datedict["rest"]
        sort_tag = "0000-00-00-0"  # As early as possible
        # If we have "rest", we will sort that alphabetically.  We will
        #  equate no-rest with "zzzzzz" because we want to pretend that
        #  uncategorized builds come _last_ (e.g. "-rc1" versus no tag)
        if not rest:
            rest = "zzzzzz"
        if year and month and day:
            # This should be everything but releases, because _describe_tags
            #  resolves weeks to days.
            sort_tag = "{}-{}-{}-{}".format(year, month, day, rest)
        else:
            if datedict["type"] == "release":
                # Let's pretend that r20 came out July 1, 2020, and that
                #  every six months we have a new one.  Each minor version
                #  can be a month, each patch version can be a day.
                # Let's just pray that we never have more than 6 minor
                #  versions and 28 patches
                rmaj = datedict["rmaj"]
                rmin = datedict["rmin"]
                rpatch = datedict["rpatch"]
                major = 0
                minor = 0
                patch = 0
                if rmaj:
                    major = int(rmaj)
                if rmin:
                    minor = int(rmin)
                    if minor > 6:
                        minor = 6  # Least of our worries?
                if rpatch:
                    patch = int(patch)
                    if patch > 28:
                        patch = 28  # See above.
                offset = math.ceil(major / 2)
                year = 2010 + offset
                month = minor
                if ((major % 2) == 0):
                    month = month+6
                day = patch
                sort_tag = "{}-{}-{}-{}".format(year, month, day, rest)
            else:
                if rest and rest != "zzzzzz":
                    # Broken tag.  No date.  So it's taken to be super-early.
                    #  Sorting is probably pointless.
                    sort_tag = "0000-00-00-{}".format(rest)
        return sort_tag

    def _translate_week(self, year, week):
        # Conventionally, our weeklies are produced Saturday, so that's
        #  Day 6 of a week.
        # Let's assume the weeks are ISO week dates, but if they're not,
        #  the strptime format needs to change to '%Y-W%W-%w'.
        #  The year number might change around the end of the year: day 6
        #   of week 52 could be in the next year.
        s_fmt = '%G-W%V-%u'
        d_str = '{}-W{}-6'.format(year, week)
        ddate = datetime.datetime.strptime(d_str, s_fmt)
        year = '{:04d}'.format(ddate.year)
        month = '{:02d}'.format(ddate.month)
        day = '{:02d}'.format(ddate.day)
        return year, month, day

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
                default=self._serialize_datetime,
            )

    def _namemap_to_json(self):
        with start_action(action_type="_namemap_to_json"):
            modmap = {}
            nm = self._name_to_manifest
            rm = self._results_map
            for k in nm:
                ihash = nm[k].get("hash")
                if ihash:
                    modmap[k] = {"hash": ihash}
            return json.dumps(modmap, sort_keys=True, indent=4)

    def _serialize_datetime(self, o):
        # Don't log this; it's way too noisy.
        if isinstance(o, datetime.datetime):
            dstr = o.__str__().replace(" ", "T")
            if dstr[-1].isdigit():
                dstr += "Z"
            return dstr

    def report(self):
        """Print the tag data.
        """
        with start_action(action_type="report"):
            if self.json:
                print(self._data_to_json())
            else:
                ls, ldescs = self.extract_image_info()
                ldstr = ",".join(ldescs)
                lstr = ",".join(ls)
                print("# Environment variables for Jupyter Lab containers")
                print("LAB_CONTAINER_NAMES='%s'" % lstr)
                print("LAB_CONTAINER_DESCS='%s'" % ldstr)
                print("export LAB_CONTAINER_NAMES LAB_CONTAINER_DESCS")

    def get_data(self):
        """Return the tag data.
        """
        with start_action(action_type="get_data"):
            return self.data

    def get_all_tags(self):
        """Return all tags in the repository (sorted by last_updated).
        """
        with start_action(action_type="get_all_tags"):
            return self._all_tags

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
            self._update_results_map(results)
            self._map_names_to_manifests()
            self._reduce_results()
            self.last_scan = datetime.datetime.utcnow()

    def _update_results_map(self, results):
        with start_action(action_type="_update_results_map"):
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
                self.logger.debug("Adding {} to check_names.".format(tag))
                check_names.append(tag)
            if not check_names:
                self.logger.debug("All images have current hash.")
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
                for name in check_names:
                    resp = requests.head(
                        baseurl + "manifests/{}".format(name), headers=headers
                    )
                    ihash = resp.headers["Docker-Content-Digest"]
                    namemap[name]["hash"] = ihash
                    results[name]["hash"] = ihash
            self._name_to_manifest.update(namemap)
            if self.cachefile:
                self.logger.debug("Writing cache file.")
                try:
                    self._writecachefile()
                except Exception as exc:
                    self.log.error(
                        "Failed to write cache file: {}".format(exc)
                    )
                    # We're up to date.

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
            sort_field = self.sort_field
            # Recommended
            # Release/Weekly/Daily
            # Experimental/Latest/Other
            c_candidates = []
            r_candidates = []
            w_candidates = []
            d_candidates = []
            e_candidates = []
            l_candidates = []
            o_candidates = []
            # This is the order for tags to appear in menu:
            displayorder = []
            if self.recommended:
                displayorder.extend([c_candidates])
            displayorder.extend(
                [e_candidates, d_candidates, w_candidates, r_candidates]
            )
            reduced_results = {}
            for res in results:
                vname = res["name"]
                ld, datedict = self._describe_tag(vname)
                reduced_results[vname] = {
                    "name": vname,
                    "description": ld,
                    "sort_tag": datedict["sort_tag"]
                }
                entry = reduced_results[vname]
                manifest = self._name_to_manifest.get(vname)
                if manifest:
                    entry["hash"] = manifest.get("hash")
                else:
                    entry["hash"] = None
            for res in reduced_results:
                if res.startswith("r") and not res.startswith("recommended"):
                    r_candidates.append(reduced_results[res])
                elif res.startswith("w"):
                    w_candidates.append(reduced_results[res])
                elif res.startswith("d"):
                    d_candidates.append(reduced_results[res])
                elif res.startswith("exp"):
                    e_candidates.append(reduced_results[res])
                elif res.startswith("latest"):
                    l_candidates.append(reduced_results[res])
                elif res.startswith("recommended"):
                    c_candidates.append(reduced_results[res])
                else:
                    o_candidates.append(res)

            for clist in [r_candidates, w_candidates, d_candidates,
                          e_candidates, l_candidates, c_candidates,
                          o_candidates]:
                clist.sort(key=lambda x: x[sort_field], reverse=True)

            r = {}
            # Index corresponds to order in displayorder
            idxbase = 0
            imap = {}
            if self.recommended:
                imap.update({"recommended": {"index": idxbase, "count": 1}})
                idxbase = 1
            imap.update(
                {
                    "experimental": {
                        "index": idxbase,
                        "count": self.experimentals,
                    },
                    "daily": {"index": idxbase + 1, "count": self.dailies},
                    "weekly": {"index": idxbase + 2, "count": self.weeklies},
                    "release": {"index": idxbase + 3, "count": self.releases},
                }
            )
            for ikey in list(imap.keys()):
                idx = imap[ikey]["index"]
                ict = imap[ikey]["count"]
                if ict:
                    r[ikey] = displayorder[idx][:ict]

            self._all_tags = [x[1]['name'] for x in self._results_map.items()]
            self._all_tags.reverse()
            self.data = r

    def _authenticate_to_repo(self, headers):
        with start_action(action_type="_authenticate_to_repo"):
            self.logger.warning("Authentication Required.")
            self.logger.warning("Headers: {}".format(headers))
            magicheader = headers.get(
                'WWW-Authenticate', headers.get('Www-Authenticate', None))
            if magicheader.startswith("BASIC"):
                auth_hdr = base64.b64encode('{}:{}'.format(
                    self.username, self.password).encode('ascii'))
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
                if (not hd or "realm" not in hd or "service" not in hd
                        or "scope" not in hd):
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
                    "Accept": ("application/vnd.docker.distribution." +
                               "manifest.v2+json")
                }
                self.logger.warning(
                    "Requesting auth scope {}".format(hd["scope"]))
                tresp = requests.get(endpoint, headers=headers, params=hd,
                                     json=True, auth=auth)
                jresp = tresp.json()
                authtok = jresp.get("token")
                if authtok:
                    self.logger.info("Received an auth token.")
                    self.logger.warning("{}".format(authtok))
                    return {"Authorization": "Bearer {}".format(authtok)}
                else:
                    self.logger.error("No auth token: {}".format(jresp))
            return {}
