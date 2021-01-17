import os
import requests
from eliot import start_action
from . import SingletonScanner


class Reaper(SingletonScanner):
    """Class to allow implementation of image retention policy.
    """

    # We don't need to categorize releases since we never delete any of
    #  them.

    def __init__(self, *args, **kwargs):
        self.keep_experimentals = kwargs.pop("keep_experimentals", 10)
        self.keep_dailies = kwargs.pop("keep_dailies", 15)
        self.keep_weeklies = kwargs.pop("keep_weeklies", 78)
        self.dry_run = kwargs.pop("dry_run", False)
        self.more_cowbell = self.reap
        super().__init__(**kwargs)
        self.logger.debug(
            (
                "Keeping: {} weeklies, {} dailies, and {} " + "experimentals."
            ).format(
                self.keep_weeklies, self.keep_dailies, self.keep_experimentals
            )
        )
        self.delete_tags = False
        if self.registry_url.startswith("registry.hub.docker.com"):
            self.delete_tags = True
        self.reapable = {}
        self._categorized_tags = {}

    def _categorize_tags(self):
        self._categorized_tags = {
            "weekly": [],
            "daily": [],
            "experimental": [],
        }
        with start_action(action_type="_categorize_tags"):
            self.scan_if_needed()
            rresults = self._reduced_results  # already sorted
            for res in rresults:
                rt = res["type"]
                if rt in ["weekly", "daily", "experimental"]:
                    self.logger.debug("Found image {}".format(res))
                    self._categorized_tags[rt].append(res["name"])
            _, old_prereleases = self._prune_releases()
            self._categorized_tags["obsolete_prereleases"] = [
                x["name"] for x in old_prereleases
            ]

    def _select_victims(self):
        with start_action(action_type="_select victims"):
            self._categorize_tags()
            reaptags = []
            sc = self._categorized_tags
            reaptags.extend(sc["experimental"][self.keep_experimentals :])
            reaptags.extend(sc["daily"][self.keep_dailies :])
            reaptags.extend(sc["weekly"][self.keep_weeklies :])
            reaptags.extend(sc["obsolete_prereleases"])
            reapable = {}
            for r in reaptags:
                reapable[r] = self._results_map[r]["hash"]
            self.logger.debug("Images to reap: {}.".format(reapable))
            self.reapable = reapable

    def report_reapable(self):
        """Return a space-separated list of reapable images.
        """
        with start_action(action_type="report_reapable"):
            self._select_victims()
            return " ".join(self.reapable.keys())

    def reap(self):
        """Select and delete images.
        """
        with start_action(action_type="reap"):
            self._select_victims()
            self._delete_from_repo()

    def _delete_from_repo(self):
        with start_action(action_type="_delete_from_repo"):
            tags = list(self.reapable.keys())
            if not tags:
                self.logger.info("No images to reap.")
                return
            if self.dry_run:
                self.logger.info("Dry run: images to reap: {}".format(tags))
                return
            headers = {
                "Accept": (
                    "application/vnd.docker.distribution.manifest." + "v2+json"
                )
            }
            sc = 0
            if self.registry_url.startswith("https://registry.hub.docker.com"):
                self._delete_tags_from_docker_hub()
                return
            for t in tags:
                self.logger.debug("Attempting to reap '{}'.".format(t))
                h = self.reapable[t]
                path = self.registry_url + "manifests/" + h
                resp = requests.delete(path, headers=headers)
                sc = resp.status_code
                if sc == 401:
                    auth_hdr = self._authenticate_to_repo(resp)
                    headers.update(auth_hdr)  # Retry with new auth
                    self.logger.warning("Retrying with new authentication.")
                    resp = requests.delete(path, headers=headers)
                    sc = resp.status_code
                if (sc >= 200) and (sc < 300):
                    # Got it.
                    del self._results_map[t]
                else:
                    self.logger.warning("DELETE {} => {}".format(path, sc))
                    self.logger.warning("Headers: {}".format(resp.headers))
                    self.logger.warning("Body: {}".format(resp.text))
                if self.cachefile:
                    self._writecachefile()  # Remove deleted tags

    def _delete_tags_from_docker_hub(self):
        # This is, of course, completely different from the published API
        #  https://github.com/docker/hub-feedback/issues/496
        with start_action(action_type="_delete_tags_from_docker_hub"):
            self.logger.info("Deleting tags from Docker Hub.")
            r_user = os.getenv("IMAGE_REAPER_USER")
            r_pw = os.getenv("IMAGE_REAPER_PASSWORD")
            data = {"username": r_user, "password": r_pw}
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            token = None
            # Exchange username/pw for token
            if r_user and r_pw:
                resp = requests.post(
                    "https://hub.docker.com/v2/users/login",
                    headers=headers,
                    json=data,
                )
                r_json = resp.json()
                if r_json:
                    token = r_json.get("token")
                else:
                    self.logger.warning("Failed to authenticate:")
                    self.logger.warning("Headers: {}".format(resp.headers))
                    self.logger.warning("Body: {}".format(resp.text))
            else:
                self.logger.error("Did not have username and password.")
            if not token:
                self.logger.error("Could not acquire JWT token.")
                return
            headers["Authorization"] = "JWT {}".format(token)
            tags = list(self.reapable.keys())
            for t in tags:
                path = (
                    "https://hub.docker.com/v2/repositories/"
                    + self.owner
                    + "/"
                    + self.name
                    + "/tags/"
                    + t
                    + "/"
                )
                self.logger.info("Deleting tag '{}'".format(t))
                resp = requests.delete(path, headers=headers)
                sc = resp.status_code
                if (sc < 200) or (sc >= 300):
                    self.logger.warning("DELETE {} => {}".format(path, sc))
                    self.logger.warning("Headers: {}".format(resp.headers))
                    self.logger.warning("Body: {}".format(resp.text))
                    if sc != 404:
                        continue
                    # It's already gone, so remove from map!
                del self._results_map[t]
            if self.cachefile:
                self._writecachefile()  # Remove deleted tags
