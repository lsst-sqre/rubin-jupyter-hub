import datetime
import threading
import time
from eliot import start_action
from .scanrepo import ScanRepo
from rubin_jupyter_utils.helpers import Singleton


class SingletonScanner(ScanRepo, metaclass=Singleton):
    """Singleton Object to hold rate-limited scanner.
    """

    def __init__(self, **kwargs):
        min_refresh_time = kwargs.get("min_refresh_time", 60)
        max_cache_age = kwargs.get("max_cache_age", 1200)
        if max_cache_age is None:
            max_cache_age = 1200
        # Now remove them from kwargs before superclass init
        for karg in ["min_refresh_time", "max_cache_age"]:
            if karg in kwargs:
                kwargs.pop(karg)
        super().__init__(**kwargs)
        self.min_refresh_time = min_refresh_time
        self.max_cache_age = max_cache_age
        self.scanning = False
        self.lock = threading.RLock()
        if max_cache_age < min_refresh_time:
            max_cache_age = 2 * min_refresh_time
            self.max_cache_age = max_cache_age
            self.logger.error("Nonsensical cache age/refresh time ratio.")
            self.logger.warning("Setting max_age to %ds." % max_cache_age)
        thd = threading.Thread(target=self.scan_if_needed)
        thd.start()

    def scan(self):
        """Execute repo scan.
        """
        with start_action(action_type="scan"):
            _timeout = 300
            _initialdelay = 0.2
            _maxdelay = 15
            _sofar = 0
            delay = _initialdelay
            if self.scanning:
                while not self._results:
                    # If there have been no results, wait up to
                    # _timeout seconds for them.
                    self.logger.debug(
                        "Scan in progress; waiting {}s for results.".format(
                            delay
                        )
                    )
                    time.sleep(delay)
                    _sofar += delay
                    if _sofar >= _timeout:
                        raise ValueError("Scan in progress never finished.")
                    delay *= 2
                    if delay > _maxdelay:
                        delay = _maxdelay
                    if _sofar + delay > _timeout:
                        delay = _timeout - _sofar
                    return  # Use cached (possibly stale) version if
                    # results exist.
            self.scanning = True
            now = datetime.datetime.utcnow()
            mt = self.min_refresh_time
            min_delay = datetime.timedelta(seconds=mt)
            if (now - self.last_scan < min_delay) and self._results:
                self.logger.warning(
                    "{}s not elapsed; have results; no rescan.".format(mt)
                )
                self.scanning = False
                return
            self.logger.info("Rescanning.")
            with self.lock:
                super().scan()
                self.scanning = False

    def scan_if_needed(self):
        with start_action(action_type="scan_if_needed"):
            now = datetime.datetime.utcnow()
            max_age = datetime.timedelta(seconds=self.max_cache_age)
            scan_age = now - self.last_scan
            if scan_age > max_age:
                self.logger.info("Scan data has expired.")
                self.data = None
                if self.scanning:
                    self.logger.info("Waiting for scan results.")
                    count = 0
                    while True:
                        time.sleep(0.2)
                        count = count + 1
                        if not (count % 50):
                            self.logger.debug(
                                "Waiting for data: {}s".format(count / 5)
                            )
                        if self.data:
                            break
                else:
                    self.logger.info("Beginning new scan.")
                    self.scan()
                self.logger.debug("Exiting scan_if_needed() wait loop.")
            else:
                secs = scan_age.total_seconds()
                self.logger.debug(
                    "Scan data is fresh ({}s); no new scan.".format(secs)
                )
                self.process_resultmap()

    def get_data(self):
        """Return repo data.
        """
        with start_action(action_type="get_data"):
            self.scan_if_needed()
            return self.data

    def get_display_tags(self):
        """Return all tags in repo.
        """
        with start_action(action_type="get_display_tags"):
            self.scan_if_needed()
            return self.display_tags

    def get_all_scan_results(self):
        """Return results from repository scan as dict.
        """
        with start_action(action_type="get_all_scan_results"):
            self.scan_if_needed()
            return self._results_map

    def extract_image_info(self):
        """Get info for all images.
        """
        with start_action(action_type="extract_image_info"):
            self.scan_if_needed()
            return super().extract_image_info()

    def report(self):
        """Report results of scan.
        """
        with start_action(action_type="report"):
            self.scan_if_needed()
            return super().report()
