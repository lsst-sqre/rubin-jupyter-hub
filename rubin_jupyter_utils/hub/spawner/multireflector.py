from kubespawner.reflector import NamespacedResourceReflector
from kubespawner.spawner import PodReflector, EventReflector
from kubernetes import watch
from urllib3.exceptions import ReadTimeoutError
from functools import partial
import json
import threading
import time


class MultiNamespaceReflector(NamespacedResourceReflector):
    """We need to remove the namespace from all the list_method_name
    calls.  That requires, unfortunately, a lot of code duplication.
    """

    list_method_omit_namespace = True

    def _list_and_update(self):
        """
        Update current list of resources by doing a full fetch.

        Overwrites all current resource info.
        """
        initial_resources = getattr(self.api, self.list_method_name)(
            label_selector=self.label_selector,
            field_selector=self.field_selector,
            _request_timeout=self.request_timeout,
            _preload_content=False,
        )
        # This is an atomic operation on the dictionary!
        initial_resources = json.loads(initial_resources.read())
        self.resources = {
            p["metadata"]["name"]: p
            for p in initial_resources[
                "\
items"
            ]
        }
        # return the resource version so we can hook up a watch
        return initial_resources["metadata"]["resourceVersion"]

    def _watch_and_update(self):
        """
        Keeps the current list of resources up-to-date

        This method is to be run not on the main thread!

        We first fetch the list of current resources, and store that. Then we
        register to be notified of changes to those resources, and keep our
        local store up-to-date based on these notifications.

        We also perform exponential backoff, giving up after we hit 32s
        wait time. This should protect against network connections dropping
        and intermittent unavailability of the api-server. Every time we
        recover from an exception we also do a full fetch, to pick up
        changes that might've been missed in the time we were not doing
        a watch.

        Note that we're playing a bit with fire here, by updating a dictionary
        in this thread while it is probably being read in another thread
        without using locks! However, dictionary access itself is atomic,
        and as long as we don't try to mutate them (do a 'fetch / modify /
        update' cycle on them), we should be ok!
        """
        selectors = []
        if self.label_selector:
            selectors.append("label selector=%r" % self.label_selector)
        if self.field_selector:
            selectors.append("field selector=%r" % self.field_selector)
        log_selector = ", ".join(selectors)

        cur_delay = 0.1

        self.log.info(
            "watching for %s with %s in namespace %s",
            self.kind,
            log_selector,
            self.namespace,
        )
        while True:
            start = time.monotonic()
            w = watch.Watch()
            try:
                resource_version = self._list_and_update()
                if not self.first_load_future.done():
                    # signal that we've loaded our initial data
                    self.first_load_future.set_result(None)
                watch_args = {
                    "label_selector": self.label_selector,
                    "field_selector": self.field_selector,
                    "resource_version": resource_version,
                }
                if self.request_timeout:
                    # set network receive timeout
                    watch_args["_request_timeout"] = self.request_timeout
                if self.timeout_seconds:
                    # set watch timeout
                    watch_args["timeout_seconds"] = self.timeout_seconds
                method = partial(
                    getattr(self.api, self.list_method_name),
                    _preload_content=False,
                )
                # in case of timeout_seconds, the w.stream just exits (no exception thrown)
                # -> we stop the watcher and start a new one
                for watch_event in w.stream(method, **watch_args):
                    # Remember that these events are k8s api related WatchEvents
                    # objects, not k8s Event or Pod representations, they will
                    # reside in the WatchEvent's object field depending on what
                    # kind of resource is watched.
                    #
                    # ref: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.16/#watchevent-v1-meta
                    # ref: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.16/#event-v1-core
                    cur_delay = 0.1
                    resource = watch_event["object"]
                    if watch_event["type"] == "DELETED":
                        # This is an atomic delete operation on the dictionary!
                        self.resources.pop(resource["metadata"]["name"], None)
                    else:
                        # This is an atomic operation on the dictionary!
                        self.resources[resource["metadata"]["name"]] = resource
                    if self._stop_event.is_set():
                        self.log.info("%s watcher stopped", self.kind)
                        break
                    watch_duration = time.monotonic() - start
                    if watch_duration >= self.restart_seconds:
                        self.log.debug(
                            "Restarting %s watcher after %i seconds",
                            self.kind,
                            watch_duration,
                        )
                        break
            except ReadTimeoutError:
                # network read time out, just continue and restart the watch
                # this could be due to a network problem or just low activity
                self.log.warning(
                    "Read timeout watching %s, reconnecting", self.kind
                )
                continue
            except Exception:
                cur_delay = cur_delay * 2
                if cur_delay > 30:
                    self.log.exception(
                        "Watching resources never recovered, giving up"
                    )
                    if self.on_failure:
                        self.on_failure()
                    return
                self.log.exception(
                    "Error when watching resources, retrying in %ss", cur_delay
                )
                time.sleep(cur_delay)
                continue
            finally:
                w.stop()
                if self._stop_event.is_set():
                    self.log.info("%s watcher stopped", self.kind)
                    break
        self.log.warning("%s watcher finished", self.kind)

    def start(self):
        """
        Start the reflection process!

        We'll do a blocking read of all resources first, so that we don't
        race with any operations that are checking the state of the pod
        store - such as polls. This should be called only once at the
        start of program initialization (when the singleton is being created),
        and not afterwards!
        """
        if hasattr(self, "watch_thread"):
            raise ValueError(
                "Thread watching for resources is already running"
            )

        self._list_and_update()
        self.watch_thread = threading.Thread(target=self._watch_and_update)
        # If the watch_thread is only thread left alive, exit app
        self.watch_thread.daemon = True
        self.watch_thread.start()


class MultiNamespacePodReflector(MultiNamespaceReflector, PodReflector):
    list_method_name = "list_pod_for_all_namespaces"


class MultiNamespaceEventReflector(MultiNamespaceReflector, EventReflector):
    list_method_name = "list_event_for_all_namespaces"
