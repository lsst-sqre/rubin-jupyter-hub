from rubin_jupyter_utils.helpers import make_logger


class Loggable(object):
    def __init__(self, *args, **kwargs):
        self.log = make_logger()
        self.log.debug("Creating {}".format(self.__class__.__name__))
