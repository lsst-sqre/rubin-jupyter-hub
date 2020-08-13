from .loggable import Loggable


class LoggableChild(Loggable):
    def __init__(self, *args, **kwargs):
        parent = kwargs.pop("parent", None)
        if not parent:
            es = "Child object must be passed parent at __init__()"
            raise ValueError(es)
        self.parent = parent
        super().__init__(*args, **kwargs)
