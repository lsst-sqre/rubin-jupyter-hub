"""The RubinMiddleManager is the only exported class: all the managers that
actually manage things report to it.
"""
from .middlemanager import RubinMiddleManager

__all__ = [RubinMiddleManager]
