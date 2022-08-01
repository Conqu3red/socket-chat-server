from threading import Lock
from contextlib import contextmanager
from typing import *


LOCKED_RESOURCES: Dict[str, Lock] = {}


@contextmanager
def locked_resource(filename: str):
    if filename not in LOCKED_RESOURCES:
        LOCKED_RESOURCES[filename] = Lock()
    
    with LOCKED_RESOURCES[filename]:
        yield