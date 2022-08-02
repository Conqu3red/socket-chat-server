from typing import *
from enum import Enum

T = TypeVar("T")

class Emitter(Generic[T]):
    def __init__(self):
        self.event_handlers: Dict[T, Callable] = {}
    
    def dispatch_event(self, event_type: T, *args, **kwargs):
        if event_type in self.event_handlers:
            handler = self.event_handlers[event_type]
            if handler is not None:
                handler(*args, **kwargs)
    
    def register_handler(self, event_type: T, handler: Callable):
        self.event_handlers[event_type] = handler
