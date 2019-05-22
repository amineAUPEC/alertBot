from abc import ABCMeta, abstractmethod


class IFaceNotify:
    __metaclass__ = ABCMeta
    """ Interface for sending notifications that all notification agents must follow """

    @abstractmethod
    def send_notification(self, msg, title: str) -> bool:
        """ Send a notification abstractmethod """
        # msg should only be str or dict
        raise NotImplemented


class IFaceSensor:
    """ Base class for all sensors """
    __metaclass__ = ABCMeta
    @abstractmethod
    def __init__(self, sensor_config, *args, **kwargs):
        # No need to actual run super() on this one.. Just created to describe classes using this IFace
        raise NotImplemented


class IFaceHTTPSource(IFaceSensor):
    """ Interface all Sensors using HTTP as log source """
    __metaclass__ = ABCMeta

    @abstractmethod
    def search(self, *args):
        raise NotImplemented
