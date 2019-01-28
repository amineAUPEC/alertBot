from abc import ABCMeta, abstractmethod


class IFaceNotify:
    __metaclass__ = ABCMeta
    """ Interface for sending notifications that all notification agents must follow """

    @abstractmethod
    def send_alert(self, msg, title: str) -> bool:
        """ Send a notification abstractmethod """
        # msg should only be str or dict
        raise NotImplemented
