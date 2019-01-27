from abc import ABCMeta, abstractmethod


class IFaceNotify:
    __metaclass__ = ABCMeta
    '''Interface for sending notifications'''

    @abstractmethod
    def send_alert(self, msg, title: str) -> bool:
        ''' Send notification on grabbed nzb for a job '''
        # msg should only be str or dict
        raise NotImplemented
