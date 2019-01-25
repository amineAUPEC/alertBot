from abc import ABCMeta, abstractmethod


class IFaceNotify:
    __metaclass__ = ABCMeta
    '''Interface for sending notifications'''

    @abstractmethod
    def send_alert(self, msg, title):
        '''Send notification on grabbed nzb for a job'''
        raise NotImplemented
