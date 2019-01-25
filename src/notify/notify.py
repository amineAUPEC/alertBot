from abc import ABCMeta, abstractmethod
import logging
from src import config

logger = logging.getLogger("alertBot.notify")


class NotifyModel:
    ''' Not in use! '''
    interface = None
    alertname = None
    src = None
    src_p = None
    dst = None
    dst_p = None
    proto = None
    class_name = None
    alert_time = None

    def __str__(self):
        formatted = """Interface: %s
Name: %s
Src: %s
Src_p: %s
Dst: %s
Dst_p: %s
Proto: %s
Class: %s
Time: %s
        """ % (self.interface, self.alertname, self.src, self.src_p,
               self.dst, self.dst_p, self.proto,
               self.class_name, self.alert_time)
        return formatted


class NotifyInterface:
    __metaclass__ = ABCMeta
    '''Interface for sending notifications'''

    @abstractmethod
    def sendalert(self, msg, title):
        '''Send notification on grabbed nzb for a job'''
        raise NotImplemented


class Notify(NotifyInterface):
    '''
    Bridge for all notification agents
    Actual class to be used when sending a notification
    '''

    def __init__(self, agent_name, config):
        # Register all agent classes from DownloadClientInterface
        self.config = config
        self._NOTIFY_AGENTS = {}
        for cls in NotifyInterface.__subclasses__():
            self._NOTIFY_AGENTS[cls.__name__.lower()] = cls
        self.agent = self._NOTIFY_AGENTS[agent_name.lower()](config)

    def sendalert(self, msg, title):
        return self.agent.sendalert(msg, title)


class SendNotification:
    def __init__(self):
        self.config = config.notify

    def getEnabledNotifiers(self):
        enabled = []
        if self.config.enabled:

            for agent in self.config.agents:
                if agent.enabled:
                    enabled.append(agent)

        if not enabled:
            logger.warning("No enabled Notifier(s) found")
            return None

        return enabled

    def getNotifyConfig(self, agentName):
        for agent in self.config.agents:
            if agent.name == agentName:
                return agent

        logger.warning("No config for notify agent %s found", agentName)
        return None

    def send_notification(self, message, title):
        # Send notification to all enabled notification agents
        agents = self.getEnabledNotifiers()
        for agent in agents:
            agentConf = self.getNotifyConfig(agent.name)

            if Notify(agent_name=agent.name, config=agentConf).sendalert(message, title):
                logger.info("Sent notification to %s", agent.name)
            else:
                logger.warning("Notification was not sent to %s", agent.name)

        return None
