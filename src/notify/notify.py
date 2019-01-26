from src.abstraction.interface import IFaceNotify
import logging
from src import config

logger = logging.getLogger("alertBot.notify")


class Notify(IFaceNotify):
    '''
    Bridge for all notification agents
    Actual class to be used when sending a notification
    '''

    def __init__(self, agent_name, config):
        # Register all agent classes from DownloadClientInterface
        self.config = config
        self._NOTIFY_AGENTS = {}
        for cls in IFaceNotify.__subclasses__():
            self._NOTIFY_AGENTS[cls.__name__.lower()] = cls
        self.agent = self._NOTIFY_AGENTS[agent_name.lower()](config)

    def send_alert(self, msg, title):
        return self.agent.send_alert(msg, title)


class Notification:
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

    def getNotifyConfig(self, agent_name):
        for agent in self.config.agents:
            if agent.name == agent_name:
                return agent

        logger.warning("No config for notify agent %s found", agent_name)
        return None

    def send_notification(self, message, title):
        # Send notification to all enabled notification agents
        agents = self.getEnabledNotifiers()
        for agent in agents:
            agentConf = self.getNotifyConfig(agent.name)

            if Notify(agent_name=agent.name, config=agentConf).send_alert(message, title):
                logger.info("Sent notification to %s", agent.name)
            else:
                logger.warning("Notification was not sent to %s", agent.name)

        return None
