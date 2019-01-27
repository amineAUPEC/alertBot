from src.abstraction.interface import IFaceNotify
import logging
from src import config

logger = logging.getLogger("alertBot.notify")


class Notify(IFaceNotify):
    """
    Bridge for all notification agents
    Actual class to be used when sending a notification

    TODO: this class is not really needed and could be integrated in class Notification..
    """

    def __init__(self, agent_name, agent_conf):
        # Register all agent classes from IFaceNotify
        # self.config = agent_conf
        self._NOTIFY_AGENTS = {}
        for cls in IFaceNotify.__subclasses__():
            self._NOTIFY_AGENTS[cls.__name__.lower()] = cls
        self.agent = self._NOTIFY_AGENTS[agent_name.lower()](agent_conf)

    def send_alert(self, msg, title) -> bool:
        return self.agent.send_alert(msg, title)


class Notification:
    def __init__(self):
        self.notify_config = config.notify

    def _get_enabled_notifiers(self):
        enabled_agents = []
        if self.notify_config.enabled:
            for agent in self.notify_config.agents:
                if agent.enabled:
                    enabled_agents.append(agent)

        if not enabled_agents:
            logger.warning("No enabled Notifier(s) found")
            return None

        return enabled_agents

    def _get_notify_config(self, agent_name):
        for agent_config in self.notify_config.agents:
            if agent_config.name == agent_name:
                # Add 'blackListedFields' to the agent config.. Nasty but ok for now..
                # 'agent_config' is a Munch object which has the '.update()' attribute.
                agent_config.update(blackListedFields=self.notify_config.blackListedFields)
                return agent_config

        logger.warning("No config for notify agent %s found", agent_name)
        return None

    def send_notification(self, message, title: str) -> None:
        # Send notification to all enabled notification agents
        agents = self._get_enabled_notifiers()
        for agent in agents:
            agent_conf = self._get_notify_config(agent.name)
            if Notify(agent_name=agent.name, agent_conf=agent_conf).send_alert(message, title):
                logger.info("Sent notification to %s", agent.name)
            else:
                logger.warning("Notification was not sent to %s", agent.name)

        # This function have not reason to return anything at the moment..
        return None
