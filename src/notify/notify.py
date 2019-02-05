from src.abstraction.interface import IFaceNotify
import logging

logger = logging.getLogger("alertBot.notify")


class Notification(IFaceNotify):
    """
        Bridge for all notification agents
        Actual class to be used when sending a notification
        """

    def __init__(self, config):
        self.notify_config = config  # Notify config
        self.enabled_agents = self._get_enabled_notifiers()  # List of all enabled agent configs
        # Registers all notification classes {agent_name: cls_obj}
        self.NOTIFY_AGENTS = dict()
        for cls in IFaceNotify.__subclasses__():
            self.NOTIFY_AGENTS[cls.__name__.lower()] = cls

    def _get_enabled_notifiers(self) -> list:
        # Generates a list(of config) of all enabled notify agents
        enabled_agents = []
        if self.notify_config.enabled:
            for agent in self.notify_config.agents:
                if agent.enabled:
                    # Injects 'blackListedFields' to the agent config.. Nasty but ok for now..
                    # 'agent_config' is a Munch object which has the '.update()' attribute.
                    agent.update(blackListedFields=self.notify_config.blackListedFields)
                    enabled_agents.append(agent)

        if not enabled_agents:
            logger.warning("No enabled Notifier(s) found")
            return []

        return enabled_agents

    def send_notification(self, message, title: str) -> None:
        if not self.enabled_agents:
            logger.warning("No notification agents enabled..")
            return None

        for _agent in self.enabled_agents:
            agent = self.NOTIFY_AGENTS[_agent.name](_agent)  # _agent = notify agent config object
            if agent.send_notification(message, title):
                logger.info("Sent notification to %s", _agent.name)
            else:
                logger.warning("Notification was not sent to %s", _agent.name)

        # This function have no reason to return anything at the moment..
        return None
