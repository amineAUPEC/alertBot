from dataclasses import dataclass


@dataclass
class Alert:
    """ Model/Dataclass used to 'store' parsed alerts

        Why? Because some parsed alert fields are expected to exist and is used in multiple places in the code base.
        Persistence is key.
        We also get nice error messages whenever at mandatory field is missing.
        Oh! and intellisense!

    """
    def __init__(self, time: str, name: str, src: str, dest: str, src_port: int = 0, dest_port: int = 0, **kwargs):
        # Mandatory fields
        self.time = time
        self.name = name
        self.src = src
        self.src_port = src_port
        self.dest = dest
        self.dest_port = dest_port

        # Set fields that is received in kwargs, but not mandatory. These fields do not get 'intellisense'
        for field_name, field_value in kwargs.items():
            self.__setattr__(field_name, field_value)

    def __repr__(self):
        # Auto generate the __repr__ with all available fields
        rep = ", ".join(f"{field_name}={repr(value)}" for field_name, value in self.__dict__.items())
        return f"AlertModel({rep})"


@dataclass
class SensorConfig:
    """ Model/Dataclass for sensor configs

        Why? 'guaranteed' fields/attrs and intellisense

    """
    def __init__(self, name: str, enabled: bool, sensorType: str, logType: str, logSourceType: str, interface: str, **kwargs):
        # Mandatory fields
        self.name = name
        self.enabled = enabled
        self.sensorType = sensorType
        self.logType = logType
        self.logSourceType = logSourceType
        self.interface = interface

        # Set fields that is received in kwargs, but not mandatory. These fields do not get 'intellisense'
        for field_name, field_value in kwargs.items():
            self.__setattr__(field_name, field_value)

    def __repr__(self):
        # Auto generate the __repr__ with all available fields
        rep = ", ".join(f"{field_name}={repr(value)}" for field_name, value in self.__dict__.items())
        return f"SensorConfig({rep})"

