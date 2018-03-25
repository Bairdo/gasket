
import logging

from gasket import gasket_conf
from gasket.gasket_conf_utils import validate_port, get_log_level


class FaucetConf(gasket_conf.GasketConf):
    url = None
    port = None
    logger_level = None
    sleep_period = None


    defaults = {
        'url' : None,
        'port' : 5672,
        'logger_level' : logging.INFO,
        'sleep_period' : 5,
    }

    defaults_types = {
        'url' : str,
        'port' : int,
        'logger_level' : (str, int),
        'sleep_period' : int,
    }

    def check_config(self):
        if self.port:
            validate_port(self.port)

        self.logger_level = get_log_level(self.logger_level)

