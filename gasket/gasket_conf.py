"""Override of faucet.Conf
"""

from faucet.conf import Conf

class GasketConf(Conf):
    """Overrides faucet.conf so that the dpid is always 0
    """
    def __init__(self, _id, conf):
        super().__init__(_id, 0, conf)

    def set_defaults(self):
        super().set_defaults()
