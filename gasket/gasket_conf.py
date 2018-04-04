"""Override of faucet.Conf
"""

from faucet.conf import Conf

class GasketConf(Conf):
    """Overrides faucet.conf so that the dpid is always 0
    """
    def __init__(self, _id, conf, dpid=0):
        super().__init__(_id, dpid, conf)
