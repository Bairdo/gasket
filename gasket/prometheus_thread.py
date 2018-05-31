
import logging
import re
import threading
import time

from gasket import auth_app_utils
from gasket import work_item


LEARNED_MACS_REGEX = r"""learned_macs{dp_id="(0x[a-f0-9]+)",dp_name="([\w-]+)",n="(\d+)",port="(\d+)",vlan="(\d+)"}"""


class Prometheus(threading.Thread):
    """Thread that periodically queries Faucet's Prometheus, for mac learning.
    The consequence of missing an L2Learn event from rabbitmq is that the host will not be learnt until another event is sent.
    Which may not happen for several minutes (and therefore authentication cannot fully complete).
    
    There is the possibility that we'll receive two events for the same learning (one from prometheus & one from rabbitmq).
    If the events are the same (same port etc), it does not matter.
    If the events are different (different port), the order of learning may get wacky.
    """

    stop = False
    work_queue = None
    logger = None
    server_url = None
    server_port = None
    sleep_period = None
    learned_macs_compiled_regex = None

    def __init__(self, work_queue, logger_location, url, port, sleep_period):
        super().__init__()
        self.work_queue = work_queue
        self.logger = auth_app_utils.get_logger('prometheus-importer',
                                                logger_location,
                                                logging.DEBUG,
                                                1)
        self.server_url = url
        self.server_port = port
        self.sleep_period = sleep_period
        self.learned_macs_compiled_regex = re.compile(LEARNED_MACS_REGEX)

    def run(self):
        """Main run method."""
        while not self.stop:
            self.get_prometheus_mac_learning()
            time.sleep(self.sleep_period)

    def get_prometheus_mac_learning(self):
        """Queries the Prometheus faucet client,
        And creates L2Learn work for macs already learnt.
        """
        # query faucets promethues.
        self.logger.info('querying Prometheus for "learned_macs"')
        try:
            prom_mac_table = auth_app_utils.scrape_prometheus_vars(self.server_url,
                                                                   ['learned_macs'])[0]
        except Exception as e:
            self.logger.exception(e)
            return
        self.logger.debug('queried Prometheus. mac_table:\n%s\n',
                          prom_mac_table)

        for line in prom_mac_table:
            labels, float_as_mac = line.split(' ')
            macstr = auth_app_utils.float_to_mac(float_as_mac)
            self.logger.debug('float %s is mac %s', float_as_mac, macstr)

            values = self.learned_macs_compiled_regex.match(labels)
            dpid, dp_name, n, port, vlan = values.groups()
            self.work_queue.put(work_item.L2LearnWorkItem(dp_name, int(dpid, 16),
                                                          int(port), int(vlan), macstr, None))
    def kill(self):
        self.stop = True
