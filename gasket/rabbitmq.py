"""Module for connecting to a RabbitMQ server"""

import json
import logging
import threading
import time
import pika

from gasket import auth_app_utils
from gasket.work_item import L2LearnWorkItem, PortChangeWorkItem


class RabbitMQ(threading.Thread):
    """Thread that adds relevant Faucet events from a RabbitMQ server to 
    the work queue.
    """
    channel = None
    work_queue = None
    logger = None
    faucet_names = None

    def __init__(self, faucet_names, work_queue, logger_location):
        super().__init__()
        self.faucet_names = faucet_names
        self.work_queue = work_queue
        self.logger = auth_app_utils.get_logger('rabbitmq',
                                                logger_location,
                                                logging.DEBUG,
                                                1)
        self.logger.info('inited')

    def run(self):
        """Main run method. start_consuming() blocks 'forever'
        """
        try:
            self.logger.info("running")
            while True:
                try:
                    connection = pika.BlockingConnection(pika.ConnectionParameters(
                        host='172.222.0.104', port=5672))
                    break
                except Exception as e:
                    self.logger.info('cannot connect to rabbitmq server')
                    self.logger.exception(e)
                    time.sleep(1)
            self.channel = connection.channel()
            self.logger.info("channeled")
            self.channel.exchange_declare(exchange='topic_recs', exchange_type='topic')
            result = self.channel.queue_declare(exclusive=True)

            self.logger.info("declared")
            queue_name = result.method.queue
            self.channel.queue_bind(exchange='topic_recs', queue=queue_name,
                                    routing_key='FAUCET.Event')

            self.channel.basic_consume(self.callback, queue=queue_name, no_ack=True)
            self.logger.info('start consuming')
            self.channel.start_consuming()
        except Exception as e:
            self.logger.exception(e)

    def callback(self, chan, method, properties, body):
        """Callback method used by channel.basic_consume.
        See: http://pika.readthedocs.io/en/0.10.0/examples/blocking_consume.html?highlight=basic_consume
        """
        self.logger.info(' [x] %r:%r', method.routing_key, body)
        for line in body.splitlines():
            d = json.loads(line.decode())
            dp_id = d['dp_id']
            dp_name = d['dp_name']
            # Only process events from faucets gasket is managing.
            if dp_name in self.faucet_names:
                if 'PORT_CHANGE' in d:
                    pc = d['PORT_CHANGE']
                    port_no = pc['port_no']
                    reason = pc['reason']
                    status = pc['status']
                    self.work_queue.put(PortChangeWorkItem(dp_name, dp_id, port_no, reason, status))

                elif 'L2_LEARN' in d:
                    l2l = d['L2_LEARN']
                    port_no = l2l['port_no']
                    vid = l2l['vid']
                    eth_src = l2l['eth_src']
                    l3_src_ip = l2l['l3_src_ip']

                    self.work_queue.put(L2LearnWorkItem(dp_name, dp_id,
                                                        port_no, vid,
                                                        eth_src, l3_src_ip))

    def kill(self):
        self.channel.close()
