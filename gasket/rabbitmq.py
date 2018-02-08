import datetime
import json
import logging
import socket
import threading
import time

import pika

from gasket import auth_app_utils
from gasket.work_item import L2LearnWorkItem, PortChangeWorkItem

class RabbitMQ(threading.Thread):

    work_queue = None

    def __init__(self, work_queue, logger_location):
        super().__init__()
        self.work_queue = work_queue
        self.logger = auth_app_utils.get_logger('rabbitmq',
                                                logger_location,
                                                logging.DEBUG,
                                                1)
        self.logger.info('inited')

    def run(self):
        try:
            self.logger.info("running")
            while True:
                try:
                    connection = pika.BlockingConnection(pika.ConnectionParameters(
                        host='172.222.0.104', port=5672))
                    break
                except Exception as e:
                    self.logger.info('cannot connect to rabbitmq server')
                    time.sleep(1)
            channel = connection.channel()
            self.logger.info("channeled")
            channel.exchange_declare(exchange='topic_recs', exchange_type='topic')
            result = channel.queue_declare(exclusive=True)

            self.logger.info("declared")
            queue_name = result.method.queue
            channel.queue_bind(exchange='topic_recs', queue=queue_name, routing_key='FAUCET.Event')

            channel.basic_consume(self.callback, queue=queue_name, no_ack=True)
            self.logger.info('start consuming')
            channel.start_consuming()
        except Exception as e:
            self.logger.exception(e)

    def callback(self, chan, method, properties, body):
        self.logger.info(' [x] %r:%r', method.routing_key, body)
        for line in body.splitlines():
            d = json.loads(line.decode())
            dp_id = d['dp_id']
            dp_name = d['dp_name']
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

                self.work_queue.put(L2LearnWorkItem(dp_name,dp_id,
                                                    port_no, vid,
                                                    eth_src, l3_src_ip))
