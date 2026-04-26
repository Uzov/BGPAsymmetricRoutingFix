__author__ = 'Юзов Евгений Борисович'

# coding:utf-8

import asyncio
import threading
import queue
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.carrier.asyncio.dgram import udp
import ipaddress
import logging
from typing import Dict, Any
from config import *

logger = logging.getLogger('script')
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ---- Создаем очередь для передачи данных ----
data_queue = queue.Queue()
data_queue.put(None)


# BGP Neighbor Finite State Machine, FSM
class BGPNeighborState:
    def __init__(self, name: str, trap_rcv_ip: ipaddress, trap_rcv_port: int, snmp_community: str):
        self.name = name  # Наименование устройства
        self.trap_rcv_ip = trap_rcv_ip
        self.trap_rcv_port = trap_rcv_port
        self.state = "Idle"
        self.states: Dict[str, str] = {"1": "Idle", "6": "Established"}
        self.snmp_community = snmp_community

    def snmp_trap_receiver(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        snmp_engine = engine.SnmpEngine()

        config.add_v1_system(snmp_engine, self.name, self.snmp_community)  # SNMP v2c community
        config.add_transport(snmp_engine, udp.DOMAIN_NAME,
                             udp.UdpTransport().open_server_mode((str(self.trap_rcv_ip), self.trap_rcv_port)))

        ntfrcv.NotificationReceiver(snmp_engine, self._trap_callback)

        logging.info(f"Старт прослушивания SNMP трапов на ip {self.trap_rcv_ip} udp порт {self.trap_rcv_port}")

        snmp_engine.transport_dispatcher.job_started(1)
        loop.run_forever()

    def _trap_callback(self, snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx) -> None:
        logging.info(f"Принят SNMP трап (сработала Callback функция):")
        traps: Dict[str, Any] = {}
        for oid, val in varBinds:
            traps[oid.prettyPrint()] = val.prettyPrint()
            logging.info(f"{oid.prettyPrint()} = {val.prettyPrint()}")
        data_queue.put(traps)


if __name__ == "__main__":
    bgp_neighbor = BGPNeighborState(FGTName, SMNPReceiverIP, SMNPReceiverIP, SNMPCommunity)

    # Запуск фонового потока для приёма трапов
    thread = threading.Thread(target=bgp_neighbor.snmp_trap_receiver, daemon=True)
    thread.start()

    # Основной поток
    while True:
        traps: Dict[str, Any] = data_queue.get()  # ждем данные из потока
        if traps is not None :
            neighbor: ipaddress = traps.get('1.3.6.1.2.1.15.3.1.7')
            state: str = traps.get('1.3.6.1.2.1.15.3.1.2')
            ''' 
            Если state = 1, то нужно disable все статические маршруты, добавленные ранее скриптом.
            # Если state = 6, то вышеназванные маршруты нужно перевести в состояние enable.
            # Дополнительно, при добавлении статических маршрутов в FortiGate, через API надо проверить состояние BGP
            сессии c Билайн.
            '''
            logging.info(f"SNMP трап получен о состоянии для BGP соседа {neighbor}.")
            logging.info(f"Состояние BGP сессии c {neighbor} изменилось на {bgp_neighbor.states.get(state)}.")
