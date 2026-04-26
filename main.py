__author__ = 'Юзов Евгений Борисович'

# coding:utf-8

import os
import subprocess
from collections import defaultdict
import threading
import queue
import logging
import ipaddress
from ipaddress import IPv4Network, IPv6Network
from typing import List, Dict, Any
import requests
from datetime import datetime
from bgp_nbg_state import BGPNeighborState
from config import *

curr_dir = os.path.abspath(__file__).replace(os.path.basename(__file__), "")
os.chdir(curr_dir)
OS = os.name  # 'posix', 'nt', 'mac', 'os2', 'ce', 'java'.

logger = logging.getLogger('script')
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


class Whois:
    def __init__(self, org_id: str, timeout: int = 60):
        self.timeout = timeout
        self.org_id = org_id

    def _run_subprocess(self, cmd: List[str]) -> subprocess.CompletedProcess:

        logging.info(f"Запуск команды: {' '.join(cmd)}.")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=self.timeout, check=True
            )
        except FileNotFoundError:
            # raise RuntimeError("Команда 'whois или wsl' не найдена. Установите пакет whois.")
            logging.error("Команда 'whois или wsl' не найдена. Установите пакет whois.")
        except subprocess.TimeoutExpired:
            # raise RuntimeError("Тайм-аут при выполнении whois.")
            logging.error("Тайм-аут при выполнении whois.")
        except Exception as e:
            # raise RuntimeError(f"Не удалось выполнить whois: {e}.")
            logging.error(f"Не удалось выполнить whois: {e}.")

        if result.returncode != 0:
            logging.error(f"Whois вернул код {result.returncode}, stderr={result.stderr.strip()}.")
            # raise RuntimeError("Ошибка выполнения whois.")
            logging.error("Ошибка выполнения whois.")

        return result

    # Вызывает whois с таймаутом, возвращает stdout как список ASN для организации
    def get_asns_by_org(self) -> List[str]:
        if OS == "nt":
            cmd = ["wsl", "whois", "-h", "whois.ripe.net", "-T", "aut-num", "-i", "org", self.org_id]
        else:
            cmd = ["whois", "-h", "whois.ripe.net", "-T", "aut-num", "-i", "org", self.org_id]

        result = self._run_subprocess(cmd)

        if result.returncode == 0:
            asns: list = []
            for line in result.stdout.splitlines():
                if line.startswith("aut-num:"):
                    parts = line.split()
                    if len(parts) > 1:
                        asns.append(parts[1])

            logging.info(f"Для организации {self.org_id} получено {len(asns)} ASN.")

            return sorted(asns)
        else:
            return []

    # Вызывает whois с таймаутом, возвращает stdout как список префиксов по ASN через RADB
    def get_prefixes_by_asns_radb(self) -> List[Dict[ipaddress, str]]:
        ip_prefixes: List[Dict[ipaddress, str]] = []
        asns: List[str] = self.get_asns_by_org()

        for asn in asns:
            if OS == "nt":
                cmd = ["wsl", "whois", "-h", "whois.radb.net", "-i", "origin", asn]
            else:
                cmd = ["whois", "-h", "whois.radb.net", "-i", "origin", asn]

            result = self._run_subprocess(cmd)

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith(("route:", "route6:")):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip_prefixes.append({ipaddress.ip_network(parts[1]): asn})
        logging.info(f"Для организации {self.org_id} получено {len(ip_prefixes)} префиксов.")

        return ip_prefixes

    # Суммаризация префиксов
    def get_summarized_prefixes_by_asns_radb(self) -> Dict[str, List[ipaddress]]:
        prefixes_by_as_v4 = defaultdict(list)
        prefixes_by_as_v6 = defaultdict(list)
        ip_prefixes: List[Dict[IPv4Network | IPv6Network, str]] = self.get_prefixes_by_asns_radb()
        if len(ip_prefixes) > 0:
            # Сохраняется информация об ASN для комментария к добавленному статическому маршруту.
            for pref in ip_prefixes:
                try:
                    network, asn = next(iter(pref.items()))
                    (prefixes_by_as_v6 if network.version == 6 else prefixes_by_as_v4)[asn].append(network)
                except ValueError:
                    logging.warning("Неверный формат префикса: %s", pref)

            # В итоге используем только ipv4 префиксы. Суммаризированные префиксы в словаре группируются по ASN
            result: dict = {
                asn: list(ipaddress.collapse_addresses(networks))
                for asn, networks in prefixes_by_as_v4.items()
            }

            logging.info(f"Для организации {self.org_id} получено {len(ip_prefixes)} префиксов до суммаризации.")

            return result
        else:
            return {}


# CRUD
class FortiGate:
    def __init__(self, base_url: str, token: str, name: str, timeout: tuple = (5, 15)):
        self.base_url = base_url
        self.token = token
        self.timeout = timeout
        self.name = name  # Наименование устройства

    def get_read(self, cmdb_url: str) -> List[dict]:

        url = f"{self.base_url}{cmdb_url}"
        in_payload = {}
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json"
        }

        try:
            response = requests.request(
                "GET",
                url,
                headers=headers,
                data=in_payload,
                timeout=self.timeout,
                verify=False
            )

            response.raise_for_status()

        except requests.exceptions.ConnectTimeout:
            logging.error(f"Таймаут подключения к {self.name}.")
            return []
        except requests.exceptions.ReadTimeout:
            logging.error(f"Таймаут чтения ответа от {self.name}.")
            return []
        except requests.exceptions.ConnectionError as e:
            logging.error(f"Ошибка соединения c {self.name}: {e}.")
            return []
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP ошибка: {e}.")
            return []

        try:
            data = response.json()
        except ValueError:
            logging.error(f"Ответ {response} не является JSON.")
            return []
        if data.get("status") != "success":
            logging.error(f"FortiGate вернул ошибку: {data}.")
            return []

        return data.get("results", [])

    def post_create(self, in_payload: Dict[str, Any], cmdb_url: str) -> bool:
        url = f"{self.base_url}{cmdb_url}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.post(
                url,
                json=in_payload,
                headers=headers,
                timeout=self.timeout
            )

            response.raise_for_status()

        except requests.exceptions.ConnectTimeout:
            logging.error(f"Таймаут подключения к {self.name}.")
            return False
        except requests.exceptions.ReadTimeout:
            logging.error(f"Таймаут чтения ответа от {self.name}.")
            return False
        except requests.exceptions.ConnectionError as e:
            logging.error(f"Ошибка соединения c {self.name}: {e}.")
            return False
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP ошибка: {e}.")

        try:
            data = response.json()
        except ValueError:
            logging.error(f"Ответ {response} не является JSON.")
            return False

        if data.get("status") != "success":
            logging.debug(f"{self.name} вернул ошибку: {data}.")

        return data.get("revision_changed")

    def put_update(self, in_payload: Dict[str, Any], cmdb_url: str) -> bool:
        url = f"{self.base_url}{cmdb_url}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.put(
                url,
                json=in_payload,
                headers=headers,
                timeout=self.timeout
            )

            response.raise_for_status()

        except requests.exceptions.ConnectTimeout:
            logging.error(f"Таймаут подключения к {self.name}.")
            return False
        except requests.exceptions.ReadTimeout:
            logging.error(f"Таймаут чтения ответа от {self.name}.")
            return False
        except requests.exceptions.ConnectionError as e:
            logging.error(f"Ошибка соединения c {self.name}: {e}.")
            return False
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP ошибка: {e}.")

        try:
            data = response.json()
        except ValueError:
            logging.error(f"Ответ {response} не является JSON.")
            return False

        if data.get("status") != "success":
            logging.debug(f"{self.name} вернул ошибку: {data}.")

        return data.get("revision_changed")

    def delete_delete(self, cmdb_url: str) -> bool:
        url = f"{self.base_url}{cmdb_url}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.delete(
                url,
                headers=headers,
                timeout=self.timeout
            )

            response.raise_for_status()

        except requests.exceptions.ConnectTimeout:
            logging.error(f"Таймаут подключения к {self.name}.")
            return False
        except requests.exceptions.ReadTimeout:
            logging.error(f"Таймаут чтения ответа от {self.name}.")
            return False
        except requests.exceptions.ConnectionError as e:
            logging.error(f"Ошибка соединения c {self.name}: {e}.")
            return False
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP ошибка: {e}.")

        try:
            data = response.json()
        except ValueError:
            logging.error(f"Ответ {response} не является JSON.")
            return False

        if data.get("status") != "success":
            logging.debug(f"{self.name} вернул ошибку: {data}.")

        return data.get("revision_changed")


class Routines:
    def __init__(self, forti: FortiGate):
        self.forti = forti  # Сюда необходимо передать нужный экземпляр класса FortiGate

    # Получает список существующих статических маршрутов
    def get_static_routes(self, cmdb_url: str = '/cmdb/router/static/') -> List[dict]:
        results: List[dict] = self.forti.get_read(cmdb_url)
        logging.info(f"Получено {len(results)} static routes.")

        return results

    # Создаёт статические маршруты, если их ещё нет
    def add_static_route(self, in_payload: Dict[str, Any], cmdb_url: str = '/cmdb/router/static/') -> bool:

        keys = {"seq-num", "status", "dst", "gateway", "device", "comment"}
        filtered = {k: v for k, v in in_payload.items() if k in keys}

        if self.forti.post_create(in_payload, cmdb_url):
            logging.info(f"Маршрут {filtered} успешно добавлен.")
            return True
        else:
            logging.error(f"Маршрут {filtered} не удаётся добавить.")
            return False

            # Создаёт статические маршруты, если их ещё нет

    def change_static_route(self, in_payload: Dict[str, Any], cmdb_url: str = '/cmdb/router/static/',
                            in_seq_num: int = 0) -> None:

        cmdb_url = f"{cmdb_url}/{in_seq_num}"

        if in_seq_num != 0:
            if self.forti.put_update(in_payload, cmdb_url):
                logging.info(f"Параметр {list(in_payload.keys())[0]} маршрута номер {in_seq_num} успешно изменён.")
            else:
                logging.error(f"Маршрут {in_seq_num} не удаётся изменить.")
        else:
            logging.error(f"Для изменения маршрута задайте его номер (seq-num) в параметрах. Номер маршрута "
                          f"не д.б. равен нулю.")

    def delete_static_route(self, cmdb_url: str = '/cmdb/router/static/', in_seq_num: int = 0) -> None:

        cmdb_url = f"{cmdb_url}/{in_seq_num}"

        if in_seq_num != 0:
            if self.forti.delete_delete(cmdb_url):
                logging.info(f"Маршрут номер {in_seq_num} успешно удалён.")
            else:
                logging.error(f"Маршрут {in_seq_num} не удаётся удалить.")
        else:
            logging.error(f"Для удаления маршрута задайте его номер (seq-num) в параметрах. Номер маршрута "
                          f"не д.б. равен нулю.")

    def get_bgp_neighbor_state(self, neighbor_ip: ipaddress,
                               cmdb_url: str = '/monitor/router/bgp/neighbors/') -> Dict | None:
        results: List[dict] = self.forti.get_read(cmdb_url)
        logging.info(f"Получена информация о {len(results)} текущих BGP соседях (neighbors).")

        result = next(
            (item for item in results if item["neighbor_ip"] == neighbor_ip), None)

        return result


# Для запуска напрямую
if __name__ == "__main__":
    vimpelcom = Whois(RIPE_ORG)
    fortigate200E = FortiGate(APIBaseURL, APIToken, FGTName)
    routines = Routines(fortigate200E)

    # Получаем сгруппированный по ASN "словарь списков" префиксов из RADB для Билайна
    prefixes = vimpelcom.get_summarized_prefixes_by_asns_radb()

    # Получаем с FortiGate список всех текущих статических маршрутов
    routes = routines.get_static_routes()
    # Получаем с FortiGate список "seq-num" всех текущих статических маршрутов (чтобы не повторялись)
    seq_nums = list(route["seq-num"] for route in routes)

    # Запуск приёмника SNMP трапов о состоянии BGP соседей
    # bgp_neighbor = BGPNeighborState(FGTName, SMNPReceiverIP, SMNPReceiverIP, SNMPCommunity)

    # Запуск фонового процесса для приёма трапов
    # thread = threading.Thread(target=bgp_neighbor.snmp_trap_receiver, daemon=True)
    # thread.start()

    # Проверяем состояние BGP соседа 213.221.2.209, т.е. Билайна
    neighbor: str = routines.get_bgp_neighbor_state(BGPNeighbor).get("state")
    if neighbor == "Established":
        status = "enable"
    else:
        status = "disable"

    # Здесь записываем статические маршруты в FortiGate
    seq_num: int = 1
    for asn, prefixes in prefixes.items():
        for prefix in prefixes:
            # Генерируем несуществующие seq-num с проверкой
            while seq_num in seq_nums:
                seq_num += 1
                if seq_num > FGTMaxStaticRoutes:  # Предел чтобы не зациклилось
                    break

            payload = {
                "seq-num": seq_num,
                "status": status,
                "dst": str(prefix),
                "src": "0.0.0.0 0.0.0.0",
                "gateway": BGPNeighbor,
                "device": BGPNeighborPort,
                "comment": f"{ScriptComment} on {datetime.now().strftime('%d-%m-%Y at %H:%M:%S')} (arrived from {asn}).",
                "sdwan": "disable",
                "vrf": 0
            }
            if routines.add_static_route(payload):
                seq_num += 1

    #######################################################################################################################
    '''vimpelcom = Whois(ORG)
    for itm in vimpelcom.get_summarized_prefixes_by_asns_radb():
        print(itm)
    
    fortigate200E = FortiGate(APIBaseURL, APIToken, FGTName)
    routines = Routines(fortigate200E)

    data = routines.get_static_routes()
    print(data, sep=' ,')
    seq_nums = list(route["seq-num"] for route in data)
    print(seq_nums, sep=' ,')
    '''
    '''    
    payload = {
        "seq-num": 11,
        "status": "enable",
        "dst": "10.110.0.0/24",
        "src": "0.0.0.0 0.0.0.0",
        "gateway": "192.168.30.1",
        "device": "port1",
        "comment": f"Added by automatic script on {datetime.now().strftime('%d-%m-%Y at %H:%M:%S')}.",
        "sdwan": "disable",
        "vrf": 0
    }
    fortigate200E.add_static_route(payload)'''

    '''    beeline_prefixes = run_whois(LASN)
    #    print("\n".join(str(net) for net in beeline_prefixes))
    routes = get_static_routes()
    for route in routes:
        print(
            route.get("seq-num"),
            route.get("dst"),
            route.get("gateway"),
            route.get("status")
        )
    # автономные системы Билайн (Вымпелком)
    LASN = (
        8773, 8755, 8563, 8402, 8371, 8350, 49144, 43970, 43687, 43275, 42842, 42245, 42110, 34894, 34747, 34644, 34038,
        3253, 3235, 3216, 31425, 31359, 29125, 28703, 2766, 2599, 21483, 21480, 21332, 20597, 20533, 16345, 16043,
        13257, 13095, 12543)

    beeline_prefixes = [
        '195.209.160.0/20',
        '195.218.128.0/17',
        '195.222.160.0/19',
        '195.239.0.0/16',
        '200.33.114.0/24',
        '212.23.64.0/19',
        '212.44.128.0/19',
        '212.46.192.0/18',
        '212.92.128.0/18',
        '212.119.192.0/18',
        '213.33.128.0/17',
        '213.132.64.0/19',
        '213.140.96.0/19',
        '213.142.192.0/19',
        '213.150.64.0/19',
        '213.191.0.0/19',
        '213.221.0.0/18',
        '213.234.192.0/18',
        '213.242.192.0/18'
    ]'''
