from main import *
import re

if __name__ == "__main__":
    fortigate200E = FortiGate(APIBaseURL, APIToken, FGTName)
    routines = Routines(fortigate200E)

    # Получаем с FortiGate список всех текущих статических маршрутов
    routes = routines.get_static_routes()
    # Получаем с FortiGate список "seq-num" всех добавленных статических маршрутов
    seq_nums = list(route["seq-num"] for route in routes
                    if re.match(r'^Added automatically by script', route["comment"]))
    for seq_num in seq_nums:
        # routines.change_static_route({'status': "enable"}, '/cmdb/router/static/', seq_num)
        routines.change_static_route({'status': "disable"}, '/cmdb/router/static/', seq_num)
