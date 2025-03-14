#!/usr/bin/env python3
"""
aiosdwan: Asynchronous Python client for Cisco Catalyst SD-WAN (vManage).

Example usage:
    import asyncio
    from aiosdwan import connect, get_devices

    async def main():
        vmanage = await connect(
            host="vmanage.example.com",
            username="admin",
            password="secret",
            verify=False
        )
        devices = await get_devices(vmanage)
        print("Devices:", devices)

    asyncio.run(main())
"""

import asyncio
import json
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Any, Dict, List, Optional

import httpx


@dataclass
class DeviceData:
    """
    Represents high-level information about a Cisco Catalyst SD-WAN device.
    """
    uuid: str
    persona: str
    system_ip: Optional[IPv4Address]
    hostname: Optional[str]
    site_id: Optional[int]
    model: Optional[str]
    version: Optional[str]
    template_id: Optional[str]
    template_name: Optional[str]
    is_managed: bool
    is_valid: bool
    is_sync: bool
    is_reachable: bool
    raw_data: Dict[str, Any]
    latitude: float = 0.0
    longitude: float = 0.0


@dataclass
class InterfaceData:
    """
    Represents interface information for a device.
    """
    if_name: str
    if_desc: str
    if_type: str
    if_mac: str
    vpn_id: str
    ip: IPv4Address
    network: IPv4Network
    raw_data: Dict[str, Any]


@dataclass
class VrrpData:
    """
    Represents VRRP (Virtual Router Redundancy Protocol) configuration on a device.
    """
    if_name: str
    group: int
    priority: int
    preempt: bool
    master: bool
    ip: IPv4Address
    raw_data: Dict[str, Any]


@dataclass
class TlocData:
    """
    Represents TLOC (Transport Locator) information used in SD-WAN for data forwarding.
    """
    site_id: int
    system_ip: IPv4Address
    private_ip: IPv4Address
    public_ip: IPv4Address
    preference: int
    weight: int
    encapsulation: str
    color: str
    raw_data: Dict[str, Any]


class Vmanage:
    """
    Asynchronous client for Cisco Catalyst SD-WAN (vManage).

    Does NOT handle login automatically. Use `connect(...)` to create
    and authenticate an instance of this class.
    """

    def __init__(
        self,
        host: str,
        verify: bool = False,
        port: int = 443,
        semaphore: int = 40,
        debug: bool = False
    ):
        """
        Constructor for Vmanage. Does NOT authenticate on its own;
        call 'connect(...)' to obtain a ready-to-use instance.
        """
        self.host = host
        self.port = port
        self.verify = verify
        self.semaphore = semaphore
        self._debug = debug

        # These will be set by connect() after successful login
        self.base_url: Optional[str] = None
        self.session: Optional[httpx.AsyncClient] = None
        self.headers: Optional[Dict[str, Any]] = None

    async def __get(self, path: str, params: Dict[str, Any] = None) -> Optional[str]:
        """
        Internal helper for asynchronous GET requests.
        """
        if not self.session or not self.base_url or not self.headers:
            return None
        params = params or {}
        try:
            response = await self.session.get(
                url=f"{self.base_url}{path}",
                headers=self.headers,
                params=params,
                timeout=None
            )
            return response.text if response.status_code == 200 else None
        except httpx.HTTPError as exc:
            raise ConnectionError(f"ConnectionError on GET {path}: {exc}") from exc

    async def __post(
        self,
        path: str,
        params: Dict[str, Any] = None,
        data: Dict[str, Any] = None
    ) -> Optional[str]:
        """
        Internal helper for asynchronous POST requests.
        """
        if not self.session or not self.base_url or not self.headers:
            return None
        params = params or {}
        data = data or {}
        try:
            response = await self.session.post(
                url=f"{self.base_url}{path}",
                headers=self.headers,
                params=params,
                data=json.dumps(data),
                timeout=None
            )
            return response.text if response.status_code == 200 else None
        except httpx.HTTPError as exc:
            raise ConnectionError(f"ConnectionError on POST {path}: {exc}") from exc

    async def __put(
        self,
        path: str,
        params: Dict[str, Any] = None,
        data: Dict[str, Any] = None
    ) -> Optional[str]:
        """
        Internal helper for asynchronous PUT requests.
        """
        if not self.session or not self.base_url or not self.headers:
            return None
        params = params or {}
        data = data or {}
        try:
            response = await self.session.put(
                url=f"{self.base_url}{path}",
                headers=self.headers,
                params=params,
                data=json.dumps(data),
                timeout=None
            )
            return response.text if response.status_code == 200 else None
        except httpx.HTTPError as exc:
            raise ConnectionError(f"ConnectionError on PUT {path}: {exc}") from exc

    async def __delete(
        self,
        path: str,
        params: Dict[str, Any] = None
    ) -> Optional[str]:
        """
        Internal helper for asynchronous DELETE requests.
        """
        if not self.session or not self.base_url or not self.headers:
            return None
        params = params or {}
        try:
            response = await self.session.delete(
                url=f"{self.base_url}{path}",
                headers=self.headers,
                params=params,
                timeout=None
            )
            return response.text if response.status_code == 200 else None
        except httpx.HTTPError as exc:
            raise ConnectionError(f"ConnectionError on DELETE {path}: {exc}") from exc

    async def get(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[List[Dict[str, Any]]]:
        """
        Public asynchronous GET. Returns JSON 'data' array if present.
        """
        result = await self.__get(endpoint, params=params)
        if not result:
            return None
        try:
            return json.loads(result).get("data")
        except json.JSONDecodeError:
            return None

    async def post(
        self,
        endpoint: str,
        params: Dict[str, Any] = None,
        data: Dict[str, Any] = None
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Public asynchronous POST. Returns JSON 'data' array if present.
        """
        result = await self.__post(endpoint, params=params, data=data)
        if not result:
            return None
        try:
            return json.loads(result).get("data")
        except json.JSONDecodeError:
            return None

    async def put(
        self,
        endpoint: str,
        params: Dict[str, Any] = None,
        data: Dict[str, Any] = None
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Public asynchronous PUT. Returns JSON 'data' array if present.
        """
        result = await self.__put(endpoint, params=params, data=data)
        if not result:
            return None
        try:
            return json.loads(result).get("data")
        except json.JSONDecodeError:
            return None

    async def delete(
        self,
        endpoint: str,
        params: Dict[str, Any] = None
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Public asynchronous DELETE. Returns JSON 'data' array if present.
        """
        result = await self.__delete(endpoint, params=params)
        if not result:
            return None
        try:
            return json.loads(result).get("data")
        except json.JSONDecodeError:
            return None

    async def get_all(self, tasks: List[Any]) -> List[Any]:
        """
        Execute multiple coroutines concurrently, respecting a semaphore limit.

        Args:
            tasks: A list of coroutine objects (e.g., [self.get('/endpoint'), ...]).

        Returns:
            A list of results from each task, in the same order.
        """
        sem = asyncio.Semaphore(self.semaphore)

        async def sem_task(task):
            async with sem:
                return await task

        return await asyncio.gather(*(sem_task(t) for t in tasks))


async def connect(
    host: str,
    username: str,
    password: str,
    verify: bool = False,
    port: int = 443,
    semaphore: int = 40,
    debug: bool = False
) -> Vmanage:
    """
    Create and return an authenticated Vmanage instance using async logic.

    Example:
        vmanage = await connect("vmanage.example.com", "admin", "secret", verify=False)

    Raises:
        ConnectionError: if the login process fails.
    """
    vmanage = Vmanage(host, verify, port, semaphore, debug)

    base_url = f"https://{host}:{port}"
    async with httpx.AsyncClient(verify=verify) as client:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"j_username": username, "j_password": password}

        try:
            login_resp = await client.post(f"{base_url}/j_security_check", data=data, headers=headers)
        except httpx.HTTPError as exc:
            raise ConnectionError(f"ConnectionError during login: {exc}") from exc

        # Check if login succeeded (status=200, not the HTML login page)
        if login_resp.status_code == 200 and not login_resp.text.startswith("<html>"):
            set_cookie = login_resp.headers.get("Set-Cookie", "")
            if not set_cookie:
                raise ConnectionError("No session cookie in login response")

            cookie = set_cookie.split(";")[0]
            vmanage.headers = {
                "Content-Type": "application/json",
                "Cookie": cookie
            }

            # Fetch CSRF token
            try:
                token_resp = await client.get(f"{base_url}/dataservice/client/token", headers=vmanage.headers)
            except httpx.HTTPError as exc:
                raise ConnectionError(f"ConnectionError fetching CSRF token: {exc}") from exc

            if token_resp.status_code == 200:
                vmanage.headers["X-XSRF-TOKEN"] = token_resp.text.strip()
                vmanage.base_url = f"{base_url}/dataservice"
                vmanage.session = httpx.AsyncClient(verify=verify)
                return vmanage

        raise ConnectionError("Failed to authenticate to vManage.")


#
# Helper function for safe integer conversion
#
def _safe_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


#
# External helper functions that operate on a Vmanage object
#


async def get_devices(vmanage: Vmanage) -> Dict[str, DeviceData]:
    """
    Fetch and consolidate device information (controllers, vEdges, statuses).
    """
    tasks = [
        vmanage.get("/system/device/controllers"),
        vmanage.get("/system/device/vedges"),
        vmanage.get("/device")
    ]
    results = await vmanage.get_all(tasks)
    if not all(results):
        return {}

    controllers_raw, vedges_raw, status_raw = results
    controllers = {item["uuid"]: item for item in controllers_raw}
    vedges = {item["uuid"]: item for item in vedges_raw}
    statuses = {item["uuid"]: item for item in status_raw}

    # Merge controllers and vedges
    merged = controllers | vedges

    # Merge status by UUID
    for uuid_key in merged:
        if uuid_key in statuses:
            merged[uuid_key] = {**merged[uuid_key], **statuses[uuid_key]}

    devices: Dict[str, DeviceData] = {}
    for uuid_key, info in merged.items():
        system_ip = info.get("system-ip")
        device_obj = DeviceData(
            uuid=info["uuid"],
            persona=info.get("personality", ""),
            system_ip=IPv4Address(system_ip) if system_ip else None,
            hostname=info.get("host-name"),
            site_id=_safe_int(info.get("site-id")),
            model=info.get("deviceModel", "").replace("vedge-", "").replace("cloud", "vbond"),
            version=info.get("version"),
            template_id=info.get("templateId"),
            template_name=info.get("template"),
            is_managed=("managed-by" in info and info["managed-by"] != "Unmanaged"),
            is_valid=(info.get("validity") == "valid"),
            is_sync=(info.get("configStatusMessage") == "In Sync"),
            is_reachable=(info.get("reachability") == "reachable"),
            latitude=float(info.get("latitude", 0.0)),
            longitude=float(info.get("longitude", 0.0)),
            raw_data=info
        )
        devices[uuid_key] = device_obj

    return devices


async def get_device_interfaces(vmanage: Vmanage, device: DeviceData) -> Optional[List[InterfaceData]]:
    """
    Retrieve interface details for a given device.
    """
    if not device.system_ip:
        return None
    raw_data = await vmanage.get("/device/interface/synced", {"deviceId": str(device.system_ip)})
    if not raw_data:
        return None

    interfaces = []
    for iface in raw_data:
        try:
            ip_str = iface["ip-address"]
            mask = iface["ipv4-subnet-mask"]
            interfaces.append(
                InterfaceData(
                    if_name=iface["ifname"],
                    if_desc=iface.get("description", "N/A"),
                    if_type=iface["interface-type"],
                    if_mac=iface["hwaddr"],
                    vpn_id=str(iface["vpn-id"]),
                    ip=IPv4Address(ip_str),
                    network=IPv4Network(f"{ip_str}/{mask}", strict=False),
                    raw_data=iface
                )
            )
        except KeyError:
            continue
    return interfaces


async def get_device_tlocs(vmanage: Vmanage, device: DeviceData) -> Optional[List[TlocData]]:
    """
    Retrieve TLOC (Transport Locator) information for a given device.
    """
    if not device.system_ip:
        return None
    raw_data = await vmanage.get("/device/omp/tlocs/advertised", {"deviceId": str(device.system_ip)})
    if not raw_data:
        return None

    tlocs = []
    for item in raw_data:
        try:
            tlocs.append(
                TlocData(
                    site_id=_safe_int(item["site-id"]) or 0,
                    system_ip=IPv4Address(item["ip"]),
                    private_ip=IPv4Address(item["tloc-private-ip"]),
                    public_ip=IPv4Address(item["tloc-public-ip"]),
                    preference=int(item["preference"]),
                    weight=int(item["weight"]),
                    encapsulation=item["encap"],
                    color=item["color"].lower(),
                    raw_data=item
                )
            )
        except KeyError:
            continue
    return tlocs


async def get_device_vrrp(vmanage: Vmanage, device: DeviceData) -> Optional[List[VrrpData]]:
    """
    Retrieve VRRP configuration and status for a given device.
    """
    if not device.system_ip:
        return None
    raw_data = await vmanage.get("/device/vrrp", {"deviceId": str(device.system_ip)})
    if not raw_data:
        return None

    vrrp_list = []
    for item in raw_data:
        try:
            master = (item["vrrp-state"] == "proto-state-master")
            vrrp_list.append(
                VrrpData(
                    if_name=item["if-name"],
                    ip=IPv4Address(item["virtual-ip"]),
                    group=int(item["group-id"]),
                    priority=int(item["priority"]),
                    preempt=bool(item["preempt"]),
                    master=master,
                    raw_data=item
                )
            )
        except KeyError:
            continue
    return vrrp_list


async def get_device_template_values(vmanage: Vmanage, device: DeviceData) -> Optional[Dict[str, Any]]:
    """
    Retrieve input values for a device's attached template.
    """
    if not device.uuid or not device.template_id:
        return None

    payload = {
        "templateId": device.template_id,
        "deviceIds": [device.uuid],
        "isEdited": False,
        "isMasterEdited": False
    }
    raw_data = await vmanage.post("/template/device/config/input", data=payload)
    if not raw_data:
        return None
    try:
        return raw_data[0]
    except (IndexError, TypeError):
        return None
