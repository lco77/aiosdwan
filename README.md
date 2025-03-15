# aiosdwan
Cisco SDWAN Client

Tested on Cisco Catalyst SDWAN versions 20.6 20.9 and 20.12

# Usage

```python
import asyncio
from aiosdwan import connect, get_devices

async def main():
    # 1) Connect
    vmanage = await connect(
        host="vmanage.example.com",
        username="admin",
        password="secret",
        verify=False
    )

    # 2) Fetch devices
    all_devices = await get_devices(vmanage)
    for uuid, dev in all_devices.items():
        print("UUID:", uuid, "Hostname:", dev.hostname)

asyncio.run(main())
```

# Functions

The following functions are currently available:

## connect() - open a Vmanage session and returns a Vmanage object
```python
connect( host: str, username: str, password: str, verify: bool = False, port: int = 443, semaphore: asyncio.Semaphore = None) -> Vmanage
```

## get_devices() - get all devices from a Vmanage session and return DeviceData objects
```python
get_devices(vmanage: Vmanage) -> Dict[str, DeviceData]
```

## get_device_interfaces - get all interfaces from a given vedge device and return InterfaceData objects
```python
get_device_interfaces(vmanage: Vmanage, device: DeviceData) -> Optional[List[InterfaceData]]
```

## get_device_tlocs - get all TLOCs from a given vedge device and return TlocData objects
```python
get_device_tlocs(vmanage: Vmanage, device: DeviceData) -> Optional[List[TlocData]]
```

## get_device_vrrp - get VRRP info from a given vedge device and return VrrpData objects
```python
get_device_vrrp(vmanage: Vmanage, device: DeviceData) -> Optional[List[VrrpData]]
```

## get_device_template_values - get device template values info from a given vedge device and data as dict
```python
get_device_template_values(vmanage: Vmanage, device: DeviceData) -> Optional[Dict[str, Any]]
```


# Concurrency

You can pass an ayncio.Semaphore object during initialization and use it to limit the number of concurrent connections sent to Vmanage:

```python
import asyncio
from aiosdwan.vmanage import connect, get_devices, get_device_template_values

async def main():

    semaphore = asyncio.Semaphore(10)

    # 1) Connect
    session = await connect(
        host="vmanage.example.com",
        username="admin",
        password="secret",
        verify=False,
        semaphore=semaphore
    )

    # 2) Fetch devices
    all_devices = await get_devices(session)
    for uuid, dev in all_devices.items():
        print("UUID:", uuid, "Hostname:", dev.hostname)


    # 3) Fetch template values concurrently with semaphore limit
    tasks = [ get_device_template_values(session, device) for key,device in all_devices.items() ]
    results = await session.run_tasks(tasks)



asyncio.run(main())
```


# Vmanage public methods

You can query any Vmanage endpoint using built-in methods:

## get()
```python
get(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[List[Dict[str, Any]]]
```
## post()
```python
post(self, endpoint: str, params: Dict[str, Any] = None, data: Dict[str, Any] = None ) -> Optional[List[Dict[str, Any]]]
```
## put()
```python
put(self, endpoint: str, params: Dict[str, Any] = None, data: Dict[str, Any] = None) -> Optional[List[Dict[str, Any]]]
```
## delete()
```python
delete(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[List[Dict[str, Any]]]
```

You can also concurrency using Semaphore controlled wrappers:

## run_task()
```python
run_task(self, task: Any)->Any
```
## run_tasks()
```python
run_tasks(self, tasks: List[Any]) -> List[Any]
```
