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