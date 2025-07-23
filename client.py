import asyncio
from fastmcp import FastMCP, Client

client = Client("./yara-webshell.py")

async def call_tool(cmd: str):
    async with client:
        result = await client.call_tool("run", {"command": cmd})
        print(result)

asyncio.run(call_tool("whoami"))