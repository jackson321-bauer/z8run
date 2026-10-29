import asyncio, json, sys
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

async def main():
    params=StdioServerParameters(command="/root/hermes-venv/bin/python3", args=["/data/z8run/mcp/z8run_mcp.py"], env=None)
    async with stdio_client(params) as (r,w):
        async with ClientSession(r,w) as s:
            await s.initialize()
            tools=await s.list_tools()
            names=[t.name for t in tools.tools]
            print("TOOLS_HAS_z8_export_flow:", "z8_export_flow" in names, flush=True)
            print("TOOLS_HAS_z8_export_document:", "z8_export_document" in names, flush=True)
            res=await s.call_tool("z8_export_flow", {"flow_id":"01a184da-a921-75e4-b3dd-52e2b31713ac","target":"native","mode":"cli","build":True,"input_json":'{"space":"space-alpha"}'})
            for c in res.content:
                if getattr(c,"type",None)=="text":
                    print(c.text, flush=True)
asyncio.run(main())
