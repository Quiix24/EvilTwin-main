import asyncio
import asyncssh
import traceback

async def run_client():
    try:
        print("Connecting to Cowrie on 127.0.0.1:2222...")
        conn = await asyncio.wait_for(
            asyncssh.connect("127.0.0.1", port=2222, username="root", password="password", known_hosts=None),
            timeout=10.0
        )
        print("Connected! Running 'ls'...")
        result = await conn.run("ls -l")
        print("Output:", result.stdout)
        conn.close()
    except Exception as e:
        traceback.print_exc()

asyncio.run(run_client())
