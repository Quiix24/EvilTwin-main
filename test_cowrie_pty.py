import asyncio
import asyncssh
import traceback

class Client(asyncssh.SSHClientSession):
    def data_received(self, data, datatype):
        print(data, end='')

async def run_client():
    try:
        print("Connecting to Cowrie on 127.0.0.1:2222...")
        conn = await asyncio.wait_for(
            asyncssh.connect("127.0.0.1", port=2222, username="root", password="password", known_hosts=None),
            timeout=10.0
        )
        print("Connected! Requesting PTY...")
        chan, session = await conn.create_session(Client, term_type='xterm')
        print("PTY established!")
        await chan.wait_closed()
        conn.close()
    except Exception as e:
        traceback.print_exc()

asyncio.run(run_client())
