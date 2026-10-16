import asyncio

# Shared key-value store visible across all connections
kv_store = {}


async def handle_client(reader, writer):
    while True:
        # readline() perfectly handles TCP framing (split or coalesced segments)
        line_bytes = await reader.readline()
        if not line_bytes:
            break  # Client closed connection

        try:
            line = line_bytes.decode('ascii')
            if not line.endswith('\n'):
                break
            text = line[:-1]  # Strip trailing \n
        except UnicodeDecodeError:
            writer.write(b"ERR\n")
            await writer.drain()
            continue

        parts = text.split(' ', 1)
        cmd = parts[0]
        response = "ERR"

        # Protocol Logic
        if cmd == "PING" and len(parts) == 1:
            response = "PONG"

        elif cmd == "ECHO" and len(parts) == 2:
            response = parts[1]

        elif cmd == "SET" and len(parts) == 2:
            subparts = parts[1].split(' ', 1)
            if len(subparts) == 2:
                key, value = subparts
                if ' ' not in key:
                    kv_store[key] = value
                    response = "OK"

        elif cmd == "GET" and len(parts) == 2:
            key = parts[1]
            if ' ' not in key:
                response = kv_store.get(key, "NOT_FOUND")

        # Send response
        writer.write(f"{response}\n".encode('ascii'))
        await writer.drain()

    writer.close()
    await writer.wait_closed()


async def main():
    # start_server automatically spawns a new task for each concurrent connection
    server = await asyncio.start_server(handle_client, '0.0.0.0', 9001)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())