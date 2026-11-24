## Install & Execution

Python 3.10 or later is recommended. From the project folder in PowerShell:

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.bat
python -m pip install -r requirements.txt
```

## Run the normal chat

Open four terminals in this folder and activate the virtual environment in
each:

Starting the server:

```powershell
python server.py --host 127.0.0.1 --port 5050
```

Start three clients:

```powershell
python client.py Alice
python client.py Bob
python client.py Carol
```

The first launch asks for and confirms a new private-key password. Later
launches ask once to unlock the existing encrypted key. Passwords are neither
stored in source code nor sent over the network.

At Alice's prompt, send a message:

Bob should display a line beginning with `[verified signature]`. Inspect
`server.log`; its `RELAY opaque_packet=` entry contains routing fields and long
base64 values for `encrypted_key`, `nonce`, `ciphertext`, and `signature`, but
does not contain the readable message or a plaintext AES key.

Other commands are `/users`, and `/quit`.

## Run the required attack

Stop the normal server and restart it in malicious demonstration mode:

```powershell
python server.py --host 127.0.0.1 --port 5050 --malicious
```

Reconnect Alice, Bob, and Carol. An attack is either applied to Alice's next
message or, for replay, to the last message already relayed from Alice.

| Alice command(s) | Expected receiving-client result |
| --- | --- |
| `/attack flip_ciphertext`, then `/msg Bob flip test` | Bob: signature invalid |
| `/attack change_number`, then `/msg Bob number test` | Bob: signature invalid |
| `/attack change_recipient Carol`, then `/msg Bob header test` | Carol: signature invalid |
| `/attack misdeliver Carol`, then `/msg Bob wrong inbox` | Carol: AES key cannot be decrypted |
| `/msg Bob replay me`, then `/attack replay` | Bob: repeated/lower message number rejected |

Wait for the server's `armed` response before sending the message that should
be modified. Malicious mode is intentionally disabled by default.

## Protocol summary

Packets are one UTF-8 JSON object per line over TCP. Binary values are base64.
The main packet types are `register`, `online_users`, `key_request`,
`key_response`, `chat`, and `error`. The server binds a registered username to
one live connection, rejects a chat whose `from` value does not match that
connection, and uses only `type`, `from`, and `to` for ordinary chat routing.
It forwards a normal encrypted packet unchanged. A send lock prevents JSON
frames from interleaving when multiple server threads notify one client.

## Submission hygiene

Do not commit or submit `keys/`, PEM files, passwords, `.venv/`, or `server.log`.
They are excluded by `.gitignore`. The prepared source ZIP likewise excludes
runtime keys, passwords, logs, caches, and the unrelated Java reference files.
