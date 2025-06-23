import logging
import traceback

from src.utils.colors import Colors
from src.utils.misc import print_and_flush, get_random_user_agent


def is_proxy_ok() -> bool:
    """
    Проверяет доступность прокси и возможность подключения к целевому хосту.
    """
    print_and_flush(f"{Colors.GREEN}\n ** Checking proxy: {gl_args.proxy} **\n\n")
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "keep-alive",
        "User-Agent": get_random_user_agent(),
    }
    try:
        response = gl_http_pool.request("GET", gl_args.host, redirect=False, headers=headers)
    except Exception:
        print_and_flush(
            f"{Colors.RED} * Error: Failed to connect to {gl_args.host} using proxy {gl_args.proxy}.\n"
            "   See logs for more details...\n"
            f"{Colors.ENDC}"
        )
        logging.warning(f"Failed to connect to {gl_args.host} using proxy", exc_info=traceback)
        return False

    if response.status == 407:
        print_and_flush(
            f"{Colors.RED} * Error 407: Proxy authentication is required.\n"
            "   Please specify correct credentials (e.g. -P http://proxy:3128 -L user:pass).\n"
            f"{Colors.ENDC}"
        )
        logging.error("Proxy authentication failed")
        return False

    if response.status in (502, 503):
        print_and_flush(
            f"{Colors.RED} * Error {response.status}: Service {gl_args.host} is not available via proxy.\n"
            "   See logs for more details...\n"
            f"{Colors.ENDC}"
        )
        logging.error("Service unavailable via proxy")
        return False

    return True
