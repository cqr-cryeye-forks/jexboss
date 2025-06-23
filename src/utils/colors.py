from enum import unique, StrEnum


@unique
class Colors(StrEnum):
    RED = '\x1b[91m'
    RED1 = '\033[31m'
    BLUE = '\033[94m'
    GREEN = '\033[32m'
    BOLD = '\033[1m'
    NORMAL = '\033[0m'
    ENDC = '\033[0m'
