import logging
import socket


def check_connectivity(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((str(host), int(port)))
        s.close()
    except socket.timeout:
        logging.info("Failed to connect to %s:%s" % (host, port))
        return False
    except:
        logging.info("Failed to connect to %s:%s" % (host, port))
        return False

    return True
