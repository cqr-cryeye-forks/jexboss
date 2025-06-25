import argparse
import textwrap

from src.core.cli.network_args import network_args
from src.utils.colors import Colors


def parse_args() -> argparse.Namespace:
    """
    Формирует и возвращает объект с аргументами командной строки.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            Colors.RED1 +
            "\n # --- JexBoss: Jboss verify and EXploitation Tool  --- #\n"
            " |    And others Java Deserialization Vulnerabilities   | \n"
            " |                                                      |\n"
            " | @author:  João Filho Matos Figueiredo                |\n"
            " | @contact: joaomatosf@gmail.com                       |\n"
            " |                                                      |\n"
            " | @updates: https://github.com/joaomatosf/jexboss      |\n"
            " #______________________________________________________#\n"
        ),
        epilog="",
        prog="JexBoss"
    )

    group_standalone = parser.add_argument_group(
        'Standalone mode'
    )
    group_advanced = parser.add_argument_group(
        'Advanced Options (USE WHEN EXPLOITING JAVA UNSERIALIZE IN APP LAYER)'
    )
    group_auto_scan = parser.add_argument_group(
        'Auto scan mode'
    )
    group_file_scan = parser.add_argument_group(
        'File scan mode'
    )

    # optional parameters
    parser.add_argument(
        "--auto-exploit",
        help="Send exploit code automatically (USE ONLY IF YOU HAVE PERMISSION!!!)",
        action='store_true',
    )
    parser.add_argument(
        "--disable-check-updates",
        help="Disable update checks by webshell and client",
        action='store_true',
    )
    parser.add_argument(
        '--mode',
        choices=['standalone', 'auto-scan', 'file-scan'],
        default='standalone',
        help="Operation mode (DEFAULT: standalone)",
    )
    parser.add_argument(
        "--app-unserialize",
        help="Check for java unserialization in HTTP parameters",
        action='store_true',
    )
    parser.add_argument(
        "--servlet-unserialize",
        help="Check for java unserialization in Servlets",
        action='store_true',
    )
    parser.add_argument(
        "--jboss",
        help="Check only for JBOSS vectors.",
        action='store_true',
    )
    parser.add_argument(
        "--jenkins",
        help="Check only for Jenkins CLI vector.",
        action='store_true',
    )
    parser.add_argument(
        "--struts2",
        help="Check only for Struts2 Jakarta Multipart parser.",
        action='store_true',
    )
    parser.add_argument(
        "--jmxtomcat",
        help="Check JMX listener in Tomcat (CVE-2016-8735/3427).",
        action='store_true',
    )
    parser.add_argument(
        '--proxy',
        help="Use a HTTP proxy (eg. -P http://192.168.0.1:3128)",
    )
    parser.add_argument(
        '--proxy-cred',
        help="Proxy authentication credentials (LOGIN:PASS)",
        metavar='LOGIN:PASS',
    )
    parser.add_argument(
        '--jboss-login',
        default='admin:admin',
        help="JBoss login:password for admin-console exploit",
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=3,
        help="Connection timeout in seconds (default 3)",
    )
    parser.add_argument(
        '--cookies',
        metavar='NAME=VALUE',
        type=str,
        help="Cookies for Struts2 exploit (eg. --cookies \"JSESSIONID=...\" )",
    )

    # advanced parameters
    group_advanced.add_argument(
        "--reverse-host",
        metavar='RHOST:RPORT',
        help="Remote host:port for reverse shell (nix only)",
    )
    group_advanced.add_argument(
        "--cmd",
        metavar='CMD',
        help="Command to run on target",
    )
    group_advanced.add_argument(
        "--dns",
        metavar='URL',
        help="DNS query for use with \"dns\" gadget",
    )
    group_advanced.add_argument(
        "--windows",
        help="Commands are for Windows (cmd.exe)",
        action='store_true',
    )
    group_advanced.add_argument(
        "--post-parameter",
        metavar='PARAMETER',
        default='javax.faces.ViewState',
        help="POST parameter to inject serialized object",
    )
    group_advanced.add_argument(
        "--show-payload",
        help="Print the generated payload",
        action='store_true',
    )
    group_advanced.add_argument(
        "--gadget",
        choices=[
            'commons-collections3.1',
            'commons-collections4.0',
            'jdk7u21',
            'jdk8u20',
            'groovy1',
            'dns'
        ],
        default='commons-collections3.1',
        help="Gadget type for automatic payload generation",
    )
    group_advanced.add_argument(
        "--load-gadget",
        metavar='FILENAME',
        help="Load serialized gadget from file",
    )
    group_advanced.add_argument(
        "--force",
        help="Force-send payload in multiple formats",
        action='store_true',
    )

    # standalone mode (required)
    group_standalone.add_argument(
        "--host",
        metavar='URL',
        help="Target URL (eg. -u http://host:8080)",
        required=True,
    )

    # auto-scan mode
    group_auto_scan.add_argument(
        "--network",
        type=network_args,
        default='192.168.0.0/24',
        help="Network in CIDR format for auto-scan",
    )
    group_auto_scan.add_argument(
        "--ports", default='8080,80',
        help="Comma-separated ports for auto-scan",
    )
    group_auto_scan.add_argument(
        "--results", metavar='FILENAME',
        default='jexboss_auto_scan_results.log',
        help="File to store auto-scan results",
    )

    # file-scan mode
    group_file_scan.add_argument(
        "--file", metavar='FILENAME_HOSTS',
        help="File with host list for file-scan",
    )
    group_file_scan.add_argument(
        "--out", metavar='FILENAME_RESULTS',
        default='jexboss_file_scan_results.log',
        help="File to store file-scan results",
    )

    return parser.parse_args()
