import logging
import socket

from requests.models import parse_url

from src.exploits.ex1 import get_list_params_with_serialized_objs
from src.exploits.struts2 import exploit_struts2_jakarta_multipart
from src.utils.colors import Colors
from src.utils.misc import print_and_flush, get_random_user_agent, get_serialized_obj_from_param, get_html_redirect_link


def check_vul(url):
    """
    Test if a GET to a URL is successful
    :param url: The URL to test
    :return: A dict with the exploit type as the keys, and the HTTP status code as the value
    """
    url_check = parse_url(url)
    if '443' in str(url_check.port) and url_check.scheme != 'https':
        url = "https://" + str(url_check.host) + ":" + str(url_check.port) + str(url_check.path)

    print_and_flush(Colors.GREEN + "\n ** Checking Host: %s **\n" % url)
    logging.info("Checking Host: %s" % url)

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}

    paths = {"jmx-console": "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo",
             "web-console": "/web-console/Invoker",
             "JMXInvokerServlet": "/invoker/JMXInvokerServlet",
             "admin-console": "/admin-console/",
             "Application Deserialization": "",
             "Servlet Deserialization": "",
             "Jenkins": "",
             "Struts2": "",
             "JMX Tomcat": ""}

    fatal_error = False

    for vector in paths:
        r = None
        if gl_interrupted: break
        try:

            # check jmx tomcat only if specifically chosen
            if (gl_args.jmxtomcat and vector != 'JMX Tomcat') or \
                    (not gl_args.jmxtomcat and vector == 'JMX Tomcat'): continue

            if gl_args.app_unserialize and vector != 'Application Deserialization': continue

            if gl_args.struts2 and vector != 'Struts2': continue

            if gl_args.servlet_unserialize and vector != 'Servlet Deserialization': continue

            if gl_args.jboss and vector not in ('jmx-console', 'web-console', 'JMXInvokerServlet',
                                                'admin-console'): continue

            if gl_args.jenkins and vector != 'Jenkins': continue

            if gl_args.force:
                paths[vector] = 200
                continue

            print_and_flush(Colors.GREEN + " [*] Checking %s: %s" % (vector, " " * (27 - len(vector))) + Colors.ENDC,
                            same_line=True)

            # check jenkins
            if vector == 'Jenkins':

                cli_port = None
                # check version and search for CLI-Port
                r = gl_http_pool.request('GET', url, redirect=True, headers=headers)
                all_headers = r.getheaders()

                # versions > 658 are not vulnerable
                if 'X-Jenkins' in all_headers:
                    version = int(all_headers['X-Jenkins'].split('.')[1].split('.')[0])
                    if version >= 638:
                        paths[vector] = 505
                        continue

                for h in all_headers:
                    if 'CLI-Port' in h:
                        cli_port = int(all_headers[h])
                        break

                if cli_port is not None:
                    paths[vector] = 200
                else:
                    paths[vector] = 505

            # chek vul for Java Unserializable in Application Parameters
            elif vector == 'Application Deserialization':

                r = gl_http_pool.request('GET', url, redirect=False, headers=headers)
                if r.status in (301, 302, 303, 307, 308):
                    cookie = r.getheader('set-cookie')
                    if cookie is not None: headers['Cookie'] = cookie
                    r = gl_http_pool.request('GET', url, redirect=True, headers=headers)
                # link, obj = get_param_value(r.data, gl_args.post_parameter)
                obj = get_serialized_obj_from_param(str(r.data), gl_args.post_parameter)

                # if no obj serialized, check if there's a html refresh redirect and follow it
                if obj is None:
                    # check if theres a redirect link
                    link = get_html_redirect_link(str(r.data))

                    # If it is a redirect link. Follow it
                    if link is not None:
                        r = gl_http_pool.request('GET', url + "/" + link, redirect=True, headers=headers)
                        # link, obj = get_param_value(r.data, gl_args.post_parameter)
                        obj = get_serialized_obj_from_param(str(r.data), gl_args.post_parameter)

                # if obj does yet None
                if obj is None:
                    # search for other params that can be exploited
                    list_params = get_list_params_with_serialized_objs(str(r.data))
                    if len(list_params) > 0:
                        paths[vector] = 110
                        print_and_flush(Colors.RED + "  [ CHECK OTHER PARAMETERS ]" + Colors.ENDC)
                        print_and_flush(
                            Colors.RED + "\n * The \"%s\" parameter does not appear to be vulnerable.\n" % gl_args.post_parameter +
                            "   But there are other parameters that it seems to be xD!\n" + Colors.ENDC + Colors.GREEN +
                            Colors.BOLD + "\n   Try these other parameters: \n" + Colors.ENDC)
                        for p in list_params:
                            print_and_flush(Colors.GREEN + "      -H %s" % p + Colors.ENDC)
                        print("")
                elif obj is not None and obj == 'stateless':
                    paths[vector] = 100
                elif obj is not None:
                    paths[vector] = 200

            # chek vul for Java Unserializable in viewState
            elif vector == 'Servlet Deserialization':

                r = gl_http_pool.request('GET', url, redirect=False, headers=headers)
                if r.status in (301, 302, 303, 307, 308):
                    cookie = r.getheader('set-cookie')
                    if cookie is not None: headers['Cookie'] = cookie
                    r = gl_http_pool.request('GET', url, redirect=True, headers=headers)

                if r.getheader('Content-Type') is not None and 'x-java-serialized-object' in r.getheader(
                        'Content-Type'):
                    paths[vector] = 200
                else:
                    paths[vector] = 505

            elif vector == 'Struts2':

                result = exploit_struts2_jakarta_multipart(url, 'jexboss', gl_args.cookies)
                if result is None or "Could not get command" in str(result):
                    paths[vector] = 100
                elif 'jexboss' in str(result) and "<html>" not in str(result).lower():
                    paths[vector] = 200
                else:
                    paths[vector] = 505

            elif vector == 'JMX Tomcat':

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(7)
                host_rmi = url.split(':')[0]
                port_rmi = int(url.split(':')[1])
                s.connect((host_rmi, port_rmi))
                s.send(b"JRMI\x00\x02K")
                msg = s.recv(1024)
                octets = str(msg[3:]).split(".")
                if len(octets) != 4:
                    paths[vector] = 505
                else:
                    paths[vector] = 200

            # check jboss vectors
            elif vector == "JMXInvokerServlet":
                # user privided web-console path and checking JMXInvoker...
                if "/web-console/Invoker" in url:
                    paths[vector] = 505
                # if the user not provided the path, append the "/invoker/JMXInvokerServlet"
                else:

                    if not url.endswith(str(paths[vector])) and not url.endswith(str(paths[vector]) + "/"):
                        url_to_check = url + str(paths[vector])
                    else:
                        url_to_check = url

                    r = gl_http_pool.request('HEAD', url_to_check, redirect=False, headers=headers)
                    # if head method is not allowed/supported, try GET
                    if r.status in (405, 406):
                        r = gl_http_pool.request('GET', url_to_check, redirect=False, headers=headers)

                    # if web-console/Invoker or invoker/JMXInvokerServlet
                    if r.getheader('Content-Type') is not None and 'x-java-serialized-object' in r.getheader(
                            'Content-Type'):
                        paths[vector] = 200
                    else:
                        paths[vector] = 505

            elif vector == "web-console":
                # user privided JMXInvoker path and checking web-console...
                if "/invoker/JMXInvokerServlet" in url:
                    paths[vector] = 505
                # if the user not provided the path, append the "/web-console/..."
                else:

                    if not url.endswith(str(paths[vector])) and not url.endswith(str(paths[vector]) + "/"):
                        url_to_check = url + str(paths[vector])
                    else:
                        url_to_check = url

                    r = gl_http_pool.request('HEAD', url_to_check, redirect=False, headers=headers)
                    # if head method is not allowed/supported, try GET
                    if r.status in (405, 406):
                        r = gl_http_pool.request('GET', url_to_check, redirect=False, headers=headers)

                    # if web-console/Invoker or invoker/JMXInvokerServlet
                    if r.getheader('Content-Type') is not None and 'x-java-serialized-object' in r.getheader(
                            'Content-Type'):
                        paths[vector] = 200
                    else:
                        paths[vector] = 505

            # other jboss vector
            else:
                r = gl_http_pool.request('HEAD', url + str(paths[vector]), redirect=False, headers=headers)
                # if head method is not allowed/supported, try GET
                if r.status in (405, 406):
                    r = gl_http_pool.request('GET', url + str(paths[vector]), redirect=False, headers=headers)
                # check if the server respond with 200/500 for all requests
                if r.status in (200, 500):
                    r = gl_http_pool.request('GET', url + str(paths[vector]) + '/github.com/joaomatosf/jexboss',
                                             redirect=False, headers=headers)

                    if r.status == 200:
                        r.status = 505
                    else:
                        r.status = 200

                paths[vector] = r.status

            # ----------------
            # Analysis of the results
            # ----------------
            # check if the proxy do not support running in the same port of the target
            if r is not None and r.status == 400 and gl_args.proxy:
                if parse_url(gl_args.proxy).port == url_check.port:
                    print_and_flush(
                        Colors.RED + "[ ERROR ]\n * An error occurred because the proxy server is running on the "
                                     "same port as the server port (port %s).\n"
                                     "   Please use a different port in the proxy.\n" % url_check.port + Colors.ENDC)
                    logging.critical("Proxy returns 400 Bad Request because is running in the same port as the server")
                    fatal_error = True
                    break

            # check if it's false positive
            if r is not None and len(r.getheaders()) == 0:
                print_and_flush(Colors.RED + "[ ERROR ]\n * The server %s is not an HTTP server.\n" % url + Colors.ENDC)
                logging.error("The server %s is not an HTTP server." % url)
                for key in paths: paths[key] = 505
                break

            if paths[vector] in (301, 302, 303, 307, 308):
                url_redirect = r.get_redirect_location()
                print_and_flush(Colors.GREEN + "  [ REDIRECT ]\n * The server sent a redirect to: %s\n" % url_redirect)
            elif paths[vector] == 200 or paths[vector] == 500:
                if vector == "admin-console":
                    print_and_flush(Colors.RED + "  [ EXPOSED ]" + Colors.ENDC)
                    logging.info("Server %s: EXPOSED" % url)
                elif vector == "Jenkins":
                    print_and_flush(Colors.RED + "  [ POSSIBLE VULNERABLE ]" + Colors.ENDC)
                    logging.info("Server %s: RUNNING JENKINS" % url)
                elif vector == "JMX Tomcat":
                    print_and_flush(Colors.RED + "  [ MAYBE VULNERABLE ]" + Colors.ENDC)
                    logging.info("Server %s: RUNNING JENKINS" % url)
                else:
                    print_and_flush(Colors.RED + "  [ VULNERABLE ]" + Colors.ENDC)
                    logging.info("Server %s: VULNERABLE" % url)
            elif paths[vector] == 100:
                paths[vector] = 200
                print_and_flush(Colors.RED + "  [ INCONCLUSIVE - NEED TO CHECK ]" + Colors.ENDC)
                logging.info("Server %s: INCONCLUSIVE - NEED TO CHECK" % url)
            elif paths[vector] == 110:
                logging.info("Server %s: CHECK OTHERS PARAMETERS" % url)
            else:
                print_and_flush(Colors.GREEN + "  [ OK ]")
        except Exception as err:
            print_and_flush(
                Colors.RED + "\n * An error occurred while connecting to the host %s (%s)\n" % (url, err) + Colors.ENDC)
            logging.info("An error occurred while connecting to the host %s" % url, exc_info=traceback)
            paths[vector] = 505

    if fatal_error:
        exit(1)
    else:
        return paths
