import os
import json


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def colored(text, color):
    return f"{color}{text}{Colors.RESET}"


def success(msg):
    return colored(f"[+] {msg}", Colors.GREEN)


def error(msg):
    return colored(f"[-] {msg}", Colors.RED)


def info(msg):
    return colored(f"[*] {msg}", Colors.CYAN)


def warning(msg):
    return colored(f"[!] {msg}", Colors.YELLOW)


def banner():
    return f"""
{Colors.CYAN}{Colors.BOLD}
 ███╗   ██╗██████╗ ████████╗███████╗██████╗ ██╗  ██╗██╗████████╗███████╗██████╗
 ████╗  ██║╚════██╗╚══██╔══╝██╔════╝██╔══██╗██║ ██╔╝██║╚══██╔══╝██╔════╝██╔══██╗
 ██╔██╗ ██║ █████╔╝   ██║   ███████╗██████╔╝█████╔╝ ██║   ██║   █████╗  ██████╔╝
 ██║╚██╗██║ ╚═══██╗   ██║   ╚════██║██╔═══╝ ██╔═██╗ ██║   ██║   ██╔══╝  ██╔══██╗
 ██║ ╚████║██████╔╝   ██║   ███████║██║     ██║  ██╗██║   ██║   ███████╗██║  ██║
 ╚═╝  ╚═══╝╚═════╝    ╚═╝   ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Colors.RESET}
{Colors.WHITE}  Advanced Network Reconnaissance Tool{Colors.RESET}
{Colors.DIM}  For Authorized Testing Only{Colors.RESET}
"""


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def load_json_file(filepath):
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def get_common_service_name(port):
    services = {
        7:"echo",9:"discard",13:"daytime",20:"ftp-data",21:"ftp",
        22:"ssh",23:"telnet",25:"smtp",37:"time",43:"whois",
        53:"dns",67:"dhcp-server",68:"dhcp-client",69:"tftp",
        70:"gopher",79:"finger",80:"http",81:"http-alt",88:"kerberos",
        110:"pop3",111:"rpcbind",113:"ident",119:"nntp",123:"ntp",
        135:"msrpc",137:"netbios-ns",138:"netbios-dgm",139:"netbios-ssn",
        143:"imap",161:"snmp",162:"snmptrap",179:"bgp",194:"irc",
        389:"ldap",427:"svrloc",443:"https",445:"microsoft-ds",
        465:"smtps",500:"isakmp",512:"exec",513:"login",514:"syslog",
        515:"printer",543:"klogin",544:"kshell",548:"afp",554:"rtsp",
        587:"submission",631:"ipp",636:"ldapssl",873:"rsync",
        990:"ftps",993:"imaps",995:"pop3s",1080:"socks",
        1194:"openvpn",1433:"ms-sql",1434:"ms-sql-m",1521:"oracle",
        1723:"pptp",1883:"mqtt",1900:"upnp",2049:"nfs",
        2082:"cpanel",2083:"cpanel-ssl",2121:"ftp-alt",2222:"ssh-alt",
        2375:"docker",3000:"grafana",3128:"squid-proxy",3306:"mysql",
        3389:"rdp",3690:"svn",4443:"https-alt",4444:"metasploit",
        5000:"upnp",5060:"sip",5222:"xmpp",5432:"postgresql",
        5601:"kibana",5631:"pcanywhere",5666:"nrpe",5672:"amqp",
        5900:"vnc",5901:"vnc-1",5984:"couchdb",5985:"wsman",
        6000:"x11",6379:"redis",6443:"kubernetes",6667:"irc",
        7000:"afs3",7070:"realserver",7199:"cassandra",7443:"oracleas",
        7474:"neo4j",8000:"http-alt",8008:"http-alt",8009:"ajp13",
        8069:"odoo",8080:"http-proxy",8081:"http-proxy",8088:"radan",
        8089:"splunkd",8139:"puppet",8200:"vault",8443:"https-alt",
        8500:"consul",8834:"nessus",8888:"http-alt",8983:"solr",
        9000:"cslistener",9042:"cassandra",9090:"zeus-admin",
        9100:"jetdirect",9200:"elasticsearch",9300:"elasticsearch",
        9418:"git",9443:"tungsten",9999:"abyss",10000:"webmin",
        10050:"zabbix-agent",10051:"zabbix-server",11211:"memcached",
        27017:"mongodb",27018:"mongodb",32400:"plex",33060:"mysqlx",
        50000:"sap",50070:"hadoop"
    }
    return services.get(port, "unknown")
