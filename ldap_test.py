import configparser
import json

import ldap3
from ldap3 import ALL, NTLM, Connection, Server

config_file = #path to ad.ini
config = configparser.ConfigParser()
config.read(config_file)
domain = "DC=,DC="
username=config["AD"]["username"]
password=config["AD"]["password"]
server = Server("", port=636, use_ssl=True, get_info=ALL)
conn = Connection(server, user=f"{domain}\\{username}", password=password, auto_bind=True, authentication=NTLM)
spec_attr = ["cn", "distinguishedName", "sAMAccountName", "givenName", "sn", "mail", "memberOf"]

while True:
    select_filter = str(input("Select LDAP filter type.\nEnter G for NSA group.\nEnter S for sAM.\nEnter P for PID.\n"))
    if select_filter.lower() == "g":
        group = "CN=,OU=Groups,DC=,DC="
        ad_filter = f"(&(objectClass=USER)(memberOf={group}))"
        conn.search(search_base=domain, search_filter=ad_filter, attributes=spec_attr)
        ent_dict = {}
        for i, entry_obj in enumerate(conn.entries):
            ent_dict[i] = json.loads(entry_obj.entry_to_json())["attributes"]
        for k, v in ent_dict.items():
            print(f"Name: ", end="")
            for i in ent_dict[k]['givenName']:
                print(i, end="")
            for i in ent_dict[k]['sn']:
                print(i)
            print(f"Email: ", end="")
            for i in ent_dict[k]['mail']:
                print(i)
            print(f"sAM Account: ", end="")
            for i in ent_dict[k]['sAMAccountName']:
                print(i)
            print(f"CN: ", end="")
            for i in ent_dict[k]['cn']:
                print(i)
            print(f"DN: ", end="")
            for i in ent_dict[k]['distinguishedName']:
                print(i)
            print("Member of:")
            for i in ent_dict[k]['memberOf']:
                print(i)
        break
    elif select_filter.lower() == "s":
        account = str(input("Enter sAM account: "))
        ad_filter = f"(&(sAMAccountName={account}))"
        conn.search(search_base=domain, search_filter=ad_filter, attributes=spec_attr)
        ent_dict = {}
        for i, entry_obj in enumerate(conn.entries):
            ent_dict[i] = json.loads(entry_obj.entry_to_json())["attributes"]
        for k, v in ent_dict.items():
            print(f"Name: ", end="")
            for i in ent_dict[0]['givenName']:
                print(i, end="")
            for i in ent_dict[0]['sn']:
                print(i)
            print(f"Email: ", end="")
            for i in ent_dict[0]['mail']:
                print(i)
            print(f"sAM Account: ", end="")
            for i in ent_dict[0]['sAMAccountName']:
                print(i)
            print(f"CN: ", end="")
            for i in ent_dict[0]['cn']:
                print(i)
            print(f"DN: ", end="")
            for i in ent_dict[0]['distinguishedName']:
                print(i)
            print("Member of:")
            for i in ent_dict[0]['memberOf']:
                print(i)
        break
    elif select_filter.lower() == "p":
        pid = str(input("Enter PID (number only): "))
        ad_filter = f"(&(uid=P{pid}))"
        conn.search(search_base=domain, search_filter=ad_filter, attributes=spec_attr)
        ent_dict = {}
        for i, entry_obj in enumerate(conn.entries):
            ent_dict[i] = json.loads(entry_obj.entry_to_json())["attributes"]
        for k, v in ent_dict.items():
            print(f"Name: ", end="")
            for i in ent_dict[0]['givenName']:
                print(i, end="")
            for i in ent_dict[0]['sn']:
                print(i)
            print(f"Email: ", end="")
            for i in ent_dict[0]['mail']:
                print(i)
            print(f"sAM Account: ", end="")
            for i in ent_dict[0]['sAMAccountName']:
                print(i)
            print(f"CN: ", end="")
            for i in ent_dict[0]['cn']:
                print(i)
            print(f"DN: ", end="")
            for i in ent_dict[0]['distinguishedName']:
                print(i)
            print("Member of:")
            for i in ent_dict[0]['memberOf']:
                print(i)
        break
    else:
        print("Please enter a valid command.")
