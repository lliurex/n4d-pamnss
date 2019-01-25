#!/usr/bin/python
import xmlrpclib

server_ip = "10.0.0.241"

c = xmlrpclib.ServerProxy("https://"+server_ip+":9779")
#c = xmlrpclib.ServerProxy("https://192.168.1.2:9779")
user = ("lliurex","lliurex")
#print c.get_methods("SlapdManager")

print c.configure_ldap_environment_client(user,"PamnssPlugin")
print c.configure_ldap(user,"PamnssPlugin")
print c.configure_nsswitch(user,"PamnssPlugin")
'''
print c.generate_ssl_certificates(user,"SlapdManager") 
print c.load_lliurex_schema(user,"SlapdManager") 
print c.enable_tls_communication(user,"SlapdManager",'/etc/ldap/slapd.cert','/etc/ldap/slapd.key') 
#c.restore(user,"SlapdManager") 
#c.configure_client_slapd(user,"SlapdManager") 
#c.configure_master_slapd(user,"SlapdManager") 
print c.configure_simple_slapd(user,"SlapdManager") 
print c.load_acl(user,"SlapdManager") 
print c.open_ports_slapd(user,"SlapdManager",'192.168.1.2') 
print c.reboot_slapd(user,"SlapdManager") 
print c.load_basic_struture(user,"SlapdManager")
print c.change_admin_passwd(user,"SlapdManager","lliurex") 
#c.update_index(user,"SlapdManager") 
#c.test(user,"SlapdManager") 
#c.backup(user,"SlapdManager") 
#c.load_schema(user,"SlapdManager")
'''
