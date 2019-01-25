#!/usr/bin/env python
from jinja2 import Environment
from jinja2.loaders import FileSystemLoader
import ConfigParser
import tarfile
import datetime
import os, sys, shutil
import os.path
import tempfile
import xmlrpclib
import threading
import time

class PamnssPlugin:

	# Templates variables
	TEMPLATES_PATH="/usr/share/n4d/templates/pamnss/"
	LDAP_ENVIRONMENT_CLIENT_TEMPLATE="etc.ldap.ldap.conf"
	LDAP_TEMPLATE="etc.ldap.conf"
	NSSWITCH_TEMPLATE="etc.nsswitch.conf"
	NSLCD_TEMPLATE="nslcd.conf"
	
	# Destination variables
	LDAP_ENVIRONMENT_CLIENT_DESTINATION="/etc/ldap/ldap.conf"
	LDAP_DESTINATION="/etc/ldap.conf"
	NSSWITCH_DESTINATION="/etc/nsswitch.conf"
	NSLCD_DESTINATION="/etc/nslcd.conf"
	
	LIST_OF_FILES=["etc.ldap.conf","etc.ldap.ldap.conf","etc.nsswitch.conf"]
	
	# Backups
	BACKUP_DEFAULT_PATH="/backup/"
	BACKUP_DEFAULT_TAR=""
	
	def __init__(self):
		
		self.failed={}
		self.failed[1]=False
		self.failed[2]=False
		self.failed[3]=False
		
	#def __init__
	
	def check_configured_status(self):
		
		for item in self.failed:
			if self.failed[item]:
				return False
				
		return True
	
	def uchmod(self,file,mode):
		
		prevmask = os.umask(0)
		os.chmod(file,mode)
		os.umask(prevmask)
		
	#def uchmod
		
	
	def mkdir(path):
		try:
			os.makedirs(path)
		except:
			pass
			
	#def mkdir(path):
	
	
	def is_client(self):
		
		if "REMOTE_VARIABLES_SERVER" in objects["VariablesManager"].variables:
			return True
		else:
			return False
		
	#def is_client
	
	
	def startup(self,options):

		if options["controlled"]:
			self.configure_ldap_environment_client()
			self.configure_ldap()
			self.configure_nsswitch()
			self.configure_nslcd()
			
			if self.check_configured_status():
				if os.path.exists("/usr/sbin/nscd") and options['boot']:
					os.system("nscd -i passwd")
					os.system("nscd -i group")
					os.system("nscd -i netgroup")
					os.system("nscd -i services")
					os.system("nscd -i hosts")
					os.system("service nscd restart")
			
			if not options.has_key("manually_launched"):
				if not self.check_configured_status():
					self.retry_configuration(6)
			
					
		return [True,True]
	
	#def startup(self):

	
	def check_variables(self,dic):
		
		for item in dic:
			if dic[item]==None:
				return False
				
		return True
		
	#check_variables
	
	def check_ldap_variables(self):
		
		if  objects.has_key("VariablesManager"):
			variables=objects["VariablesManager"].get_variable_list(["LDAP_BASE_DN","CLIENT_LDAP_URI"])
			
			for item in variables:
				if variables[item]==False:
					return False
					
			return True
		
		return False
		
	#def check_ldap_variables
	
	def get_local_users(self):
	
		f=open("/etc/passwd")
		lines=f.readlines()
		f.close()
		
		ret=""
		
		for line in lines:
			data=line.split(":")
			if int(data[2])<1000:
				ret+=data[0]+","
				
		ret=ret.rstrip(",")
		
		return ret
	
	#def get_local_users
	
	
	
	def retry_configuration(self,tries):
		
		t=threading.Thread(target=self._retry_thread,args=(tries,))
		t.daemon=True
		t.start()
		
	#def retry_configuration
	
	def _retry_thread(self,tries):
		
		for try_ in range(0,tries):
			if not self.check_configured_status():
				print "\t[STARTUP][PamnssPlugin] Retrying %s..."%try_
				time.sleep(2)
				options={}
				options["controlled"]=True
				options["manually_launched"]=True
				options["boot"]=False
				self.startup(options)
			else:
				break

		
		if self.check_configured_status():
			if os.path.exists("/usr/sbin/nscd"):
				os.system("nscd -i passwd")
				os.system("nscd -i group")
				os.system("nscd -i netgroup")
				os.system("nscd -i services")
				os.system("nscd -i hosts")
				os.system("service nscd restart")	
			
		
	#def _retry_thread


	def configure_ldap_environment_client(self):

		# XMLRPC Debug
		# server=xmlrpclib.ServerProxy("https://localhost:9779")

		# XMLRPC Debug
		# if True:
		if  objects.has_key("VariablesManager"):
			ldap_environment_variables=objects["VariablesManager"].get_variable_list(["LDAP_BASE_DN","CLIENT_LDAP_URI"])
			if not self.check_variables(ldap_environment_variables):
				self.failed[1]=True
				return [False,False]
			else:
				self.failed[1]=False
							
			if os.path.exists("/var/lib/n4d/variables-dir/LDAP_SID"):
				ldap_environment_variables["CLIENT_LDAP_URI"]="ldaps://localhost"
			
		# Temporal file creation
		path_to_work=tempfile.mkdtemp()
		filename=path_to_work+"ldap.conf"
		
		# Create temporal environment for jinja
		env = Environment(loader=FileSystemLoader(PamnssPlugin.TEMPLATES_PATH))
		tmpl = env.get_template(PamnssPlugin.LDAP_ENVIRONMENT_CLIENT_TEMPLATE)
		
		# Render the template with diferent values		
		textrendered=tmpl.render(ldap_environment_variables)
		
		# Create a temporal for nsswitch
		tmp,filename=tempfile.mkstemp()
		f = open(filename,'w')
		f.writelines(textrendered)
		f.close()
		
		# Using the ultimate chmod
		self.uchmod(filename,0644)

		# Copy unitaria
		shutil.copy(filename,PamnssPlugin.LDAP_ENVIRONMENT_CLIENT_DESTINATION)
		os.remove(filename)
		
		return [True,True]
		
	# def  configure_ldap_environment_client(self):
	
	def configure_ldap(self):

		# Temporal file creation
		path_to_work=tempfile.mkdtemp()
		filename=path_to_work+"ldap.conf"
	
		# XMLRPC Debug
		# if True:
		if  objects.has_key("VariablesManager"):
			ldap_variables=objects["VariablesManager"].get_variable_list(["LDAP_BASE_DN","CLIENT_LDAP_URI_NOSSL"])
			if not self.check_variables(ldap_variables):
				self.failed[2]=True
				return [False,False]
			else:
				self.failed[2]=False
			
				
			if os.path.exists("/var/lib/n4d/variables-dir/LDAP_SID"):
				ldap_variables["CLIENT_LDAP_URI_NOSSL"]="ldap://localhost"
			
	
		# Create temporal environment for jinja
		env = Environment(loader=FileSystemLoader(PamnssPlugin.TEMPLATES_PATH))
		tmpl = env.get_template(PamnssPlugin.LDAP_TEMPLATE)
		
		# Render the template with diferent values
		textrendered = tmpl.render(ldap_variables)
		
		# Create a temporal for nsswitch
		tmp,filename=tempfile.mkstemp()
		f = open(filename,'w')
		f.writelines(textrendered)
		f.close()
		
		# Using the ultimate chmod
		self.uchmod(filename,0644)
		
		# Move to the final destination
		shutil.copy(filename,PamnssPlugin.LDAP_DESTINATION)
		os.remove(filename)
		
		return [True,True]
		
	#def configure_ldap(self):
		
		
	def configure_nsswitch(self): 

		# XMLRPC Debug
		# server=xmlrpclib.ServerProxy("https://localhost:9779")
		
		# Get the template from templates library
		env = Environment(loader=FileSystemLoader(PamnssPlugin.TEMPLATES_PATH))
		tmpl = env.get_template('etc.nsswitch.conf')
		enable_nss_ldap={}
		enable_nss_ldap["ENABLE_NSS_LDAP"]="ENABLED"
		# Render the template
		textrendered=tmpl.render(enable_nss_ldap)
		
		# Create a temporal for nsswitch
		tmp,filename=tempfile.mkstemp()
		f = open(filename,'w')
		f.writelines(textrendered)
		f.close()
		
		self.uchmod(filename,0644)
		
		# Copy unitaria
		shutil.copy(filename,PamnssPlugin.NSSWITCH_DESTINATION)
		os.remove(filename)
		
		if os.path.exists("/usr/sbin/nscd"):
				os.system("nscd -i passwd")
				os.system("nscd -i group")
				os.system("nscd -i netgroup")
				os.system("nscd -i services")
				os.system("nscd -i hosts")
				os.system("service nscd restart")		
				
		
		
		return [True,True]
	# def configure_nsswitch
	
	def configure_nslcd(self):
		
		env = Environment(loader=FileSystemLoader(PamnssPlugin.TEMPLATES_PATH))
		tmpl = env.get_template('nslcd.conf')
		vars={}
		vars=objects["VariablesManager"].get_variable_list(["LDAP_BASE_DN","CLIENT_LDAP_URI_NOSSL"])
	
		if not self.check_variables(vars):
			self.failed[3]=True
			return False
		else:
			self.failed[3]=False

		
		if os.path.exists("/usr/share/n4d/python-plugins/Golem.py"):
			vars["CLIENT_LDAP_URI_NOSSL"]="ldap://localhost"
				
				
		textrendered=tmpl.render(vars)
		tmp,filename=tempfile.mkstemp()
		f = open(filename,'w')
		f.writelines(textrendered)
		f.close()
		
		os.system("chmod 640 %s;chown root:nslcd %s"%(filename,filename))
		os.system("diff %s %s 1>/dev/null || { cp %s %s; systemctl restart nslcd; sleep 1; systemctl restart nslcd; } "%(filename,PamnssPlugin.NSLCD_DESTINATION,filename,PamnssPlugin.NSLCD_DESTINATION))
		os.remove(filename)
		return True
		
		
	#def configure_nslcd

	
	def backup(self,dir_=BACKUP_DEFAULT_PATH):
		
		file_path=dir_+"/"+get_backup_name("PamnssPlugin")
		self.backup_output=self.backup_configuration(file_path)
		return self.backup_output
		
	#def backup(self):
	
	def test(self):
		return [True, True]
	#def test(self):
	
	
	def restore(self,file_path=None):
		
		if file_path==None:
			for f in sorted(os.listdir("/backup"),reverse=True):
				if "PamnssPlugin" in f:
					file_path="/backup/"+f
					break			
		
		self.restore_output=self.restore_configuration(file_path)
		return self.restore_output
	#def restore(self):
	
	def restore_configuration(self, path):
		
		# Exists the file?
		if not os.path.exists(path):
			return [False, "[N4D]  PamnssPlugin -Restore- Tar File is not present"]
		
		# Extract to temporal directory
		path_to_work=tempfile.mkdtemp()
	
		tar=tarfile.open(path)
		tar.extractall(path_to_work)
		tar.close()
		
		path_to_work=path_to_work+"/"+self.__class__.__name__+"/"
		print path_to_work
		
		# First read the configuration from n4d-config-ini
		if not os.path.exists(path_to_work+"n4d-config.ini"):
			return [False, "[N4D] - PamnssPlugin -Restore- Configuration File is not present"]
	
		Config = ConfigParser.ConfigParser()
		Config.read(path_to_work+"n4d-config.ini")
		
		for section in Config.sections():
			
			# Read the config.ini
			back_file=Config.get(section,"file")
			dest_path= Config.get(section,"path")
			permissions=Config.get(section,"permissions")
			
			# Create path in destination if not exists
			if not os.path.isdir(os.path.dirname(dest_path)):
				os.makedirs(os.path.dirname(dest_path),0755)

			# Copy the file to destination
			shutil.copy(path_to_work+back_file,dest_path)
			print (path_to_work+back_file,dest_path)

		return [True, True]
		
	#def restore_configuration(self, path=BACKUP_DEFAULT_PATH):
		
	def backup_configuration(self,file_path):
		
			
		# Temporal directory to work
		path_to_work=tempfile.mkdtemp()+"/"

		# Create config to backup the files
		Config = ConfigParser.ConfigParser()
		backupCfg= open(path_to_work+"n4d-config.ini","w")

		# Copy the configuration files to the path
		try :
			
			# Copy LDAP files
			shutil.copy(PamnssPlugin.LDAP_DESTINATION,path_to_work+PamnssPlugin.LDAP_TEMPLATE)
			# Add to ini file backup info
			Config.add_section("LDAP")
			Config.set("LDAP", "FILE", PamnssPlugin.LDAP_TEMPLATE)
			Config.set("LDAP","PATH",PamnssPlugin.LDAP_DESTINATION)
			Config.set("LDAP","PERMISSIONS","0644")
			
			# Copy LDAP CLIENT
			shutil.copy(PamnssPlugin.LDAP_ENVIRONMENT_CLIENT_DESTINATION,path_to_work+PamnssPlugin.LDAP_ENVIRONMENT_CLIENT_TEMPLATE)
			# Add to ini file backup info
			Config.add_section("LDAPENVIRONMENT")
			Config.set("LDAPENVIRONMENT", "FILE", PamnssPlugin.LDAP_ENVIRONMENT_CLIENT_TEMPLATE)
			Config.set("LDAPENVIRONMENT","PATH",PamnssPlugin.LDAP_ENVIRONMENT_CLIENT_DESTINATION)
			Config.set("LDAPENVIRONMENT","PERMISSIONS","0644")
			
			# Copy nsswitch
			shutil.copy(PamnssPlugin.NSSWITCH_DESTINATION,path_to_work+PamnssPlugin.NSSWITCH_TEMPLATE)	
			# Addd to ini file backup Infoe
			Config.add_section("NSSWITCH")
			Config.set("NSSWITCH","FILE",PamnssPlugin.NSSWITCH_TEMPLATE)
			Config.set("NSSWITCH","PATH",PamnssPlugin.NSSWITCH_DESTINATION)
			Config.set("NSSWITCH","PERMISSIONS","0644")
			
			# Copy nslcd
			shutil.copy(PamnssPlugin.NSLCD_DESTINATION,path_to_work+PamnssPlugin.NSLCD_TEMPLATE)	
			# Addd to ini file backup Infoe
			Config.add_section("NSLCD")
			Config.set("NSLCD","FILE",PamnssPlugin.NSLCD_TEMPLATE)
			Config.set("NSLCD","PATH",PamnssPlugin.NSLCD_DESTINATION)
			Config.set("NSLCD","PERMISSIONS","0644")
			
			# Close the ini.file
			Config.write(backupCfg)
			backupCfg.close()

			# Create tar.gz
			date_tar_gz=datetime.date.today().__str__()
			path_to_backup=file_path
			
			# Resolve if the file is present
			if os.path.exists(path_to_backup):
				os.remove(path_to_backup)
			
			tar = tarfile.open(path_to_backup,"w:gz")
			tar.add(path_to_work,arcname=self.__class__.__name__)
			tar.close()

			return [True, path_to_backup]
			
		except IOError as e:
			
			# something is going wrong
			return [False, "[N4D] I/O error({0}): {1}".format(e.errno, e.strerror)]
	#def backup_configuration(self,path=BACKUP_DEFAULT_PATH):
			

	def check_network_authentication(self):
		
		if  self.nsswitch_enable and self.ldap_enable : 
			return [True,True]
		else:
			return [True,False]
	#def check_network_authentication(self):

#class PamnssPlugin

if __name__=="__main__":
	print ("[N4D] Debug Pamnss")
	pp=PamnssPlugin()
	#print pp.backup()
	#print pp.configure_ldap()
	#print name_backup
	#print pp.restore_configuration("/backup/n4d/PamnssPlugin-2012-10-04.tar.gz")
	
	
	
