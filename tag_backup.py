##############################################################################
#
# Tag backup
# File: tag_backup.py
#
# Script handling the backup of tagged files with a specific Mac OS tag.
# The tagged files are archived and encrypted before being uploaded in the
# cloud service HubiC.
# Access to HubiC is achived thanks to the module lhubic written by Philippe
# Larduinat: https://github.com/philippelt/lhubic
#
# This software is released under the MIT licence
#
# Copyright (c) 2016 Jean-Baptiste Quelard
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
###############################################################################
#!/usr/bin/python

import os
import sys
import json
import xattr
import zipfile
import zlib
import hashlib
import gnupg
import datetime
import argparse
import getpass

try:
  import lhubic
except ImportError:
  print "lhubic module required"
  print "Please visit: https://github.com/philippelt/lhubic"
  exit(1)


GPG_HOME = "~/.gnupg"
BACKUP_TAG_NAME = "Backup" # The name given to the Mac OS tag
BLOCKSIZE = 65536
BACKUP_INFO_FILE = "tag_backup/backup_data" # File containing the information about the backup
TAG_BACKUP_CONFIG_FILE = ".tag_config" # Script configuration file
DESCRIPTION = """
Backup script for encrypting and uploading archived files to a cloud service (Hubic)"""


class styles:
  """ Terminal output styling """

  GREEN = '\033[92m'
  YELLOW = '\033[93m'
  RED = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'


class status:
  """ Colored statuses for the terminal """

  OK = "[  %sOK%s  ]" % (styles.GREEN,styles.ENDC)
  FAIL = "[ %sFAIL%s ]" % (styles.RED,styles.ENDC)
  WARNING = "[ %sWARN%s ]" % (styles.YELLOW,styles.ENDC)
 
# Helper functions
def print_status(message,status):
  """
    Helper function for printing the outcome of an operation.
  """
  print "{:<80} {:<10}".format(message, status)


def get_file_hash(filename):
  """ Returns the sha1 hash of the given file """

  hasher = hashlib.sha1()
  with open(filename, 'rb') as fp:
    block = fp.read(BLOCKSIZE)
    while len(block) > 0:
        hasher.update(block)
        block = fp.read(BLOCKSIZE)
  return hasher.hexdigest()


def get_file_md5(filename):
  """ Returns the md5 hash of the given file """

  hasher = hashlib.md5()
  with open(filename, 'rb') as fp:
    block = fp.read(BLOCKSIZE)
    while len(block) > 0:
        hasher.update(block)
        block = fp.read(BLOCKSIZE)
  return hasher.hexdigest()


class cloud_storage:
  """ Base class for the cloud storage service """

  def __init__(self,config,password):

    try:
      self.cloud = lhubic.Hubic(client_id=config["app_id"],
				client_secret=config["app_password"],
				username=config["username"],
				password=password)
    except Exception as e:
      print_status("Cloud client initialization:", status.FAIL)
      print "  %s%s%s" % (styles.RED,e,styles.ENDC)


  def init_storage(self):
    """ Function checking if the cloud storage can be initialized """

    self.authenticate()

    header, object_list = self.cloud.get_container("default", delimiter="/")
    if [item["subdir"] for item in object_list if item.get("subdir") == "tag_backup/"]:
      print "%s%sWarning!%s Tag Backup has found some backup data in the remote storage" % \
	(styles.YELLOW,styles.BOLD,styles.ENDC)
      print "Clean the storage before initialization."
      exit(1)


  def authenticate(self):
    """ Function calling the authentication method for the cloud storage """

    sys.stdout.write("Cloud storage authentication...\r")
    sys.stdout.flush()
    try:
      self.cloud.os_auth()
      print_status("Cloud storage authentication", status.OK)
    except Exception as e:
      print_status("Cloud storage authentication", status.FAIL)
      print "Error: %s" % e
      exit(1)


  def check_free_space(self):
    """ Function indicating the percentage of free space on the remote storage """

    sys.stdout.write("Check free space...\r")
    sys.stdout.flush()

    header, containers = self.cloud.get_account()
    total = int(header["x-account-meta-quota"])
    used = int(header["x-account-bytes-used"])
    free = 100 - used / float(total) * 100
    if free < 10:
      print_status("Check free space: %d%% free only!" % free, status.WARN)
    else:
      print_status("Check free space: %d%% free" % free, status.OK)


  def push_backup_data(self,enc_backup_data):
    """ Function uploading the encrypted backup data to the cloud storage """

    sys.stdout.write("Uploading backup data...\r")
    sys.stdout.flush()
    try:
      self.cloud.put_object("default",BACKUP_INFO_FILE,enc_backup_data)
      print_status("Uploading backup data", status.OK)
    except Exception as e:
      print_status("Uploading backup data", status.FAIL)
      print "  %s%s%s" % (styles.RED,e,styles.ENDC)
      exit(1)


  def get_backup_data(self):
    """ Function retrieving the encrypted backup data from the remote storage """

    sys.stdout.write("Fetching backup data...\r")
    sys.stdout.flush()

    try:
      stats, content = self.cloud.get_object("default", BACKUP_INFO_FILE)
      print_status("Fetching backup data", status.OK)
    except Exception as e:
      print_status("Fetching backup data", status.FAIL)
      print "  %s%s%s" % (styles.RED,e,styles.ENDC)
      exit(1) # Exit on failure

    return content


  def upload_file(self,filename):
    """ Upload the given file to the cloud storage """

    # Get the encrypted archive name
    encrypted_archive = os.path.basename(os.path.normpath(filename)) + ".gpg"
    print "Uploading %s" % encrypted_archive
    with open(filename + ".gpg", "rb") as f:
      file_hash = self.cloud.put_object("default", "tag_backup/" + encrypted_archive, f.read())

    # Compare the hash returned to verify the uploaded archive's integrity
    calculated_hash = get_file_md5(encrypted_archive)
    if file_hash == calculated_hash:
      print "File integrity verification: %sPASSED%s" % (styles.GREEN, styles.ENDC)
      return True
    else:
      print "File integrity verification: %sFAILED%s" % (styles.RED, styles.ENDC)
      print "Calculated MD5: %s" % calculated_hash
      print "Returned MD5: %s" % file_hash 
      return False

  
  def delete_file(self,filename):
    """ Delete the given file from the cloud storage """

    try:
      self.cloud.delete_object("default", filename)
    except Exception as e:
      print "Deletion of %s failed with the following error: %s" % (filename, e)


class backup_handler:
  """ Base class for the backup handler """

  def __init__(self):
    self.backup_data = []
    self.config = {}
    self.gpg = gnupg.GPG(gnupghome=GPG_HOME)
    self.archives_list = []


  def init_backup(self):
    """
      Initialize what's needed for the backup script:
      credentials, encryption password, directories to back up.
    """

    print "%s-- Tag Backup Configuration --%s" % (styles.BOLD, styles.ENDC)
   
    # The user has to provide these info:
    username = raw_input("Cloud service username (login): ")
    self.password = getpass.getpass("Cloud service password: ")
    app_id = raw_input("Application identifier: ")
    app_password = raw_input("Application password: ")
    enc_passphrase = raw_input("Encryption passphrase: ")
    paths = raw_input("Directories to backup (comma separated): ")

    self.config = {"username":username,
		    "app_id":app_id,
		    "app_password":app_password,
		    "enc_passphrase":enc_passphrase,
		    "paths":[]}

    # Write config file
    with open(TAG_BACKUP_CONFIG_FILE,"w") as f:
      f.write(json.dumps(self.config))

    # Add the directories to backup up
    self.add_paths(paths)

    # Create an instance of the remote storage
    cloud = cloud_storage(self.config,self.password)
    # Check if it can be initialized
    cloud.init_storage()
    # Upload an empty backup data file
    enc_backup_data = tag_backup.encrypt_backup_data(json.dumps(self.backup_data))
    cloud.push_backup_data(str(enc_backup_data))


  def add_paths(self,paths):
    """
      Function adding the given paths to the repositories to be walked through
      to the script configuration file.
    """

    self.load_config()
    paths_list = paths.split(',')
    # Remove last '/' if present
    formatted_paths_list = [path[:-1] if path.endswith('/') else path for path in paths_list]
    self.config["paths"] += formatted_paths_list

    # Write the config file
    with open(TAG_BACKUP_CONFIG_FILE,"w") as f:
      f.write(json.dumps(self.config))


  def delete_paths(self,paths):
    """
      Function removing the given paths to the repositories to be walked through
      from the script configuration file.
    """
    
    self.load_config()
    paths_list = paths.split(',')
    
    for path in paths_list:
      try:
	self.config["paths"].remove(path)
      except Exception as e:
	print "%sError: can't remove path '%s'\nIs this path in the configuration?%s" % \
	  (styles.RED,path,styles.ENDC)

    # Write config file
    with open(TAG_BACKUP_CONFIG_FILE,"w") as f:
      f.write(json.dumps(self.config))


  def list_paths(self):
    """
      Function listing the paths to the repositories to be walked through
      by the backup script.
    """

    self.load_config()

    print "Tag Backup will walk the following directories:"
    for directory in self.config["paths"]:
      print directory


  def perform_backup(self):
    """
      Function handling the whole backup process.
    """

    print "%s-- Tag Backup --%s" % (styles.BOLD, styles.ENDC)

    # Load the configuration parameters needed for authenticating to the
    # cloud service as well as decrypting the backup data.
    self.load_config()
    self.password = getpass.getpass("Cloud service password: ")
    # Create an instance of the cloud storage
    self.cloud = cloud_storage(self.config,self.password)
    self.cloud.authenticate() 
    self.cloud.check_free_space()
    # Fetch the encrypted backup data from the remote storage
    encrypted_data = self.cloud.get_backup_data()
    decrypted_data = self.decrypt_backup_data(encrypted_data) # Decrypt the backup data
    self.cloud_backup_data = json.loads(str(decrypted_data))
    # Generate the local backup data based on the current tags and to be compared
    # with the fetched backap data
    self.generate_backup_data()
    # Compare the local and remote backup data to determine what needs to be
    # (re)archived / (re)uploaded
    self.compare_backup_data()
    # Generates the archives for each modified/new directory to be backed up
    self.generate_archives()
    self.encrypt_files()
    self.upload_archives()


  def load_config(self):
    """
      Function loading the configuration from the config file .tag_config.
      The configuration contains essential information about authentication
      to the cloud service and the passphrase used for encrypting the files.
    """
    
    try:
      with open(TAG_BACKUP_CONFIG_FILE,"r") as f:
	self.config = json.loads(f.read())
    except Exception as e:
      print "%sError:%s Failed to fetch configuration file with the following error: %s" % \
	    (styles.RED,styles.ENDC,e)
      exit(1)


  def encrypt_files(self):
    """ 
      Encrypt the archives in archives_list with the configured passphrase
      and using 256bit AES. (No GPG key used but symmetric encryption instead)
      The encrypted archives keep the same name but the .gpg extension is added
    """

    sys.stdout.write("Encrypting archives...\r")

    for filename in self.archives_list:
      encrypted_file = filename + ".gpg"
      with open(filename,"rb") as fp:
	self.gpg.encrypt_file(fp,None,passphrase=self.config["enc_passphrase"],
			      symmetric="AES256",output=encrypted_file)

    print_status("Encrypting archives", status.OK)


  def encrypt_backup_data(self,data):
    """
      Encrypt the given backup data with the configured passphrase
      and using 256bit AES. (No GPG key used but symmetric encryption instead)
      The encrypted data is returned.
    """
    
    sys.stdout.write("Encrypting backup data...\r")

    encrypted_data = self.gpg.encrypt(data,None,passphrase=self.config["enc_passphrase"],symmetric="AES256")
    print_status("Encrypting backup data", status.OK)
    return encrypted_data


  def decrypt_backup_data(self,encrypted_data):
    """
      Decrypt the given encrypted backup data with the configured passphrase.
      The decrypted data is returned.
    """

    sys.stdout.write("Decrypting backup data...\r")

    decrypted_data = self.gpg.decrypt(encrypted_data,passphrase=self.config["enc_passphrase"])
    print_status("Decrypting backup data", status.OK)
    return decrypted_data


  def generate_backup_data(self):
    """
      Generate the local backup data. The directories listed in the config file
      will be walked through to get a backup schema based on the tagged files
      to back up.
    """

    sys.stdout.write("Preparing backup...\r")
    sys.stdout.flush()

    archives_names = []
    for dir_to_check in self.config["paths"]:
      for root, dirs, files in os.walk(dir_to_check):
	if files:
	  backup_files = []
	  for f in files:
	    path = os.path.join(root,f)
	    attrs = xattr.xattr(path)
	    # Check if the file is tagged
	    try:
	      tags_attr = attrs["com.apple.metadata:_kMDItemUserTags"]
	      if BACKUP_TAG_NAME in tags_attr:
		# Calculate the hash in order to determine if the file
		# has been modified since the last backup.
		file_hash = get_file_hash(path)
		backup_files.append({"name":f,"hash":file_hash})	 
	    except KeyError:
	      pass # File is not tagged, just pass.

	  # If some tagged files have been found in this directory
	  if backup_files:
	    # Generate an archive name for this directory
	    # To do so, both the directory name and its parent's name are combined
	    directory = {}
	    archive_name = os.path.basename(os.path.normpath(root))
	    archive_name = os.path.split(os.path.dirname(root))[1] + "_" + archive_name

	    # If the name already exists, then it can't be backed up
	    if archive_name in archives_names:
	      print "%sWARNING!%s The directory %s cannot be backed up." % (styles.RED,styles.ENDC,root)
	      print "Its archive name is already used."
	    else:
	      directory[root] = {"archive_name":archive_name,"files":backup_files}
	      self.backup_data.append(directory) 
	      archives_names.append(archive_name) # Append the name to the list

    print_status("Preparing backup", status.OK)


  def compare_backup_data(self):
    """
      Compare the local and the remote backup data.
      Populate a list of directories that need to be (re)archived and
      backed up as well as a list of directories that should be removed
      from the cloud storage.
    """

    # Get the list of directories that differ from the cloud backup list
    # This gives the directories for which the backuped version differ
    # or that have not been backed up yet.
    self.dirs_to_update = [directory for item in self.backup_data
				     for directory in item
				     if item not in self.cloud_backup_data]

    # Get the list of directories that need to be archived
    local_dir_list = [directory for item in self.backup_data for directory in item]

    # Get the list of directories that differ from the local backup_list
    # This gives the directories that have been backed up but are no
    # longer needed as they don't appear in the local directories list.
    self.dirs_to_remove = [directory for item in self.cloud_backup_data
				     for directory in item
				     if directory not in local_dir_list] 


    if not self.dirs_to_update and not self.dirs_to_remove:
      print "%sCloud backup is up-to-date%s" % (styles.GREEN, styles.ENDC)
      exit() # No need to go further

    # User feedback
    print "%s%d%s directories need to be backed up" % \
	(styles.BOLD,len(self.dirs_to_update),styles.ENDC)
    for directory in self.dirs_to_update:
      print " " + directory
    print "%s%d%s directories no longer need backup" % \
	(styles.BOLD,len(self.dirs_to_remove),styles.ENDC)
    for directory in self.dirs_to_remove:
      print " " + directory


  def generate_archives(self):
    """
      Generate the archives of the files to back up.
      The name of the archive is then added to the list of archives
      to be uploaded.
    """

    count = 0 # for user feedback
    for item in self.backup_data:
      for directory in item:
	# Check if the directory needs to be archived
	if directory in self.dirs_to_update:
	  count += 1
	  sys.stdout.write("Generating archives... %d/%d\r" % (count, len(self.dirs_to_update)))
	  sys.stdout.flush()

	  # Get the archive name from the local backup data
	  archive_name = item[directory]["archive_name"] + ".zip"
	  zf = zipfile.ZipFile(archive_name, mode='w')
	  try:
	    # Add the tagged files to the archive
	    for filename in item[directory]["files"]:
	      zf.write(os.path.join(directory,filename["name"]),compress_type=zipfile.ZIP_DEFLATED)
	  finally:
	    zf.close()
	    self.archives_list.append(os.path.join(os.getcwd(),archive_name))

    print_status("Generating archives", status.OK)


  def upload_archives(self):
    """
      Handle the deletion and the uploading to the cloud storage.
      First the archives that should be removed are deleted.
      Then the archives to be backed up are uploaded.
      If archive integrity check has failed, then it is retried once.
    """

    # Contains the list of archives that couldn't be uploaded successfully
    failed_uploads = []

    # Delete the archives that don't need backup anymore
    for directory in self.dirs_to_remove:
      # Retrieve the archive name
      archive_name = ''.join(item[directory]["archive_name"] for item in self.cloud_backup_data
							     for dir_path in item if dir_path == directory)

      archive_name = "tag_backup/" + archive_name + ".zip.gpg"
      self.cloud.delete_file(archive_name)

    if self.dirs_to_remove:
      print_status("Deprecated archives deletion", status.OK)

    # Upload the archives that need to be backed up
    for archive in self.archives_list:
      if self.cloud.upload_file(archive):
	# delete both encrypted and clear archives on success
	os.remove(archive)
	os.remove(archive + ".gpg")
      else:
	# Retry
	failed_uploads.append(archive)

    # Retry failed uploads
    for archive in failed_uploads:
      if self.cloud.upload_file(archive):
	# delete both encrypted and clear archives on success
	os.remove(archive)
	os.remove(archive + ".gpg")

    # When all the archives are successfully uploaded, update the remote
    # backup data
    if not failed_uploads:
      enc_backup_data = self.encrypt_backup_data(json.dumps(self.backup_data))
      self.cloud.push_backup_data(str(enc_backup_data))


if __name__ == "__main__":

  parser = argparse.ArgumentParser(description=DESCRIPTION)

  parser.add_argument('-i','--init', dest='init', action='store_true',
                   help='Initialize Tag Backup parameters')
  parser.add_argument('-a', '--add', dest='add_paths', action='store',
                   help='Add paths to the directories that the backup handler should include')
  parser.add_argument('-d', '--delete', dest='del_paths', action='store',
                   help='Delete paths to the directories that the backup handler include')
  parser.add_argument('-l', '--list', dest='list_paths', action='store_true',
                   help='List paths to the directories that the backup handler include')

  args = parser.parse_args()

  tag_backup = backup_handler() # Create an instance of the backup handler

  if args.add_paths:
    tag_backup.add_paths(args.add_paths)
    exit()

  if args.del_paths:
    tag_backup.delete_paths(args.del_paths)
    exit()

  if args.list_paths:
    tag_backup.list_paths()
    exit()

  if args.init:
    tag_backup.init_backup()
    exit()
  else:
    tag_backup.perform_backup()
    exit()
