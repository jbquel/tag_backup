# tag_backup
Backup script for uploading encrypted archives of tagged files to a cloud storage (hubiC)

This script requires **MacOS X** for tagging the files (tested on MacOS X 10.9.5)

## Before starting
1. Create a tag named "**Backup**" (the name is mandatory but the color is up to you)
2. Get **lhubic.py** from https://github.com/philippelt/lhubic
3. Create a client ID and a client Password from the "Developers" menu in your hubiC account

## Initialization
```
 $ ./tag_backup.py -i
```
Then provide the requested information:
```
Cloud service username (login): exemple@domain.com
Cloud service password: 
Application identifier: api_hubic_C0MsOjcLuLQSmg3s4lgGHzG8r90XzynJ
Application password: n098JVzEk6xXMi3lUsLCxc2lc3OUFXBPa8XA1hHTtPP7agpHBQ4VT3S1ybSOmZcv
Encryption passphrase: my encryption passphrase
Directories to backup (comma separated): ~/my_photos,~/my_documents
```

## Usage
1. Tag the files within the directories you have provided with the tag "Backup" you should have created.
2. Launch the script
```
$ ./tag_backup.py
```

## Notes
- Script and documation are under development
- Use "./tag_backup.py -h" to see the available commands
