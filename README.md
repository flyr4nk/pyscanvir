# pyscanvir

Is a proof-of-concept program using VirusTotal's APIv2.

The aim is to create software that detects new archives in a given origin
directory and check it via VirusTotal's APIv2, if any engine detects a
virus the file will be moved to a given quarentine directory. If everything goes
fine the file will be moved to a given destination directory.

It could be integrated in a NAS (Network Attached Storage) that check every new file before share it.



### USAGE:
```sh
pyscanvir.py [-o|--origin <directory_name>] [-d|--destination <directory_name>] [-q|--quarentine] <directory_name>
```
### Requisites:

pyinotify
requests
