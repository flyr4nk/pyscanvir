import sys
import os
import hashlib
import argparse
import logging
import requests
import json
import time
import pyinotify
import sched


from virustotal.virt import VirusTotal, VT_Response_Send
from eventhandler import DirectoryEventHandler

USAGE_PROGRAM = ('USAGE: pyscanvir.py [-o|--origin <directory_name>] '
                 '[-d|--destination <directory_name>] '
                 '[-q|--quarentine <directory_name>] ')

ERROR_PARAMS_MISSING = "Mandatory params missing"
ERROR_PARAMS_DIRECTORY = "Directory does not exists:{}"
MSG_EXITING = "\nExiting\n"


EXT_QRTN = ".QUARENTINE"
EXT_DTLS = ".DETAILS"


def process_pending(sc, vt, dir_event_handler, interval, destination, quarentine):
    if dir_event_handler.any_pending_send():
        filename = dir_event_handler.next_pending_send()
        print("Enviado:{}".format(filename))
        responses = vt.send_files_withresponse([filename, ])
        for res in responses:
            if res.status_code == VT_Response_Send.HTTP_OK:
                dir_event_handler.add_pending_response(filename, res.scan_id)
    elif dir_event_handler.any_pending_response():
        pr = dir_event_handler.next_pending_response()
        scan_id = pr[1]
        fullpath_filename = pr[0]
        print("Recuperando:{} {}".format(fullpath_filename, scan_id))
        res = vt.retrieve_report_withresponse(scan_id)
        if res.response_code == -2:
            print("Delaying...")
            dir_event_handler.add_pending_response(fullpath_filename, scan_id)
        elif res.response_code == 1:
            filename = os.path.basename(fullpath_filename)
            print("Result. Positives:{} Total{}".format(res.positives, res.total))
            if res.positives > 0:
                print("Moving to quarentine...")
                quarentine_filename = os.path.join(quarentine, filename)
                os.rename(fullpath_filename, quarentine_filename + EXT_QRTN)
                with open(quarentine_filename + EXT_DTLS, "w") as details_file:
                    details_file.write(res.res_text)
            else:
                print("Moving to destination...")
                os.rename(fullpath_filename, os.path.join(destination,filename))


    sc.enter(interval, 1, process_pending, (sc, vt, dir_event_handler, interval,destination, quarentine,))


def watchfiles(origin, destination, quarentine, vt, eh):
    """

    """
    interval = 20  # 20 segs (4 every minute) for a public api
    wm = pyinotify.WatchManager()
    wm.add_watch(origin, pyinotify.ALL_EVENTS)

    event_notifier = pyinotify.ThreadedNotifier(wm, eh)
    event_notifier.start()

    sc = sched.scheduler(time.time, time.sleep)
    sc.enter(interval, 1, process_pending, (sc, vt, eh, interval, destination, quarentine,))
    try:
        sc.run()
    except (KeyboardInterrupt, SystemExit):
        print(MSG_EXITING)
        event_notifier.stop()
        sys.exit()


def main(argv):

    parser = argparse.ArgumentParser(description='Virustotal File Scan')
    parser.add_argument("-p", "--private", help="the API key belongs to a private API service", action="store_true")
    parser.add_argument("-v", "--verbose", help="print verbose log (everything in response)", action="store_true")
    parser.add_argument("-o", "--origin", help="Origin directory of files to scan", metavar="PATH")
    parser.add_argument("-d", "--destination", help="Destination directory of clean files", metavar="PATH")
    parser.add_argument("-q", "--quarentine", help="Quarentine directory of not clean files", metavar="PATH")
    parser.add_argument("-l", "--log", help="log actions and responses in file", metavar="LOGFILE")
    args = parser.parse_args(argv)

    if args.origin:
        origin = args.origin

    if args.destination:
        destination = args.destination

    if args.quarentine:
        quarentine = args.quarentine

    if not (origin or destination or quarentine):
        print(ERROR_PARAMS_MISSING)
        print(USAGE_PROGRAM)
        sys.exit(2)

    if not os.path.isdir(origin):
        print(ERROR_PARAMS_DIRECTORY.format(origin))
        print(USAGE_PROGRAM)
        sys.exit(2)

    if not os.path.isdir(destination):
        print(ERROR_PARAMS_DIRECTORY.format(destination))
        print(USAGE_PROGRAM)
        sys.exit(2)

    if not os.path.isdir(quarentine):
        print(ERROR_PARAMS_DIRECTORY.format(quarentine))
        print(USAGE_PROGRAM)
        sys.exit(2)

    vt = VirusTotal()
    vt.is_verboselog = args.verbose
    with open(os.getenv("HOME") + '/.virustotal.api') as keyfile:
        vt.apikey = keyfile.read().strip()

    dir_event_handler = DirectoryEventHandler(vt)
    watchfiles(origin, destination, quarentine, vt, dir_event_handler)


if __name__ == "__main__":
    main(sys.argv[1:])
