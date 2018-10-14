import pyinotify

from collections import deque


class DirectoryEventHandler(pyinotify.ProcessEvent):

    def __init__(self, vt):
        self._pending_send = deque()
        self._pending_response = deque()
        self._vt = vt

    def any_pending_send(self):
        return len(self._pending_send)

    def add_pending_send(self, filename):
        self._pending_send.append(filename)

    def next_pending_send(self):
        return self._pending_send.popleft()

    def any_pending_response(self):
        return len(self._pending_response)

    def add_pending_response(self, filename, scan_id):
        self._pending_response.append((filename, scan_id))

    def next_pending_response(self):
        return self._pending_response.popleft()

    def process_IN_MOVED_TO(self, event):
        try:
            print("Archivo Movido:{}".format(event.pathname))
            self.process_file(event.pathname)
        except Exception as inst:
            print(type(inst))

    def process_IN_CLOSE_WRITE(self, event):
        try:
            print("Nuevo archivo:{}".format(event.pathname))
            self.process_file(event.pathname)
        except Exception as inst:
            print(type(inst))

    def process_file(self, filename):
        self.add_pending_send(filename)
