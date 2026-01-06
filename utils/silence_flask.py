import sys

class DevNull:
    def write(self, *_):
        pass

    def flush(self):
        pass


def silence_flask():
    """
    Disable Flask / Werkzeug stdout & stderr spam
    """
    sys.stdout = DevNull()
    sys.stderr = DevNull()
