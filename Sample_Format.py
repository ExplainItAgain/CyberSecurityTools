""" Provide a sample format for my python modules

Functions:
write_host
 """

import logging
import sys

##################
# Logging Config #
##################

FORMAT = "%(asctime)s: %(levelname)s: %(message)s (File %(filename)s: Function %(funcName)s: Line %(lineno)d)"
handlers = [logging.StreamHandler(sys.stdout)]
# Optional: handlers.append(logging.FileHandler(log_path, "a"))
logging.basicConfig(
    level=logging.INFO,
    datefmt='%H:%M:%S',
    format=FORMAT,
    handlers=handlers
)

def write_host(content: str, sep="")->None:
    """Outputs to the host

    Arguments:
    content (type=str) -- item to print (default "")
    """
    print(content, sep = sep)

write_host("hello world")
