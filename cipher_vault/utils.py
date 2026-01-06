import logging
from rich.logging import RichHandler

def setup_logging(level=logging.INFO):
    """
    Sets up a professional logging configuration using Rich.
    """
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)]
    )
    return logging.getLogger("cipher_vault")
