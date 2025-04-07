import logging

from rich.logging import RichHandler

def setup_logging(level: int = logging.INFO):
    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
    stdout_handler = RichHandler(rich_tracebacks=True, show_time=False, show_level=True, show_path=False)

    file_handler = logging.FileHandler("app.log")
    file_handler.setLevel(logging.DEBUG)

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[stdout_handler, file_handler],
    )