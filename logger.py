import os
import logging
from datetime import datetime
from dataclasses import dataclass


@dataclass
class RQ1Entry:
    round: int
    seed: str
    label: str
    length: int
    alert: bool
    time: float
    returncode: int

    def __str__(self):
        return f"{self.round},{self.seed},{self.label},{self.length},{self.alert},{self.time},{self.returncode}"


@dataclass
class RQ2Entry:
    n: int
    exclude: list
    seed: str
    label: str
    length: int
    alert: bool
    time: float
    returncode: int

    def __str__(self) -> str:
        exclude = ";".join(self.exclude)
        return f"{self.n},{exclude},{self.seed},{self.label},{self.length},{self.alert},{self.time},{self.returncode}"


class Logger:
    def __init__(self, name: str) -> None:
        timestamp = datetime.now().strftime("%y%m%d-%H%M%S")
        base_path = os.path.abspath(os.path.dirname(__file__))
        self.logs_path = os.path.join(base_path, "logs", f"{timestamp}-{name}")
        os.makedirs(self.logs_path)

        # Entries
        self.entries_path = os.path.join(self.logs_path, "entries.csv")
        with open(self.entries_path, "w") as f:
            f.write("round,seed,label,length,alert,time,returncode\n")

        # Logs
        self.logger = logging.getLogger(name)
        self.logger.setLevel("DEBUG")

        # Set up file handler for logger
        file_handler = logging.FileHandler(os.path.join(self.logs_path, "experiment.log"))
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        self.logger.addHandler(file_handler)

        # Set up console handler for logger
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(console_handler)

    def log(self, message: str):
        self.logger.info(message)

    def entry(self, entry: RQ1Entry | RQ2Entry):
        with open(self.entries_path, "a") as f:
            f.write(f"{str(entry)}\n")

    def sample(self, filename: str, sample: str):
        sample_path = os.path.join(self.logs_path, f"{filename}.txt")
        with open(sample_path, "w") as f:
            f.write(sample)