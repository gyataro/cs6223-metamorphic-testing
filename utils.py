import re
import json
import time
import signal
import subprocess
from datetime import datetime

import yaml
import falco
import docker
from lark import Tree

from falco_parser import FalcoParser, ExpandMarcos, ExpandLists
from entities import FalcoRule, Rules, Macros, Lists


def load_syscalls(syscalls_path: str) -> set[str]:
    """Load syscall vocabulary from .txt file.
    """
    syscalls = []

    with open(syscalls_path) as f:
        syscalls = f.read().splitlines()

    return set(syscalls)


def load_seeds(rule_path: str, seed_path: str, parser: FalcoParser) -> list[tuple[str, Tree]]:
    """Load and process all rules from a .yaml file, keep those listed in the seed corpus.
    """
    def _import_rules(rule_path: str) -> tuple[Rules, Macros, Lists]:
        """
        Import a .yaml file containing Falco rules, lists, and macros.
        Expand macros and lists in rules with their actual referenced values.
        
        Args:
            rule_path: path to a .yaml rule file

        Returns
            dict: a dict mapping rule names to expanded Falco rules
        """
        falco_rules: dict[str, FalcoRule] = {}
        lists = {}
        macros = {}

        # Load Falco rules, lists, macros
        with open(rule_path, "r") as f:
            items: list[dict] = yaml.safe_load(f)
            for item in items:
                if "macro" in item:
                    macro_name = item.get("macro")
                    macro_condition: str = item.get("condition")
                    macro_condition = " ".join(macro_condition.split())
                    macros[macro_name] = macro_condition 

                elif "list" in item:
                    list_name = item.get("list")
                    list_items = item.get("items")
                    lists[list_name] = list_items 

                elif "rule" in item:
                    rule = item.get("rule")
                    desc = item.get("desc")
                    output = item.get("output")
                    priority = item.get("priority")
                    condition: str = item.get("condition")
                    condition = " ".join(condition.split())
                    rule_name: str = re.sub(r'[^a-zA-Z]+', ' ', rule)
                    rule_name = ''.join(word.lower() for word in rule_name.split())
                    falco_rule = FalcoRule(rule=rule, desc=desc, condition=condition, output=output, priority=priority)
                    falco_rules[rule_name] = falco_rule

        return falco_rules, macros, lists
    
    rules, macros, lists = _import_rules(rule_path)
    seed_names = open(seed_path).read().splitlines()
    seeds = {}

    for seed_name in seed_names:
        name = seed_name.split(".")[-1]
        rule = rules[name.lower()]
        tree: Tree = parser.to_tree(rule.condition)
        tree = ExpandMarcos(macros, parser).transform(tree)
        tree = ExpandLists(lists).transform(tree)
        seeds[seed_name] = tree

    return list(seeds.items())


def run_falco(falco_path: str, falco_config_path: str, rule_file: str, options: list[str] = []) -> subprocess.Popen:
    """Run Falco.
    """
    falco_command = [falco_path, "-c", falco_config_path, "-r", rule_file] + options
    falco_process = subprocess.Popen(falco_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    launch_logs = []
    success = False

    for line in falco_process.stderr:
        launch_logs.append(line)
        if "Starting gRPC server" in line:
            success = True
            break

    if not success: 
        falco_process.terminate()
        raise ChildProcessError("\n".join(launch_logs))

    return falco_process


def run_attack(rule_name: str):
    """Run Falco event-generator attack that corresponds to a specific rule by name.
    """
    success = False
    client = docker.from_env()
    client.containers.run("falcosecurity/event-generator")
    container = client.containers.run(
        image="falcosecurity/event-generator",
        command=["run", rule_name],
        name="falco-eventgen",
        remove=True,
        detach=True,
        auto_remove=True,
        privileged=True,
        userns_mode="host"
    )

    success = True
    attack_logs = []
    for line in container.logs(follow=True, stream=True):
        attack_logs.append(line)
        if "action executed" in line.decode('utf-8'):
            success = True

    if not success: raise ChildProcessError("\n".join(line))


def get_alerts(start_time: float, client: falco.Client, rule_file: str) -> tuple[bool, float]:
    """Check alerts produced by Falco
    """
    def _timeout(signum, frame):
        raise TimeoutError()

    try:
        now = datetime.now()
        alert_time = -1
        alert = False
        signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(30) 
        for event in client.sub():
            event: dict = json.loads(event)

            if (event["rule"] == "r" and not alert and rule_file in event["output"]):
                alert = True
                event_time = event["output_fields"]['evt.time']
                event_time = event_time[:event_time.index('.') + 7]
                event_time = datetime.strptime(event_time, "%H:%M:%S.%f")
                event_time = event_time.replace(year=now.year, month=now.month, day=now.day)  
                alert_time = now.timestamp() - event_time.timestamp() # detect_time.timestamp() - start_time

            if alert:
                break

    except TimeoutError:
        pass

    finally:
        signal.alarm(0)  

    return alert, alert_time

                
def remove_containers():
    """Remove all stopped falcosecurity/event-generator containers used in attacks.
    """
    result = subprocess.run(
        [
            "docker", "ps", "-a", "--filter", f"ancestor=falcosecurity/event-generator", 
            "--format", "{{.ID}} {{.Image}} {{.Status}}"
        ],
        capture_output=True,
        text=True,
        check=True
    )
    
    containers = result.stdout.strip().split('\n')
    
    for container_info in containers:
        if container_info:
            container_id, _, status = container_info.split(maxsplit=2)
            
            # Check if the container is stopped (status contains "Exited")
            if "Exited" in status:
                print(f"\tRemove {container_id}")
                subprocess.run(["docker", "rm", container_id], stdout=subprocess.PIPE, check=True)