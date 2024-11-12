import os
import time
import random
import tempfile

import yaml
import falco

from logger import Logger, RQ1Entry
from falco_parser import FalcoParser
from transform import ExtractSyscalls, InsertDeadSubtrees
from utils import (
    load_syscalls, 
    load_seeds,
    run_falco,
    run_attack,
    get_alerts,
    remove_containers
)

base_path = os.path.abspath(os.path.dirname(__file__))
rule_path = os.path.join(base_path, "falco_rules.yaml")
seed_path = os.path.join(base_path, "falco_seed.txt")
falco_path = os.path.join(base_path, "falco_binary")
falco_config_path = os.path.join(base_path, "falco.yaml")
syscalls_path = os.path.join(base_path, "syscalls", "x86_64.txt")


if __name__ == "__main__":
    RNG_SEED = 42
    ROUNDS = 10000
    SAMPLE_RNG = random.Random(RNG_SEED)
    SYSCALLS = load_syscalls(syscalls_path)
    
    logger = Logger("rq1")
    parser = FalcoParser()
    mutator = InsertDeadSubtrees(SYSCALLS, iterations=(2, 10), p=0.1, seed=RNG_SEED)
    seeds = load_seeds(rule_path, seed_path, parser)
    blacklist_syscalls = {name: ExtractSyscalls().visit(tree) for (name, tree) in seeds}
    
    for i in range(ROUNDS):
        # Initialize and get random seed
        abort = False
        falco_process, falco_client = None, None
        seed_name, tree = SAMPLE_RNG.choice(seeds)
        logger.log(f"Round {i+1}/{ROUNDS}: {seed_name}")

        # Insert dead subtrees into rule tree
        try:
            logger.log(f"\tMutating rule")
            tree_prime = mutator.transform(tree, blacklist_syscalls[seed_name])
        except Exception as e:
            logger.log(f"\tMutation failed: {e}")
            abort = True

        if abort: continue

        for t, label in [(tree, "r"), (tree_prime, "r'")]:
            with tempfile.NamedTemporaryFile(delete_on_close=False) as tmp:
                # Prepare rule in temp .yaml file
                try:
                    logger.log(f"\tPreparing rules at {tmp.name}")
                    os.chmod(tmp.name, 0o777)
                    rule = parser.to_rule(t)
                    logger.log(f"\tLength: ({len(rule)})")
                    rule_obj = {
                        "rule": "r", 
                        "desc": "r", 
                        "condition": rule, 
                        "output": tmp.name, 
                        "priority": "CRITICAL"
                    }
                    with open(tmp.name, 'w') as f:
                        rule_yaml = yaml.dump([rule_obj], default_flow_style=False, width=float("inf"))
                        f.write(rule_yaml)
                except Exception as e:
                    logger.log(f"\tPrepare rule failed: {e}")
                    abort = True

                # Launch Falco with the rules
                if not abort:
                    try:
                        logger.log(f"\tLaunching Falco")
                        falco_process = run_falco(falco_path, falco_config_path, tmp.name)
                    except Exception as e:
                        logger.log(f"\tLaunch failed: \n{e}")
                        abort = True

                # Initialize Falco client
                if not abort:
                    try:
                        falco_client = falco.Client(endpoint="unix:///run/falco/falco.sock", output_format="json")
                        time.sleep(5)
                    except Exception as e:
                        logger.log(f"\tClient failed: {e}")
                        abort = True

                # Launch attack
                if not abort:
                    try:
                        logger.log(f"\tLaunching attack")
                        success = run_attack(seed_name)
                    except Exception as e:
                        logger.log(f"\tAttack failed: \n{e}")
                        abort = True

                    from datetime import datetime
                    start_time = datetime.now().timestamp()
                
                # Check alerts
                if not abort:
                    try:
                        logger.log(f"\tChecking alerts")
                        alert, alert_time = get_alerts(start_time, falco_client, tmp.name)
                        alert_status = f"\033[0;32m{True}\033[0m" if alert else f"\033[0;31m{False}\033[0m"
                        logger.log(f"\tChecked events: [r] {alert_status} ({alert_time:.5f})")
                    except Exception as e:
                        logger.log(f"\tCheck failed: {e}")
                        abort = True

                # Record rules if they are interesting
                if abort or not alert:
                    logger.sample(filename=f"{i+1}-{label}.txt", sample=rule)

                # Cleanup: delete client, stop Falco, remove containers
                try:
                    logger.log("\tCleanup")
                    returncode = -9
                    remove_containers()

                    if falco_client: 
                        del falco_client

                    if falco_process: 
                        falco_process.kill()
                        returncode = falco_process.wait(5)

                except Exception as e:
                    logger.log(f"\tCleanup failed: {e}")
                finally:
                    entry = RQ1Entry(
                        round=i+1,
                        seed=seed_name,
                        label=label,
                        length=len(rule),
                        alert=alert,
                        time=alert_time,
                        returncode=returncode
                    )
                    logger.entry(entry)
                    abort = False
                    time.sleep(2)