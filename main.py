import os
import time
import json
import signal
import random
import tempfile
import subprocess

import yaml
import falco
import docker

from falco_parser import FalcoParser
from transform import ExtractSyscalls, InsertDeadSubtrees
from utils import load_syscalls, load_seeds, prepare_test_samples


base_path = os.path.abspath(os.path.dirname(__file__))
rule_path = os.path.join(base_path, "falco_rules.yaml")
seed_path = os.path.join(base_path, "falco_seed.txt")
falco_path = os.path.join(base_path, "falco_binary")
falco_config_path = os.path.join(base_path, "falco.yaml")
syscalls_path = os.path.join(base_path, "syscalls", "x86_64.txt")


def run_falco(rule_file: str) -> subprocess.Popen:
    """Run Falco.
    """
    falco_command = [falco_path, "-c", falco_config_path, "-r", rule_file]
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


def get_alerts(client: falco.Client) -> tuple[bool, bool, float, float]:
    """Check alerts produced by Falco
    """
    def _timeout(signum, frame):
        raise TimeoutError()

    try:
        alert_time, alert_prime_time = -1, -1
        alert, alert_prime = False, False
        start_time = time.perf_counter()
        signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(20) 
        for event in client.sub():
            event: dict = json.loads(event)

            if (event["rule"] == "r" and not alert and tmp.name in event["output"]):
                alert = True
                alert_time = time.perf_counter() - start_time
            if (event["rule"] == "r_prime" and not alert_prime and tmp.name in event["output"]):
                alert_prime = True
                alert_prime_time = time.perf_counter() - start_time
            if alert and alert_prime: 
                break

    except TimeoutError:
        pass

    finally:
        signal.alarm(0)  

    return alert, alert_prime, alert_time, alert_prime_time

                
def cleanup():
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
                print(f"\tCleanup {container_id}")
                subprocess.run(["docker", "rm", container_id], stdout=subprocess.PIPE, check=True)


if __name__ == "__main__":
    RNG_SEED = 42
    ROUNDS = 10
    SAMPLE_RNG = random.Random(RNG_SEED)
    SHUFFLE_RNG = random.Random(RNG_SEED)
    SYSCALLS = load_syscalls(syscalls_path)
    
    parser = FalcoParser()
    mutator = InsertDeadSubtrees(SYSCALLS, iterations=(2, 10), p=0.1, seed=RNG_SEED)
    seeds = load_seeds(rule_path, seed_path, parser)
    blacklist_syscalls = {name: ExtractSyscalls().visit(tree) for (name, tree) in seeds}
    
    for i in range(len(seeds)):
        name, tree = seeds[i] #SAMPLE_RNG.choice(seeds)
        print(f"Round {i+1}/{len(seeds)}: {name}")

        with tempfile.NamedTemporaryFile(delete_on_close=False) as tmp:
            # Insert dead subtrees into rule tree
            print(f"\tMutating rule")
            tree_prime = mutator.transform(tree, blacklist_syscalls[name])
            
            # Prepare rules in temp .yaml file
            print(f"\tPreparing rules at {tmp.name}")
            os.chmod(tmp.name, 0o777)
            rule_prime = parser.to_rule(tree_prime)
            rule = rule_prime # parser.to_rule(tree)
            rules = prepare_test_samples(rule, rule_prime, tmp.name)
            SHUFFLE_RNG.shuffle(rules)
            with open(tmp.name, 'w') as f:
                rules_yaml = yaml.dump(rules, default_flow_style=False, width=float("inf"))
                f.write(rules_yaml)

            # Launch Falco with the rules
            try:
                print(f"\tLaunching Falco")
                falco_process = run_falco(tmp.name)
            except Exception as e:
                print(f"\tLaunch failed: \n{e}")
                continue

            # Initialize Falco client
            client = falco.Client(endpoint="unix:///run/falco/falco.sock", output_format="json")
            time.sleep(5)

            # Launch attack
            try:
                print(f"\tLaunching attack")
                success = run_attack(name)
            except Exception as e:
                print(f"\tAttack failed: \n{e}")
                cleanup()
                continue
            
            # Check alerts
            try:
                print(f"\tChecking alerts")
                alert, alert_prime, alert_time, alert_prime_time = get_alerts(client)
                alert_status = f"\033[0;32m{True}\033[0m" if alert else f"\033[0;31m{False}\033[0m"
                alert_prime_status = f"\033[0;32m{True}\033[0m" if alert_prime else f"\033[0;31m{False}\033[0m"
                print(f"\tChecked events: [r] {alert_status} ({alert_time:.5f}) | [r'] {alert_prime_status} ({alert_prime_time:.5f})")
            except Exception as e:
                print(f"\tCheck failed: {e}")
                cleanup()
                continue


            # Cleanup: delete client, stop Falco, remove containers
            try:
                print("\tCleanup")
                del client
                falco_process.terminate()
                cleanup()
                time.sleep(2)
            except Exception as e:
                print(f"\tCleanup failed: {e}")
                continue