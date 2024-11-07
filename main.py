import os
import time
import json
import tempfile
import subprocess

import falco
import docker

from falco_parser import FalcoParser
from utils import load_seeds, prepare_test_samples


base_path = os.path.abspath(os.path.dirname(__file__))
rule_path = os.path.join(base_path, "falco_rules.yaml")
seed_path = os.path.join(base_path, "falco_seed.txt")
falco_path = os.path.join(base_path, "falco_binary")
falco_config_path = os.path.join(base_path, "falco.yaml")


def run_falco(rule_file: str) -> subprocess.Popen:
    """Run Falco.
    """
    falco_command = [falco_path, "-c", falco_config_path, "-r", rule_file]
    falco_process = subprocess.Popen(falco_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    try:
        for line in falco_process.stderr:
            if "Starting gRPC server" in line:
                print(f"\tLaunch success")
                break

    except Exception as e:
        print(f"\tLaunch failed: {e}")

    return falco_process


def run_attack(rule_name: str) -> bool:
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
    for line in container.logs(follow=True, stream=True):
        if "action executed" in line.decode('utf-8'):
            success = True

    return success


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
    parser = FalcoParser()
    seeds = load_seeds(rule_path, seed_path, parser)
    rounds = 10

    #for i in range(rounds):
    for i, (rule_name, rule_tree) in enumerate(seeds):
        #rule_name, rule_tree = random.choice(seeds)
        print(f"Round {i+1}/{len(seeds)}: {rule_name}")

        with tempfile.NamedTemporaryFile(delete_on_close=False) as tmp:
            # Prepare rules in temp .yaml file
            print(f"\tPreparing rules at {tmp.name}")
            c = parser.to_rule(rule_tree)
            c_prime = c
            prepare_test_samples(c, c_prime, tmp.name)
            os.chmod(tmp.name, 0o777)

            # Launch Falco with the rules
            print(f"\tLaunching Falco")
            falco_process = run_falco(tmp.name)
            client = falco.Client(endpoint="unix:///run/falco/falco.sock", output_format="json")
            time.sleep(5)

            # Launch attacks
            print(f"\tLaunching attack")
            success = run_attack(rule_name)
            if success: 
                # Check alerts produced by Falco
                print(f"\tAttack success")
                time.sleep(10)

                r, r_prime = False, False
                for event in client.get():
                    print(event)
                    event: dict = json.loads(event)
                    r |= (event["rule"] == "r" and tmp.name in event["output"])
                    r_prime |= (event["rule"] == "r_prime" and tmp.name in event["desc"])

                print(f"\tChecked events: [r] \033[0;32m{r}\033[0m | [r'] \033[0;32m{r_prime}\033[0m")
            else:
                print(f"\tAttack failed")

            # Stop Falco
            print(f"\tStopping Falco")
            del client
            falco_process.terminate()
            cleanup()
            time.sleep(2)