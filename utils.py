import re

import yaml
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


def prepare_test_samples(c: str, c_prime: str, filename: str) -> None:
    """
    Prepare a rule r and its metamorphic transformed rule r' to be loaded into Falco.
    
    Args:
        c: original rule condition
        c_prime: transformed rule condition
    
    Returns:
        str: the filename of temporary .yaml rule file
    """
    r = {
        "rule": "r", 
        "desc": "r", 
        "condition": c, 
        "output": filename, 
        "priority": "CRITICAL"
    }
    r_prime = {
        "rule": "r_prime", 
        "desc": "r_prime", 
        "condition": c_prime, 
        "output": filename, 
        "priority": "CRITICAL"
    }

    with open(filename, 'w') as f:
        rules = yaml.dump([r, r_prime], default_flow_style=False, width=float("inf"))
        f.write(rules)