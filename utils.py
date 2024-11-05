import re

import yaml

from entities import FalcoRule, Rules, Macros, Lists


def import_rules(rule_path: str) -> tuple[Rules, Macros, Lists]:
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


def export_rules(c: str, c_prime: str) -> str:
    """
    Export the original rule condition c and its transformed version c' 
    after applying metamorphic relations.

    Args:
        x: original rule condition
        x_prime: transformed rule condition

    Returns:
        str: both rules represented in yaml format
    """
    c = ''.join(c.splitlines())
    c_prime = ''.join(c_prime.splitlines())
    x = {"rule": "x", "desc": "x", "condition": c, "output": "x", "priority": "CRITICAL"}
    x_prime = {"rule": "x_prime", "desc": "x_prime", "condition": c_prime, "output": "x_prime", "priority": "CRITICAL"}
    rules = yaml.dump([x, x_prime], default_flow_style=False, width=float("inf"))
    return rules