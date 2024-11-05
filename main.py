import os
from lark import Tree

from falco_parser import FalcoParser
from utils import import_rules, export_rules


base_path = os.path.abspath(os.path.dirname(__file__))
rule_path = os.path.join(base_path, "falco_rules.yaml")
rules, macros, lists = import_rules(rule_path)
parser = FalcoParser(macros, lists)

seeds = open("./falco_seed.txt").read().splitlines()
for seed in seeds:
    name = seed.split(".")[-1]
    rule = rules[name.lower()]

    tree: Tree = parser.to_tree(rule.condition)


    #print(tree.pretty())
    c = parser.to_rule(tree)
    c_prime = c
    a = export_rules(c, c_prime)
    with open(f"./{name}.yaml", "w") as f: f.write(a)