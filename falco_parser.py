import os

from lark import Lark, Transformer, Tree, Token, v_args
from lark.reconstruct import Reconstructor
from entities import Macros, Lists


class ExpandMarcos(Transformer):
    def __init__(self, macros: Macros, parser: 'FalcoParser') -> None:
        super().__init__()
        self.macros = macros
        self.parser = parser

    @v_args(tree=True)
    def MACRO(self, name: str):
        macro = self.macros[name]
        subtree: Tree = self.parser.to_tree(macro)
        subtree = self.transform(subtree)
        assert len(subtree.children) == 1
        return subtree.children[-1]
    

class ExpandLists(Transformer):
    def __init__(self, lists: Lists) -> None:
        super().__init__()
        self.lists = lists

    def _expand_list(self, list_name: str):
        new_elements = []
        new_values: list = self.lists[list_name]
        for i, new_value in enumerate(new_values):
            if type(new_value) is int or type(new_value) is float:
                element_type = "NUMBER"
            elif type(new_value) is str and new_value.startswith("'") and new_value.endswith("'"):
                element_type = "SINGLE_QUOTED_STRING"
            elif type(new_value) is str and new_value.startswith('"') and new_value.endswith('"'):
                element_type = "DOUBLE_QUOTED_STRING"
            else:
                element_type = "UNQUOTED_STRING"

            element = Token(type=element_type, value=new_value)
            new_elements.append(element)

        return new_elements

    @v_args(tree=True)
    def set(self, tree: Tree):
        expanded = []

        for child in tree.children:
            if not (isinstance(child, Token) and child.type == "UNQUOTED_STRING"):
                expanded.append(child)
                continue

            list_name = child.value

            if list_name not in self.lists:
                expanded.append(child)
                continue

            new_elements = self._expand_list(list_name)

            if len(new_elements) > 0:
                expanded.extend(new_elements)
                continue
            
        tree.children = expanded
        return tree
    

class FalcoParser:
    def __init__(self, grammar_path: str = None):
        """
        Initializes Falco rule condition parser.
        Converts rule to syntax tree and vice versa.
        """
        if not grammar_path:
            base_path = os.path.abspath(os.path.dirname(__file__))
            grammar_path = os.path.join(base_path, "falco_grammar.txt")
        
        self.grammar = open(grammar_path).read()
        self.parser = Lark(self.grammar, start="_rule", parser='earley', lexer="dynamic", maybe_placeholders=False)
        self.reconstructor = Reconstructor(self.parser)

    def to_tree(self, rule: str) -> Tree:
        tree = self.parser.parse(rule)
        return tree

    def to_rule(self, tree: Tree) -> str:
        rule = self.reconstructor.reconstruct(tree)
        return rule