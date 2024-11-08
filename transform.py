import random

from lark import Tree, Token, Visitor, Transformer, v_args


class ExtractSyscalls(Visitor):
    def __init__(self) -> None:
        """
        Extract all syscalls present in the rule.
        We approach conservatively by assuming every syscall present is used.
        """
        super().__init__()
        self.syscalls = set()

    def visit(self, tree: Tree) -> set[str]:
        super().visit(tree)
        return self.syscalls
        
    def pred(self, tree: Tree) -> Tree:
        """Check predicate nodes
        """
        field = tree.children[0]
        value = tree.children[-1]

        # An event type (syscall) field must be evt.type
        if (
            len(field.children) == 2
            and isinstance(field.children[0], Token)
            and isinstance(field.children[1], Token)
            and field.children[0].value == "evt"
            and field.children[1].value == "type"
        ):
            self._extract_syscalls(value)

    def _extract_syscalls(self, item) -> None:
        """
        Recursively get all syscalls from tokens in the right operand.
        All unquoted strings are potential syscalls.
        """
        if isinstance(item, Token):
            if item.type == "UNQUOTED_STRING": 
                self.syscalls.add(item.value)
            return

        if isinstance(item, Tree):
            for child in item.children:
                self._extract_syscalls(child)


class InsertDeadSubtrees(Transformer):
    def __init__(self, syscalls: set[str], iterations: tuple[int, int], p: float, seed: int) -> None:
        """Tranform a rule tree by randomly adding dead subtrees.

        Args:
            syscalls: vocabulary of all syscalls
            iterations: number of transformations in [min, max] range
            p: probability of adding subtree at each node
            seed: for random number generator
        """
        super().__init__()
        self.rng = random.Random(seed)
        self.whitelist_syscalls = None
        self.syscalls = syscalls
        self.min_iter, self.max_iter = iterations
        self.p = p

    def transform(self, tree: Tree, blacklist_syscalls: set[str]) -> Tree:
        """
        Args:
            tree: the tree to transform
            blacklist_syscalls: syscalls that should not be used in dead subtrees

        Returns:
            Tree: transformed tree
        """
        self.whitelist_syscalls = list(self.syscalls.difference(blacklist_syscalls))
        iterations = random.randint(self.min_iter, self.max_iter)

        for _ in range(iterations):
            tree = super().transform(tree)

        return tree

    @v_args(tree=True)
    def pred(self, tree: Tree) -> Tree:
        return self._add_subtree(tree)

    @v_args(tree=True)
    def and_op(self, tree: Tree) -> Tree:
        return self._add_subtree(tree)

    @v_args(tree=True)
    def or_op(self, tree: Tree) -> Tree:
        return self._add_subtree(tree)
    
    def _add_subtree(self, x: Tree) -> Tree:
        """
        0.5 * p% chance of inserting dead OR subtree
        0.5 * p% chance of inserting dead AND subtree
        """
        if self.rng.random() > self.p: return x
        op = "or_op" if self.rng.random() > 0.5 else "and_op"
        add_pred = self.rng.choice([
            self._add_eq_pred,
            self._add_set_pred
        ])
        children = [add_pred(op == "or_op"), x]
        self.rng.shuffle(children)
        return Tree(op, children)
    
    def _add_eq_pred(self, or_op: bool) -> Tree:
        ops = Token("EQ", "=") if or_op else Token("NEQ", "!=") 
        syscall = self.rng.choice(self.whitelist_syscalls)
        return Tree("pred", [
            Tree("field", [
                Token("CLASS", "evt"),
                Token("SUBCLASS", "type")
            ]),
            ops,
            Token('UNQUOTED_STRING', syscall)
        ])

    def _add_is_pred(self, or_op: bool) -> Tree:
        syscall = self.rng.choice(self.whitelist_syscalls)
        return Tree("pred", [
            Tree("field", [
                Token("CLASS", "evt"),
                Token("SUBCLASS", "type"),
                Token("SUBCLASS", "is"),
                Token("SUBCLASS", syscall)
            ]),
            Token("EQ", "="),
            Token('NUMBER', 1 if or_op else 0)
        ])

    def _add_set_pred(self, or_op: bool) -> Tree:
        k = self.rng.randint(1, len(self.whitelist_syscalls))
        syscalls = self.rng.sample(self.whitelist_syscalls, k)
        pred = Tree("pred", [
            Tree("field", [
                Token("CLASS", "evt"),
                Token("SUBCLASS", "type")
            ]),
            Token("IN", "in"),
            Tree("set", [
                Token('UNQUOTED_STRING', syscall)
                for syscall in syscalls
            ])
        ])
        return pred if or_op else Tree("not_op", [pred])