import ast, re, sys, os

M = 0xFFFFFFFF

def s32(x):
    x &= M
    return x - 0x100000000 if x & 0x80000000 else x

class Ev(ast.NodeVisitor):
    def __init__(self, env):
        self.env = env
    def eval(self, node):
        return self.visit(node)
    def visit_Expression(self, n): return self.visit(n.body)
    def visit_Constant(self, n): return n.value
    def visit_Name(self, n):
        if n.id not in self.env:
            raise NameError(n.id)
        return self.env[n.id]
    def visit_UnaryOp(self, n):
        v = self.visit(n.operand)
        if isinstance(n.op, ast.USub): return s32(-v)
        if isinstance(n.op, ast.UAdd): return s32(v)
        if isinstance(n.op, ast.Invert): return s32(~v)
        raise Exception("unop")
    def visit_BinOp(self, n):
        a = self.visit(n.left); b = self.visit(n.right)
        op = n.op
        if isinstance(op, ast.Add): return s32(a + b)
        if isinstance(op, ast.Sub): return s32(a - b)
        if isinstance(op, ast.Mult): return s32(a * b)
        if isinstance(op, ast.BitXor): return s32(a ^ b)
        if isinstance(op, ast.BitAnd): return s32(a & b)
        if isinstance(op, ast.BitOr): return s32(a | b)
        if isinstance(op, ast.RShift):
            # logical shift on 32-bit
            return s32((a & M) >> (b & 31))
        if isinstance(op, ast.LShift): return s32(a << (b & 31))
        if isinstance(op, ast.Div):
            # java int division truncates toward zero
            q = abs(a) // abs(b)
            if (a < 0) != (b < 0): q = -q
            return s32(q)
        if isinstance(op, ast.Mod):
            r = abs(a) % abs(b)
            if a < 0: r = -r
            return s32(r)
        raise Exception("binop %r" % op)

def to_py(expr):
    expr = expr.replace(">>>", ">>")
    # remove java casts
    expr = re.sub(r'\(byte\)', '', expr)
    expr = re.sub(r'\(char\)', '', expr)
    expr = re.sub(r'\(int\)', '', expr)
    expr = re.sub(r'\(long\)', '', expr)
    expr = re.sub(r'\(short\)', '', expr)
    expr = expr.rstrip(';').strip()
    expr = expr.rstrip('L').strip()
    # replace android R refs with 0
    expr = re.sub(r'R\.id\.[A-Za-z_][A-Za-z0-9_]*', '0', expr)
    return expr

def eval_int(expr, env):
    py = to_py(expr)
    tree = ast.parse(py, mode='eval')
    v = Ev(env).eval(tree)
    return s32(v)

def parse_methods(src):
    methods = {}
    # find method signatures and brace-match bodies
    for m in re.finditer(r'private static (?:/\* synthetic \*/ )?String ([A-Za-z0-9_$]+)\(\)\s*\{', src):
        name = m.group(1)
        start = m.end() - 1
        depth = 0
        i = start
        while i < len(src):
            if src[i] == '{': depth += 1
            elif src[i] == '}':
                depth -= 1
                if depth == 0: break
            i += 1
        methods[name] = src[start+1:i]
    return methods

def deob_body(body):
    env = {}
    # split into statements simply by lines; drop if/float/double/other
    # We only care about int/long assignments and the return
    lines = body.split('\n')
    retval = None
    for line in lines:
        s = line.strip()
        if s.startswith('int '):
            mm = re.match(r'int ([A-Za-z0-9_$]+)\s*=\s*(.+);$', s)
            if mm:
                try:
                    env[mm.group(1)] = eval_int(mm.group(2), env)
                except Exception as e:
                    env[mm.group(1)] = 0
        elif s.startswith('long '):
            mm = re.match(r'long ([A-Za-z0-9_$]+)\s*=\s*(.+);$', s)
            if mm:
                env[mm.group(1)] = 0
        elif s.startswith('return '):
            retval = s
    if retval is None:
        return None
    # extract new byte[]{...}
    mb = re.search(r'new byte\s*\[\]?\s*\{(.*?)\}', retval, re.S)
    if not mb:
        return None
    elems = mb.group(1)
    ml = re.search(r'\},\s*0,\s*(\d+)\)', retval)
    length = int(ml.group(1)) if ml else None
    # split elems by top-level commas
    parts = []
    depth = 0
    cur = ''
    for ch in elems:
        if ch in '([':
            depth += 1
        elif ch in ')]':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(cur); cur = ''
        else:
            cur += ch
    if cur.strip(): parts.append(cur)
    out = bytearray()
    for p in parts:
        try:
            v = eval_int(p, env)
        except Exception as e:
            v = 0
        out.append(v & 0xFF)
    if length is not None:
        out = out[:length]
    return bytes(out)

def decode_file(path):
    src = open(path, encoding='utf-8', errors='replace').read()
    methods = parse_methods(src)
    res = {}
    for name, body in methods.items():
        try:
            b = deob_body(body)
            if b is None: continue
            res[name] = b.decode('utf-8', 'replace')
        except Exception as e:
            res[name] = '<ERR %s>' % e
    return res

if __name__ == '__main__':
    for path in sys.argv[1:]:
        print("===== %s =====" % path)
        r = decode_file(path)
        for k, v in r.items():
            print("%-12s = %r" % (k, v))
