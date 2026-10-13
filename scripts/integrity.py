import hashlib, struct, sys, os

# Usage: python3 integrity.py [EXTRACTION_DIR]
# Defaults to ./skyblock-extract relative to the current directory.
base = sys.argv[1] if len(sys.argv) > 1 else 'skyblock-extract'
data = open(os.path.join(base, 'y0whhmrf/t52qmy3n/jyvfg75jyq/edmst/integrity.bin'), 'rb').read()
off = 0
count = data[off] | (data[off+1] << 8); off += 2
print("entries:", count, "total bytes:", len(data))
for i in range(count):
    nl = data[off]; off += 1
    name = data[off:off+nl].decode(); off += nl
    hl = data[off]; off += 1
    h = data[off:off+hl]; off += hl
    path = os.path.join(base, name)
    status = 'MISSING'
    if os.path.exists(path):
        actual = hashlib.sha256(open(path,'rb').read()).digest()
        status = 'MATCH' if actual == h else 'MISMATCH actual=%s' % actual.hex()
    print("%-60s %s %s" % (name, h.hex(), status))
print("consumed", off, "of", len(data))
