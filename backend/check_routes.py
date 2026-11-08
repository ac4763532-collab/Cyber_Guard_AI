"""
Route inventory. Proves all routers mount to the FastAPI app.
No DB connection required.
"""
from app.main import app

print(f"Total routes: {len(app.routes)}")
print()

# Group by prefix
from collections import defaultdict
by_prefix = defaultdict(list)

for route in app.routes:
    path = getattr(route, "path", "")
    methods = getattr(route, "methods", set())
    method_str = ",".join(sorted(methods)) if methods else "(mount)"
    # Extract first two path segments as the prefix
    parts = [p for p in path.split("/") if p]
    prefix = "/" + "/".join(parts[:2]) if parts else "/"
    by_prefix[prefix].append((method_str, path))

print("Routes by prefix:")
for prefix in sorted(by_prefix.keys()):
    print(f"\n  {prefix}  ({len(by_prefix[prefix])} routes)")
    for method, path in sorted(by_prefix[prefix], key=lambda x: x[1]):
        print(f"    {method:12} {path}")