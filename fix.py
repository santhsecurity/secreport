import os
import shutil

src_dir = "src"

def write_file(path, content):
    with open(os.path.join(src_dir, path), "w") as f:
        f.write(content)

# We will generate the following files:
# src/lib.rs
# src/format.rs
# src/models.rs
# src/render.rs
# src/render/json.rs
# src/render/markdown.rs
# src/render/summary.rs
# src/tests.rs
# src/adversarial_tests.rs

# Let's read existing tests to preserve them
tests_rs = ""
try:
    with open(os.path.join(src_dir, "tests.rs")) as f:
        tests_rs = f.read()
except:
    pass

adv_tests_rs = ""
try:
    with open(os.path.join(src_dir, "adversarial_tests.rs")) as f:
        adv_tests_rs = f.read()
except:
    pass

# We will rewrite adversarial_tests.rs to fix the tests later.

