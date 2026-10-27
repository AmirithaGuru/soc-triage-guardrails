"""conftest.py — pytest session configuration.

`lambda` is a Python keyword, so `import lambda.extract` is a SyntaxError.
This file adds the lambda/ source directory to sys.path at session start so
test files can use plain module imports: `import extract`, `import prompts`, etc.
"""

import sys
from pathlib import Path

# Insert lambda/ at the front so test imports shadow nothing unexpected.
sys.path.insert(0, str(Path(__file__).parent.parent / "lambda"))
