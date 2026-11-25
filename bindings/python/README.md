# devtape-dtp

Python 3.9+ bindings for decoding DTP v0.1 tapes and sanitizing ANSI replay text.

```python
import json
from pathlib import Path
from devtape_dtp import decode_tape_json, sanitize_ansi
archive = json.loads(decode_tape_json(Path("session.tape").read_bytes()))
safe_text = sanitize_ansi("hello\x1b]52;c;secret\x07world")
```

Invalid tapes raise `ValueError`. To build locally, create a virtual environment and run `maturin develop` in this directory.
