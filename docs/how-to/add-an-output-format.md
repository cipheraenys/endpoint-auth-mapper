# Add an output format

Add a new report format (e.g., CSV, XML) via a reporter function.
Reporters are pure functions taking a `ScanResult` object and returning a rendered string.

## 1. Create reporter

Create `src/authmapper/reporters/<format>_reporter.py`.
Implement formatter function:

```python
from authmapper.core.model import ScanResult

def render_myformat(result: ScanResult) -> str:
    """Render the scan result to MyFormat."""
    output = []
    # Format the result.findings ...
    return "\n".join(output)
```

## 2. Register reporter

Edit `src/authmapper/reporters/__init__.py`.
Import function and add to `REPORTERS` map:

```python
from .myformat_reporter import render_myformat

REPORTERS = {
    # ... existing ...
    "myformat": render_myformat,
}
```

## 3. Update CLI options

1. Edit `src/authmapper/cli.py`. Add format to `--format` argument `choices` list.
2. Edit `src/authmapper/app/runner.py`. Add file extension to extension mapping dictionary (e.g., `"myformat": "ext"`).

## 4. Add tests

Create `tests/test_reporters_myformat.py`.
Assert reporter produces well-formed output for a mock `ScanResult`.
