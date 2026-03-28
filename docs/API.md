# Python API Reference

> Auto-generated. Do not edit manually — run the Documentation Agent to regenerate.

## Installation

```bash
git clone https://github.com/sunilblinkoninfra-cyber/pact-sentinel
cd pact-sentinel
# No pip install needed — zero mandatory dependencies
```

## PactSentinel

```python
from src.core.analyzer import PactSentinel
```

### Constructor

```python
PactSentinel(
    api_key: str = None,          # Single key — auto-detects OpenAI vs Anthropic
    openai_key: str = None,       # Explicit OpenAI key (or OPENAI_API_KEY env)
    anthropic_key: str = None,    # Explicit Anthropic key (or ANTHROPIC_API_KEY env)
    ai_provider: str = None,      # Force: "openai" | "anthropic"
    use_ai: bool = True,          # Set False to disable AI enrichment
    severity_filter: str = None,  # Show only: "critical" | "high" | "medium" | "low"
    skip_rules: list = None,      # e.g. ["R-003", "R-009"]
    confidence_threshold: float = 0.5,
)
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `analyze_source(source, filename)` | `AnalysisResult` | Analyze Pact source string |
| `analyze_file(path)` | `AnalysisResult` | Analyze a .pact file from disk |
| `analyze_directory(path)` | `List[AnalysisResult]` | Scan all .pact files recursively |

## AnalysisResult

| Attribute | Type | Description |
|-----------|------|-------------|
| `.findings` | `List[Finding]` | All detected findings |
| `.risk_score` | `RiskScore` | Grade, score, breakdown |
| `.summary` | `str` | One-paragraph text summary |
| `.elapsed` | `float` | Analysis time in seconds |

### Output Methods

| Method | Output |
|--------|--------|
| `.as_cli(color=True)` | ANSI terminal report |
| `.as_json(indent=2)` | Structured JSON string |
| `.as_markdown()` | GitHub-flavoured Markdown |
| `.as_sarif()` | SARIF 2.1.0 JSON for Code Scanning |

## Finding

| Field | Type | Description |
|-------|------|-------------|
| `.rule_id` | `str` | e.g. `"R-001"` |
| `.title` | `str` | Human-readable title |
| `.severity` | `Severity` | `CRITICAL / HIGH / MEDIUM / LOW` |
| `.location.module` | `str` | Module name |
| `.location.function` | `str` | Function / capability name |
| `.location.line` | `int` | Line number |
| `.issue` | `str` | What is wrong |
| `.risk` | `str` | Why it matters |
| `.recommendation` | `str` | How to fix it |
| `.fixed_code_example` | `str` | Corrected Pact code |
| `.confidence` | `float` | 0.0–1.0 detection confidence |

## Examples

```python
from src.core.analyzer import PactSentinel

# Basic — no AI
sentinel = PactSentinel(use_ai=False)
result = sentinel.analyze_file("mytoken.pact")
print(result.as_cli())

# With OpenAI
sentinel = PactSentinel(openai_key="sk-proj-...")
result = sentinel.analyze_source(pact_code)
print(f"Grade: {result.risk_score.letter_grade}")

# Filter critical only
from src.rules.rule_engine import Severity
critical = [f for f in result.findings if f.severity == Severity.CRITICAL]

# JSON for CI
import json
report = json.loads(result.as_json())
exit(1 if report["risk_score"]["security_score"] < 50 else 0)
```