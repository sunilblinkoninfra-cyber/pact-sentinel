# Security Rules Reference

> Auto-generated from source by the Documentation Agent.

Pact Sentinel ships **12 detection rules** covering all vulnerability categories from the problem statement.

## Quick Reference

| ID | Severity | Title | Key Tags |
|----|----------|-------|----------|
| **R-001** | 🔴 CRITICAL | State Mutation Without Capability Guard | `access-control` · `capability` · `state-mutation` |
| **R-005** | 🔴 CRITICAL | Capability Missing Authorization Enforcement | `capability` · `enforce` · `authorization` |
| **R-007** | 🔴 CRITICAL | Unguarded Administrative Function | `admin` · `access-control` · `governance` |
| **R-003** | 🟠 HIGH | Hardcoded Admin Keyset / Key Reference | `keyset` · `hardcoded` · `admin` |
| **R-004** | 🟠 HIGH | Public Function Directly Modifies Sensitive State | `access-control` · `public-function` · `sensitive-state` |
| **R-006** | 🟠 HIGH | State Change Before Authorization Check (CEI Violation) | `cei` · `reentrancy` · `ordering` |
| **R-008** | 🟠 HIGH | Unsafe Multi-Step Pact (defpact) Logic | `defpact` · `multi-step` · `rollback` |
| **R-009** | 🟠 HIGH | Weak or Bypassable Guard Construction | `guard` · `authentication` · `user-controlled` |
| **R-012** | 🟠 HIGH | Transfer Capability Missing @managed Annotation | `managed-capability` · `double-spend` · `transfer` |
| **R-002** | 🟡 MEDIUM | Overly Broad Capability Scope (with-capability Misuse) | `capability` · `scope` · `least-privilege` |
| **R-010** | 🟡 MEDIUM | Unprotected Table Initialization | `table` · `initialization` · `deployment` |
| **R-011** | 🟡 MEDIUM | Potential Capability Composition Re-entrancy | `reentrancy` · `capability` · `compose-capability` |

## Detailed Descriptions

### R-001 — State Mutation Without Capability Guard

**Severity:** 🔴 `CRITICAL`  
**Tags:** `access-control`, `capability`, `state-mutation`

**What it detects:**
See source code for details.

**How to remediate:** Add appropriate capability guards, enforce checks, or `@managed` annotations as described in the finding output.

---

### R-002 — Overly Broad Capability Scope (with-capability Misuse)

**Severity:** 🟡 `MEDIUM`  
**Tags:** `capability`, `scope`, `least-privilege`

**What it detects:**
See source code for details.

**How to remediate:** Add appropriate capability guards, enforce checks, or `@managed` annotations as described in the finding output.

---

### R-003 — Hardcoded Admin Keyset / Key Reference

**Severity:** 🟠 `HIGH`  
**Tags:** `keyset`, `hardcoded`, `admin`, `decentralization`

**What it detects:**
See source code for details.

**How to remediate:** Add appropriate capability guards, enforce checks, or `@managed` annotations as described in the finding output.

---

### R-004 — Public Function Directly Modifies Sensitive State

**Severity:** 🟠 `HIGH`  
**Tags:** `access-control`, `public-function`, `sensitive-state`

**What it detects:**
See source code for details.

**How to remediate:** Add appropriate capability guards, enforce checks, or `@managed` annotations as described in the finding output.

---

### R-005 — Capability Missing Authorization Enforcement

**Severity:** 🔴 `CRITICAL`  
**Tags:** `capability`, `enforce`, `authorization`

**What it detects:**
See source code for details.

**How to remediate:** Add appropriate capability guards, enforce checks, or `@managed` annotations as described in the finding output.

---

### R-006 — State Change Before Authorization Check (CEI Violation)

**Severity:** 🟠 `HIGH`  
**Tags:** `cei`, `reentrancy`, `ordering`, `toctou`

**What it detects:**
See source code for details.

**How to remediate:** Add appropriate capability guards, enforce checks, or `@managed` annotations as described in the finding output.

---

### R-007 — Unguarded Administrative Function

**Severity:** 🔴 `CRITICAL`  
**Tags:** `admin`, `access-control`, `governance`

**What it detects:**
See source code for details.

**How to remediate:** Add appropriate capability guards, enforce checks, or `@managed` annotations as described in the finding output.

---

### R-008 — Unsafe Multi-Step Pact (defpact) Logic

**Severity:** 🟠 `HIGH`  
**Tags:** `defpact`, `multi-step`, `rollback`, `cross-chain`

**What it detects:**
See source code for details.

**How to remediate:** Add appropriate capability guards, enforce checks, or `@managed` annotations as described in the finding output.

---

### R-009 — Weak or Bypassable Guard Construction

**Severity:** 🟠 `HIGH`  
**Tags:** `guard`, `authentication`, `user-controlled`

**What it detects:**
See source code for details.

**How to remediate:** Add appropriate capability guards, enforce checks, or `@managed` annotations as described in the finding output.

---

### R-010 — Unprotected Table Initialization

**Severity:** 🟡 `MEDIUM`  
**Tags:** `table`, `initialization`, `deployment`

**What it detects:**
See source code for details.

**How to remediate:** Add appropriate capability guards, enforce checks, or `@managed` annotations as described in the finding output.

---

### R-011 — Potential Capability Composition Re-entrancy

**Severity:** 🟡 `MEDIUM`  
**Tags:** `reentrancy`, `capability`, `compose-capability`

**What it detects:**
See source code for details.

**How to remediate:** Add appropriate capability guards, enforce checks, or `@managed` annotations as described in the finding output.

---

### R-012 — Transfer Capability Missing @managed Annotation

**Severity:** 🟠 `HIGH`  
**Tags:** `managed-capability`, `double-spend`, `transfer`

**What it detects:**
See source code for details.

**How to remediate:** Add appropriate capability guards, enforce checks, or `@managed` annotations as described in the finding output.

---

## Adding a Custom Rule

```python
from src.rules.rule_engine import BaseRule, Finding, Severity

class R013_MyCheck(BaseRule):
    rule_id  = "R-013"
    title    = "My Custom Check"
    severity = Severity.HIGH
    tags     = ["custom"]

    def analyze(self, contract) -> list:
        findings = []
        # your detection logic here
        return findings

ALL_RULES.append(R013_MyCheck())
```