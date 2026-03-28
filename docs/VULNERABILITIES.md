# Vulnerability Catalog

> Demonstrates what Pact Sentinel detects. Auto-generated from `tests/contracts/vulnerable-defi.pact`.

**Module:** `vulnerable-defi-token`  
**Grade:** F-  
**Score:** 0.0/100  
**Total findings:** 23 (12 critical · 9 high · 2 medium)

---

## R-005 — Capability Missing Authorization Enforcement

**Severity:** 🔴 `CRITICAL`  
**Location:** `vulnerable-defi-token` → `TRANSFER` (line 25)

**Issue:** Capability `TRANSFER` has an empty body — it grants permission to anyone unconditionally.

**Risk:** `TRANSFER` appears to be a token transfer capability. Empty capabilities are equivalent to no access control — any transaction can acquire this capability for free, bypassing all security.

**Fix:** Add `enforce-guard` or `enforce` in `TRANSFER` to verify the caller. For account-based capabilities: `(enforce-guard (at 'guard (read table account)))`. For admin capabilities: `(enforce-guard (keyset-ref-guard 'ns.admin-ks))`.

**Corrected code:**
```pact
(defcap TRANSFER (account:string)
  @doc "Enforces account ownership"
  (enforce-guard (at 'guard (read accounts account))))
```

---

## R-005 — Capability Missing Authorization Enforcement

**Severity:** 🔴 `CRITICAL`  
**Location:** `vulnerable-defi-token` → `CREDIT` (line 37)

**Issue:** Capability `CREDIT` has an empty body — it grants permission to anyone unconditionally.

**Risk:** `CREDIT` appears to be a balance credit capability. Empty capabilities are equivalent to no access control — any transaction can acquire this capability for free, bypassing all security.

**Fix:** Add `enforce-guard` or `enforce` in `CREDIT` to verify the caller. For account-based capabilities: `(enforce-guard (at 'guard (read table account)))`. For admin capabilities: `(enforce-guard (keyset-ref-guard 'ns.admin-ks))`.

**Corrected code:**
```pact
(defcap CREDIT (account:string)
  @doc "Enforces account ownership"
  (enforce-guard (at 'guard (read accounts account))))
```

---

## R-007 — Unguarded Administrative Function

**Severity:** 🔴 `CRITICAL`  
**Location:** `vulnerable-defi-token` → `init` (line 42)

**Issue:** Administrative function `init` (a contract initialization) has no capability guard, enforce check, or require-capability.

**Risk:** `init` is a contract initialization function callable by any account. An attacker monitoring the mempool can front-run deployment, seize governance, drain funds, or permanently disable the contract.

**Fix:** `init` is a contract initialization and must be gated by the module's GOVERNANCE capability. This enforces the governing keyset and prevents unauthorized access at the transaction level.

**Corrected code:**
```pact
(defcap GOVERNANCE ()
  @doc "Module governance — requires admin keyset"
  (enforce-guard (keyset-ref-guard 'ns.admin-ks)))

(defun init (...)
  (with-capability (GOVERNANCE)
    ;; contract initialization logic here
  ))
```

---

## R-001 — State Mutation Without Capability Guard

**Severity:** 🔴 `CRITICAL`  
**Location:** `vulnerable-defi-token` → `init` (line 44)

**Issue:** `init` performs `insert` on table `config` with no capability guard or enforce check.

**Risk:** Any account can call `init` and modify `config` without authorization. For a contract initialization function this enables direct exploitation — unauthorized state changes, fund theft, or contract takeover.

**Fix:** `init` is a contract initialization function. Define a `INIT_AUTH` capability that enforces the caller's identity (via `enforce-guard`) and wrap the `insert` call inside `(with-capability (INIT_AUTH ...))`.

**Corrected code:**
```pact
(defcap INIT_AUTH (account:string)
  @doc "Guard for init"
  (enforce-guard (at 'guard (read config account))))

(defun init (...)
  (with-capability (INIT_AUTH account)
    (insert config account {...})))
```

---

## R-007 — Unguarded Administrative Function

**Severity:** 🔴 `CRITICAL`  
**Location:** `vulnerable-defi-token` → `mint` (line 68)

**Issue:** Administrative function `mint` (a token minting) has no capability guard, enforce check, or require-capability.

**Risk:** `mint` is a token minting function callable by any account. An attacker monitoring the mempool can front-run deployment, seize governance, drain funds, or permanently disable the contract.

**Fix:** `mint` is a token minting and must be gated by the module's GOVERNANCE capability. This enforces the governing keyset and prevents unauthorized access at the transaction level.

**Corrected code:**
```pact
(defcap GOVERNANCE ()
  @doc "Module governance — requires admin keyset"
  (enforce-guard (keyset-ref-guard 'ns.admin-ks)))

(defun mint (...)
  (with-capability (GOVERNANCE)
    ;; token minting logic here
  ))
```

---

## R-001 — State Mutation Without Capability Guard

**Severity:** 🔴 `CRITICAL`  
**Location:** `vulnerable-defi-token` → `mint` (line 71)

**Issue:** `mint` performs `update` on table `accounts` with no capability guard or enforce check.

**Risk:** Any account can call `mint` and modify `accounts` without authorization. For a token minting function this enables direct exploitation — unauthorized state changes, fund theft, or contract takeover.

**Fix:** `mint` is a token minting function. Define a `MINT_AUTH` capability that enforces the caller's identity (via `enforce-guard`) and wrap the `update` call inside `(with-capability (MINT_AUTH ...))`.

**Corrected code:**
```pact
(defcap MINT_AUTH (account:string)
  @doc "Guard for mint"
  (enforce-guard (at 'guard (read accounts account))))

(defun mint (...)
  (with-capability (MINT_AUTH account)
    (update accounts account {...})))
```

---

## R-007 — Unguarded Administrative Function

**Severity:** 🔴 `CRITICAL`  
**Location:** `vulnerable-defi-token` → `pause` (line 77)

**Issue:** Administrative function `pause` (a emergency circuit-breaker) has no capability guard, enforce check, or require-capability.

**Risk:** `pause` is a emergency circuit-breaker function callable by any account. An attacker monitoring the mempool can front-run deployment, seize governance, drain funds, or permanently disable the contract.

**Fix:** `pause` is a emergency circuit-breaker and must be gated by the module's GOVERNANCE capability. This enforces the governing keyset and prevents unauthorized access at the transaction level.

**Corrected code:**
```pact
(defcap GOVERNANCE ()
  @doc "Module governance — requires admin keyset"
  (enforce-guard (keyset-ref-guard 'ns.admin-ks)))

(defun pause (...)
  (with-capability (GOVERNANCE)
    ;; emergency circuit-breaker logic here
  ))
```

---

## R-001 — State Mutation Without Capability Guard

**Severity:** 🔴 `CRITICAL`  
**Location:** `vulnerable-defi-token` → `pause` (line 79)

**Issue:** `pause` performs `update` on table `config` with no capability guard or enforce check.

**Risk:** Any account can call `pause` and modify `config` without authorization. For a emergency circuit-breaker function this enables direct exploitation — unauthorized state changes, fund theft, or contract takeover.

**Fix:** `pause` is a emergency circuit-breaker function. Define a `PAUSE_AUTH` capability that enforces the caller's identity (via `enforce-guard`) and wrap the `update` call inside `(with-capability (PAUSE_AUTH ...))`.

**Corrected code:**
```pact
(defcap PAUSE_AUTH (account:string)
  @doc "Guard for pause"
  (enforce-guard (at 'guard (read config account))))

(defun pause (...)
  (with-capability (PAUSE_AUTH account)
    (update config account {...})))
```

---

## R-007 — Unguarded Administrative Function

**Severity:** 🔴 `CRITICAL`  
**Location:** `vulnerable-defi-token` → `unpause` (line 82)

**Issue:** Administrative function `unpause` (a emergency circuit-breaker) has no capability guard, enforce check, or require-capability.

**Risk:** `unpause` is a emergency circuit-breaker function callable by any account. An attacker monitoring the mempool can front-run deployment, seize governance, drain funds, or permanently disable the contract.

**Fix:** `unpause` is a emergency circuit-breaker and must be gated by the module's GOVERNANCE capability. This enforces the governing keyset and prevents unauthorized access at the transaction level.

**Corrected code:**
```pact
(defcap GOVERNANCE ()
  @doc "Module governance — requires admin keyset"
  (enforce-guard (keyset-ref-guard 'ns.admin-ks)))

(defun unpause (...)
  (with-capability (GOVERNANCE)
    ;; emergency circuit-breaker logic here
  ))
```

---

## R-001 — State Mutation Without Capability Guard

**Severity:** 🔴 `CRITICAL`  
**Location:** `vulnerable-defi-token` → `unpause` (line 84)

**Issue:** `unpause` performs `update` on table `config` with no capability guard or enforce check.

**Risk:** Any account can call `unpause` and modify `config` without authorization. For a emergency circuit-breaker function this enables direct exploitation — unauthorized state changes, fund theft, or contract takeover.

**Fix:** `unpause` is a emergency circuit-breaker function. Define a `UNPAUSE_AUTH` capability that enforces the caller's identity (via `enforce-guard`) and wrap the `update` call inside `(with-capability (UNPAUSE_AUTH ...))`.

**Corrected code:**
```pact
(defcap UNPAUSE_AUTH (account:string)
  @doc "Guard for unpause"
  (enforce-guard (at 'guard (read config account))))

(defun unpause (...)
  (with-capability (UNPAUSE_AUTH account)
    (update config account {...})))
```

---

## R-001 — State Mutation Without Capability Guard

**Severity:** 🔴 `CRITICAL`  
**Location:** `vulnerable-defi-token` → `create-account` (line 90)

**Issue:** `create-account` performs `insert` on table `accounts` with no capability guard or enforce check.

**Risk:** Any account can call `create-account` and modify `accounts` without authorization. For a account or resource creation function this enables direct exploitation — unauthorized state changes, fund theft, or contract takeover.

**Fix:** `create-account` is a account or resource creation function. Define a `CREATE_ACCOUNT_AUTH` capability that enforces the caller's identity (via `enforce-guard`) and wrap the `insert` call inside `(with-capability (CREATE_ACCOUNT_AUTH ...))`.

**Corrected code:**
```pact
(defcap CREATE_ACCOUNT_AUTH (account:string)
  @doc "Guard for create-account"
  (enforce-guard (at 'guard (read accounts account))))

(defun create-account (...)
  (with-capability (CREATE_ACCOUNT_AUTH account)
    (insert accounts account {...})))
```

---

## R-001 — State Mutation Without Capability Guard

**Severity:** 🔴 `CRITICAL`  
**Location:** `vulnerable-defi-token` → `update-guard` (line 99)

**Issue:** `update-guard` performs `update` on table `accounts` with no capability guard or enforce check.

**Risk:** Any account can call `update-guard` and modify `accounts` without authorization. For a state update function this enables direct exploitation — unauthorized state changes, fund theft, or contract takeover.

**Fix:** `update-guard` is a state update function. Define a `UPDATE_GUARD_AUTH` capability that enforces the caller's identity (via `enforce-guard`) and wrap the `update` call inside `(with-capability (UPDATE_GUARD_AUTH ...))`.

**Corrected code:**
```pact
(defcap UPDATE_GUARD_AUTH (account:string)
  @doc "Guard for update-guard"
  (enforce-guard (at 'guard (read accounts account))))

(defun update-guard (...)
  (with-capability (UPDATE_GUARD_AUTH account)
    (update accounts account {...})))
```

---

## R-003 — Hardcoded Admin Keyset / Key Reference

**Severity:** 🟠 `HIGH`  
**Location:** `<top-level>` → `define-keyset` (line 8)

**Issue:** Top-level `(define-keyset 'admin ...)` uses a generic admin name. This creates a well-known privileged keyset name attackers can target.

**Risk:** Generic keyset names like 'admin' or 'operator' are frequently targeted in deployment attacks. If the keyset is not rotated or is misconfigured, any account can claim ownership.

**Fix:** Use a namespaced keyset: `(define-keyset 'your-project.admin-ks ...)`. Always read the keyset from transaction data: `(define-keyset 'project.admin (read-keyset "admin"))` and confirm via `(enforce-guard (keyset-ref-guard 'project.admin))`.

**Corrected code:**
```pact
(namespace 'your-project)
(define-keyset 'your-project.admin-ks (read-keyset "admin"))

(defcap GOVERNANCE ()
  (enforce-guard (keyset-ref-guard 'your-project.admin-ks)))
```

---

## R-003 — Hardcoded Admin Keyset / Key Reference

**Severity:** 🟠 `HIGH`  
**Location:** `vulnerable-defi-token` → `<module-governance>` (line 10)

**Issue:** Module `vulnerable-defi-token` is governed by hardcoded keyset `'admin`. Using a string literal as module governance is a security anti-pattern.

**Risk:** A module governed by a bare string keyset (not a capability) cannot enforce upgrade authorization at runtime. Any account holding that keyset can upgrade the module without time-locks or multi-sig.

**Fix:** Replace `(module vulnerable-defi-token ''admin ...)` with a GOVERNANCE capability: `(module vulnerable-defi-token GOVERNANCE ...)` and define `(defcap GOVERNANCE () (enforce-guard (keyset-ref-guard 'ns.admin-ks)))`.

**Corrected code:**
```pact
(module vulnerable-defi-token GOVERNANCE
  (defcap GOVERNANCE ()
    (enforce-guard (keyset-ref-guard 'ns.admin-ks)))
  ...)
```

---

## R-012 — Transfer Capability Missing @managed Annotation

**Severity:** 🟠 `HIGH`  
**Location:** `vulnerable-defi-token` → `TRANSFER` (line 25)

**Issue:** Capability `TRANSFER` is a transfer/payment capability without `@managed`. The same grant can be used multiple times in one tx.

**Risk:** `TRANSFER` without `@managed` allows double-spend: a single authorization for N tokens can be consumed multiple times in nested calls within a single transaction, draining more than authorized.

**Fix:** Add `@managed amount TRANSFER-mgr` and implement a manager function that tracks consumed amount. Follow the Kadena coin contract pattern exactly.

**Corrected code:**
```pact
(defcap TRANSFER (sender:string receiver:string amount:decimal)
  @managed amount TRANSFER-mgr
  (enforce-guard (at 'guard (read accounts sender)))
  (enforce (> amount 0.0) "Positive non-zero amount")
  (enforce (!= sender receiver) "Same-account restriction"))

(defun TRANSFER-mgr:decimal (managed:decimal requested:decimal)
  (enforce (>= managed requested) "TRANSFER limit exceeded")
  (- managed requested))
```

---

## R-012 — Transfer Capability Missing @managed Annotation

**Severity:** 🟠 `HIGH`  
**Location:** `vulnerable-defi-token` → `DEBIT` (line 31)

**Issue:** Capability `DEBIT` is a transfer/payment capability without `@managed`. The same grant can be used multiple times in one tx.

**Risk:** `DEBIT` without `@managed` allows double-spend: a single authorization for N tokens can be consumed multiple times in nested calls within a single transaction, draining more than authorized.

**Fix:** Add `@managed amount DEBIT-mgr` and implement a manager function that tracks consumed amount. Follow the Kadena coin contract pattern exactly.

**Corrected code:**
```pact
(defcap DEBIT (sender:string receiver:string amount:decimal)
  @managed amount DEBIT-mgr
  (enforce-guard (at 'guard (read accounts sender)))
  (enforce (> amount 0.0) "Positive non-zero amount")
  (enforce (!= sender receiver) "Same-account restriction"))

(defun DEBIT-mgr:decimal (managed:decimal requested:decimal)
  (enforce (>= managed requested) "DEBIT limit exceeded")
  (- managed requested))
```

---

## R-004 — Public Function Directly Modifies Sensitive State

**Severity:** 🟠 `HIGH`  
**Location:** `vulnerable-defi-token` → `transfer` (line 58)

**Issue:** Public `transfer` directly mutates sensitive table `accounts` without any capability protection.

**Risk:** `transfer` appears to be a token transfer function. Direct unguarded access to `accounts` allows any caller to manipulate balances or ownership records — enabling token inflation, theft, or account takeover.

**Fix:** Wrap the `accounts` mutation inside a dedicated capability (e.g., `TRANSFER`, `DEBIT`, or `CREDIT` following the Kadena coin contract pattern). Use `@managed` on transfer capabilities to prevent double-spend.

**Corrected code:**
```pact
(defcap DEBIT (sender:string amount:decimal)
  @managed amount DEBIT-mgr
  (enforce-guard (at 'guard (read accounts sender))))

(defun DEBIT-mgr:decimal (managed:decimal requested:decimal)
  (enforce (>= managed requested) "Exceeds authorized amount")
  (- managed requested))

(defun transfer (sender:string receiver:string amount:decimal)
  (with-capability (DEBIT sender amount)
    (update accounts sender {'balance: (- old-bal amount)}))
```

---

## R-006 — State Change Before Authorization Check (CEI Violation)

**Severity:** 🟠 `HIGH`  
**Location:** `vulnerable-defi-token` → `transfer` (line 58)

**Issue:** `transfer`: `update` on `accounts` (line 58) occurs BEFORE `enforce` (line 61).

**Risk:** `transfer` is a token transfer function. State committed before validation cannot be rolled back if the check fails. In cross-module calls this creates a classic read-modify-write reentrancy window.

**Fix:** Restructure `transfer` to follow Checks-Effects-Interactions:
  1. ALL `enforce`/`enforce-guard` checks first
  2. State reads (`with-read`, `select`)
  3. State writes (`update`, `insert`) last
Never write to `accounts` before all authorization is confirmed.

**Corrected code:**
```pact
(defun transfer (...)
  ;; ── 1. CHECKS (all validation first) ──
  (enforce (> amount 0.0) "Amount must be positive")
  (enforce-guard (at 'guard (read accounts sender)))
  ;; ── 2. READS ──
  (with-read accounts sender {'balance := bal}
    (enforce (>= bal amount) "Insufficient balance")
    ;; ── 3. EFFECTS (writes last) ──
    (update accounts sender {'balance: (- bal amount)})))
```

---

## R-004 — Public Function Directly Modifies Sensitive State

**Severity:** 🟠 `HIGH`  
**Location:** `vulnerable-defi-token` → `mint` (line 71)

**Issue:** Public `mint` directly mutates sensitive table `accounts` without any capability protection.

**Risk:** `mint` appears to be a token minting function. Direct unguarded access to `accounts` allows any caller to manipulate balances or ownership records — enabling token inflation, theft, or account takeover.

**Fix:** Wrap the `accounts` mutation inside a dedicated capability (e.g., `TRANSFER`, `DEBIT`, or `CREDIT` following the Kadena coin contract pattern). Use `@managed` on transfer capabilities to prevent double-spend.

**Corrected code:**
```pact
(defcap DEBIT (sender:string amount:decimal)
  @managed amount DEBIT-mgr
  (enforce-guard (at 'guard (read accounts sender))))

(defun DEBIT-mgr:decimal (managed:decimal requested:decimal)
  (enforce (>= managed requested) "Exceeds authorized amount")
  (- managed requested))

(defun mint (sender:string receiver:string amount:decimal)
  (with-capability (DEBIT sender amount)
    (update accounts sender {'balance: (- old-bal amount)}))
```

---

## R-004 — Public Function Directly Modifies Sensitive State

**Severity:** 🟠 `HIGH`  
**Location:** `vulnerable-defi-token` → `create-account` (line 90)

**Issue:** Public `create-account` directly mutates sensitive table `accounts` without any capability protection.

**Risk:** `create-account` appears to be a account or resource creation function. Direct unguarded access to `accounts` allows any caller to manipulate balances or ownership records — enabling token inflation, theft, or account takeover.

**Fix:** Wrap the `accounts` mutation inside a dedicated capability (e.g., `TRANSFER`, `DEBIT`, or `CREDIT` following the Kadena coin contract pattern). Use `@managed` on transfer capabilities to prevent double-spend.

**Corrected code:**
```pact
(defcap DEBIT (sender:string amount:decimal)
  @managed amount DEBIT-mgr
  (enforce-guard (at 'guard (read accounts sender))))

(defun DEBIT-mgr:decimal (managed:decimal requested:decimal)
  (enforce (>= managed requested) "Exceeds authorized amount")
  (- managed requested))

(defun create-account (sender:string receiver:string amount:decimal)
  (with-capability (DEBIT sender amount)
    (update accounts sender {'balance: (- old-bal amount)}))
```

---

## R-004 — Public Function Directly Modifies Sensitive State

**Severity:** 🟠 `HIGH`  
**Location:** `vulnerable-defi-token` → `update-guard` (line 99)

**Issue:** Public `update-guard` directly mutates sensitive table `accounts` without any capability protection.

**Risk:** `update-guard` appears to be a state update function. Direct unguarded access to `accounts` allows any caller to manipulate balances or ownership records — enabling token inflation, theft, or account takeover.

**Fix:** Wrap the `accounts` mutation inside a dedicated capability (e.g., `TRANSFER`, `DEBIT`, or `CREDIT` following the Kadena coin contract pattern). Use `@managed` on transfer capabilities to prevent double-spend.

**Corrected code:**
```pact
(defcap DEBIT (sender:string amount:decimal)
  @managed amount DEBIT-mgr
  (enforce-guard (at 'guard (read accounts sender))))

(defun DEBIT-mgr:decimal (managed:decimal requested:decimal)
  (enforce (>= managed requested) "Exceeds authorized amount")
  (- managed requested))

(defun update-guard (sender:string receiver:string amount:decimal)
  (with-capability (DEBIT sender amount)
    (update accounts sender {'balance: (- old-bal amount)}))
```

---

## R-010 — Unprotected Table Initialization

**Severity:** 🟡 `MEDIUM`  
**Location:** `vulnerable-defi-token` → `init` (line 42)

**Issue:** `init` (contract initialization) inserts/writes to tables without governance protection.

**Risk:** Mempool front-running attack: an attacker monitoring the deployment transaction can call this function before the legitimate operator, seeding tables with malicious initial state (e.g., attacker-owned admin accounts).

**Fix:** Protect `init` with the module's GOVERNANCE capability. For truly one-time initialization, also add a guard that fails if initialization has already occurred (read-with-default pattern).

**Corrected code:**
```pact
(defun init ()
  (with-capability (GOVERNANCE)
    ;; Guard against re-initialization
    (with-default-read config-table 'initialized
      {'initialized: false}
      {'initialized := already-init}
      (enforce (not already-init) "Already initialized")
      (insert config-table 'initialized {'initialized: true}))))
```

---

## R-010 — Unprotected Table Initialization

**Severity:** 🟡 `MEDIUM`  
**Location:** `vulnerable-defi-token` → `create-account` (line 88)

**Issue:** `create-account` (account or resource creation) inserts/writes to tables without governance protection.

**Risk:** Mempool front-running attack: an attacker monitoring the deployment transaction can call this function before the legitimate operator, seeding tables with malicious initial state (e.g., attacker-owned admin accounts).

**Fix:** Protect `create-account` with the module's GOVERNANCE capability. For truly one-time initialization, also add a guard that fails if initialization has already occurred (read-with-default pattern).

**Corrected code:**
```pact
(defun create-account ()
  (with-capability (GOVERNANCE)
    ;; Guard against re-initialization
    (with-default-read config-table 'initialized
      {'initialized: false}
      {'initialized := already-init}
      (enforce (not already-init) "Already initialized")
      (insert config-table 'initialized {'initialized: true}))))
```

---
