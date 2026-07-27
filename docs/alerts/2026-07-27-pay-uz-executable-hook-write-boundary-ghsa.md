---
title: pay-uz unauthenticated executable-hook write boundary
---

# pay-uz unauthenticated executable-hook write boundary

GHSA-m5wg-cjgh-223j turns a package-specific issue into a reusable Laravel assessment workflow: map package-owned control-panel routes, verify the middleware actually applied at runtime, trace user-controlled editor content into executable hook files, and prove the later load edge without a shell payload. In `goodoneuz/pay-uz` through 2.2.24, the default control-panel group used only Laravel's `web` middleware, `Route::any()` exposed the editor update action, and `file_put_contents()` replaced an existing `.php` hook selected by request data. Normal payment-service paths later loaded those hooks with `require`.

Sources:

- [GHSA-m5wg-cjgh-223j / CVE-2026-31843](https://github.com/advisories/GHSA-m5wg-cjgh-223j)
- [pay-uz 2.2.24 route definitions](https://github.com/goodoneuz/pay-uz/blob/2.2.24/src/routes/web.php)
- [pay-uz 2.2.24 `ApiController::file_put`](https://github.com/goodoneuz/pay-uz/blob/2.2.24/src/Http/Controllers/ApiController.php)
- [pay-uz 2.2.24 payment-service hook loads](https://github.com/goodoneuz/pay-uz/blob/2.2.24/src/Services/PaymentService.php)
- [Upstream hardening pull request #73](https://github.com/shaxzodbek-uzb/pay-uz/pull/73)
- [pay-uz 3.0.0 release](https://github.com/shaxzodbek-uzb/pay-uz/releases/tag/3.0.0)

The reviewed advisory lists versions through 2.2.24 as affected and 3.0.0 as the first patched release. Confirm the installed package, published configuration, route cache, and runtime middleware rather than inferring exposure from a dependency name alone.

!!! warning "Authorized validation only"
    Use a disposable Laravel application, fake payment records, published canary hooks, and an isolated PHP runtime. Never replace production payment logic, submit real transactions, write a command-execution payload, touch credentials, or trigger a live payment callback. On a customer deployment, stop at dependency, route, middleware, and non-mutating response evidence unless explicit approval covers a lab clone.

## Why this pattern matters

Framework packages can silently add privileged routes to a host application. A feature described as an “editor” is especially sensitive when its output is PHP, a template, a job definition, or another artifact loaded by the runtime.

The boundary has four independent edges:

| Edge | Question | Safe evidence |
| --- | --- | --- |
| package reachability | is `goodoneuz/pay-uz` installed and are its routes registered? | lockfile entry and route-list output |
| authorization | does an anonymous or low-privilege request reach the action? | status/body and middleware trace with no write fields |
| write confinement | can request data select or replace an existing hook? | before/after hash of one disposable canary hook |
| execution | does a normal package path later load that hook? | instrumented `require` trace or no-op counter |

Do not collapse these into “RCE” from package presence. The strongest bounded finding demonstrates all four in a disposable environment.

## 1. Establish package and route reachability

Start offline where possible:

```bash
grep -n 'goodoneuz/pay-uz' composer.lock
composer show goodoneuz/pay-uz --locked
php artisan route:list --path=payment --columns=Method,URI,Name,Action,Middleware
```

Record:

- exact installed version and lockfile source reference;
- whether package route registration is enabled;
- the effective URI prefix after application customization;
- accepted methods for the editor update action;
- controller action and complete middleware chain;
- whether Laravel's route/config caches match the files on disk.

In 2.2.24, the package route file placed `/payment/api/editable/update` in a group whose empty/default configuration became `['web']`. Laravel's `web` middleware supplies session and CSRF behavior but is not authentication. Test actual runtime behavior: integrations may add a reverse-proxy control, custom middleware, or a published `config/payuz.php` override.

## 2. Use a non-mutating authorization matrix first

Send requests without `content` and `file_name`; the goal is to identify routing and authorization, not to modify a hook.

| Principal | Method | CSRF state | Expected secure result |
| --- | --- | --- | --- |
| anonymous | `GET` | none | authentication or authorization rejection |
| anonymous | `POST` | absent | rejection before controller side effects |
| authenticated ordinary user | accepted method | valid | authorization rejection |
| authorized control-panel admin | accepted method | valid | controller-level validation error for missing fields |

Capture the route name, status, redirect destination, response signature, applied middleware, and controller-entry trace. Because the affected route used `Route::any()`, include method variation: a CSRF rejection on `POST` does not prove that `GET`, `PUT`, or another accepted method is protected.

A meaningful pre-write result is **untrusted principal -> package route -> controller validation response**, while a secure control is **the same request rejected by authentication/authorization before controller entry**.

## 3. Prove the write boundary only in a disposable application

1. Install 2.2.24 in a throwaway Laravel application and publish only synthetic payment hook files.
2. Put unique comments and known hashes in the intended hook directory. Place a separate marker outside that directory for a no-write negative control.
3. Snapshot file paths, real paths, owners, modes, hashes, and modification times.
4. Select one existing synthetic hook. Preserve its expected PHP signature and replace its body only with a no-op return value or test-local counter; do not invoke a shell, network client, filesystem API, or dynamic evaluator.
5. Submit the editor request as an anonymous client using the method that reached the controller in the matrix.
6. Verify the response and compare the single hook's before/after hash. Confirm all other hooks and the outside marker are unchanged.
7. Repeat with a nonexistent hook name, an omitted field, an ordinary authenticated user, and 3.0.0.
8. Restore the lab snapshot before testing the load edge.

The 2.2.24 controller checks that the computed file already exists, but that is not authorization. Its request-selected name is concatenated into a path and the supplied content is passed to `file_put_contents()`. The fixed implementation adds an exact hook-name allowlist, verifies the resolved target remains directly in the intended directory, and places control-panel routes behind authentication by default.

Do not publish a traversal string. The ordinary named-hook overwrite is sufficient to establish the executable-file boundary, and an outside-directory marker can remain an untouched negative control.

## 4. Separate write from execution

The affected payment service loads named hooks such as `before_pay.php`, `after_pay.php`, `paying.php`, and `before_response.php` with `require`. Prove that edge without a command payload:

1. Restore a syntactically valid canary hook that increments only an in-memory test counter or returns a unique inert value.
2. Invoke the corresponding service method directly in a unit/integration test with fake models; do not call a payment provider.
3. Trace the loaded absolute path and assert the canary counter/value exactly once.
4. Run an untouched-hook control and a fixed-version control.
5. Tear down the application and delete all synthetic files.

Report the edges separately:

- **write primitive:** untrusted request changes an existing PHP hook;
- **load primitive:** a package service later `require`s that hook;
- **combined impact:** executable hook replacement reaches PHP evaluation under the application worker identity.

A changed hash alone is arbitrary content replacement, not proof of execution. A source-code `require` alone is reachability evidence, not proof that the tested deployment invokes that path.

## Fixed-version decision table

| Control | Affected expectation | 3.0.0 expectation |
| --- | --- | --- |
| anonymous request, no fields | controller may be reached depending on method/CSRF | auth rejection before controller |
| ordinary user with valid session | package configuration dependent | reject unless explicitly authorized |
| allowed hook name in authorized admin lab | existing hook may be updated | confined update only after authorization |
| unknown hook name | file-existence-dependent response | reject exact-name allowlist |
| symlinked allowed hook in lab | test only as a no-write boundary | resolved target must remain in hook directory |
| canary hook service path | hook loads in payment service | loads only administrator-authorized, confined content |

Also inspect published configuration after upgrade. Package defaults do not override every application-local configuration choice, and stale route/config caches can preserve surprising behavior.

## Reporting checklist

Include:

- package version, source reference, Laravel/PHP version, and deployment mode;
- route URI, accepted methods, route cache state, and effective middleware order;
- principal/session/CSRF state for every authorization row;
- target lexical path, resolved path, and before/after hash from the disposable app;
- exact service method and instrumented hook-load trace;
- affected-versus-fixed decision table and negative controls;
- confirmation that no live payment, external callback, credential, shell command, or production hook was used.

A precise impact statement is: **an unauthenticated package route can replace an existing application PHP payment hook, and a normal package service path later loads that hook under the application worker identity**. State any missing edge explicitly instead of upgrading route reachability or source inspection into an unverified remote-code-execution claim.
