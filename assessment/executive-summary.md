# Executive summary

[EXECUTION] The assessment ran commit `8b51e6297661c9a653e1647c00f7f0738724bad3` plus the recorded dirty worktree against a deterministic service bound only to `127.0.0.1:18080`.

[REPOSITORY] Katana is optional and disabled by default; its embedded engine always returns an error, after which Raptor tries the installed binary and continues with Raptor-only discovery if that also fails.

[EXECUTION] Standalone Katana standard and headless passes, Raptor-only, Raptor with a successful Katana pre-pass, a Katana-unavailable fallback, and authenticated Chromium/CDP passes were exercised separately.

[EXECUTION] SQLMap confirmed the fixture `id` parameter twice by boolean, time, and UNION techniques and rejected the prepared-statement control. Dalfox produced a verified execution-tier reflected-XSS result and rejected the escaped control. Nuclei's pinned custom template matched twice and rejected its control. LFImap sent three bounded marker-wordlist requests per case but reported no vulnerability; manual marker-only replay proved the fixture behavior, so no LFImap scanner finding is claimed.

[REPOSITORY] Only SQLMap raw-request export and Dalfox GET-URL export are implemented as repository adapters. LFImap and Nuclei have no executable adapter despite README roadmap language.

[EXECUTION] The non-cached test suite failed two dynamic integration tests: login POST capture lacked configured credentials, and modal/drawer workflows were blocked by mutation policy. Other packages passed.

[RECOMMENDATION] P0 work should fix body completeness/base64 handling and response-status persistence, bind crawl IDs consistently, and prevent eligible scanner rows from being produced for incomplete bodies. P1 should make Katana path resolution deterministic and add first-class scanner run/finding persistence.
