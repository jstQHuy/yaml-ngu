KB Starter Pack (Level 1)

Files:
- kb/signatures.yaml  : signature rules (keyword/regex -> vuln_type + CVE hints)
- tools/kb_query.py   : offline matcher that reads your recon artifact JSON and produces triage JSON

Install dependency:
  pip install pyyaml

Run:
  python tools/kb_query.py --artifact recon_memory/<TOPIC>_artifact.json --signatures kb/signatures.yaml

Tip (to make rules useful):
Populate analysis.web.evidence with a few short lines like:
  "80: Server: Apache/2.4.49"
  "80: Title: Stratosphere"
And analysis.web.interesting_paths with discovered paths (e.g. "/cgi-bin/user.sh").
