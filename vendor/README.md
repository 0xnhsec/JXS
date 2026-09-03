# vendor/

Third-party tools used (or planned) by jxs. They are **NOT bundled** with this
repo — clone them separately into `vendor/` (licensing and repo-size reasons).
Fresh clones therefore get empty directories here; that is expected.

| Tool | Role in jxs | Upstream |
| --- | --- | --- |
| JSFinder | Passive JS link/endpoint discovery — currently NOT auto-invoked (future integration) | https://github.com/Threezh1/JSFinder |
| LinkFinder | Endpoint regex source — re-implemented natively in `src/extraction/patterns.py` | https://github.com/GerbenJavado/LinkFinder |
| js-beautify | JS beautifier used by the extractor — installed via pip as `jsbeautifier` | https://github.com/beautify-web/js-beautify |
| mantra | Secret scanner (Go binary) — invoked as a subprocess; set `MANTRA_BIN` or put it on `PATH` | https://github.com/MrEmpy/mantra |
| wappalyzer | Tech fingerprints — hand-translated into `src/techstack/detector.py` | https://github.com/enthec/webappalyzer |
| CF-Hero | Cloudflare origin recon — standalone, not wired into the pipeline | https://github.com/m0zgen/CF-Hero |
| Scrapling | Planned: active verification engine | https://github.com/D4Vinci/Scrapling |
| vulnerability-Checklist | Planned: advisor extension | upstream: (check author's original reference) |

`vendor/*/` is gitignored — only this README is tracked.
