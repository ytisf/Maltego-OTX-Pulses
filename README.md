# OTX AlienVault Pulses Maltego Transforms

## What is This
These are 3 transforms (transform-set) to do the following lookups:
- Domain to related pulses (including malware and adversaries).
- IPv4 to related pulses (including malware and adversaries).
- Hash to related pulses (including malware and adversaries).

**Important Notice** - Domain lookup will lookup either a subdomain (www.github.com) as `hostname` OR a domain name (github.com) and will lookup a `domain` according to AlientVault. This means that if you look for a Domain Entity of the content 'www.github.com' and it appears in a pulse as a hostname, it will appear. If it, however, appears as the domain 'github.com' then the search you've ran will not find that.

## How to Install
1. Copy all of the files to a folder `X`.
2. Run `pip install --user -r requirements.txt`.
2. Import the `maltego-OTX.mtz` file directly to Maltego.
3. Go to Maltego into the tab `Transforms` and hit `Transform Manager`.
4. Find the transforms by typing `otx` on the search bar on the top right.
5. Edit the `Command line` to point to your Python directory.
6. Edit the `Working Directory` to point to where you've copied the files (`X`).

## Appendix

Thanks to @paterva for `maltego-trx`.
