# SecureAI Visual Prototype

## Overview
Build a polished, faculty-friendly SecureAI prototype using the supplied charcoal-and-orange cybersecurity visuals as the design reference. Keep all data mocked and make the five requested pages easy to understand within one minute.

## Pages
- **Dashboard:** security score, open findings, last scan, recent findings, and a prominent Start Scan action.
- **Scan:** target input, three security checks, a compact progress display, and a working simulated scan.
- **Findings:** a clean table containing the three supplied mock vulnerabilities and links into remediation.
- **Remediation:** selected issue, AI explanation, recommended fix, before/after code comparison, approve and reject actions.
- **Verification:** passed security and functionality checks with a clear verified verdict.

## Visual Direction
- Dark charcoal shell with near-black panels, warm orange accents, crisp white type, thin borders, and restrained glow.
- Fixed desktop sidebar inspired by the references, adapted into a compact mobile header.
- Sparse, information-first layouts with no maps, complex charts, enterprise modules, or decorative clutter.
- Small purposeful transitions only; respect reduced-motion settings.

## Interaction
- Navigation works across all five pages.
- Dashboard and Scan actions navigate into the scan flow.
- Scan progress can be started and visibly completes using mock state.
- Finding rows open remediation with the selected finding.
- Approve proceeds to Verification; Reject returns to Findings.

## Technical Notes
- Use TanStack file-based routes and shared navigation.
- Define all palette, typography, spacing, border, and shadow roles as semantic tokens in the global design system.
- Add unique metadata for every page and verify the main flow at desktop and mobile sizes.
