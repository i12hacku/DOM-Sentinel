# Changelog

All notable changes to DOM Sentinel are documented here.
This project follows [Semantic Versioning](https://semver.org/) and the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

- **MAJOR** — breaking changes (removed features, changed permissions or stored-data format)
- **MINOR** — new features that keep working the same way for existing users
- **PATCH** — bug fixes only

## [Unreleased]

### Added
- Review findings as **Confirmed**, **False positive** or **Accepted risk**. Reviews are saved per site and reapplied automatically on every scan.
- Review filter (Hide dismissed, Not reviewed, Confirmed, False positives, Accepted risks, All findings) and a "reviewed" progress count.
- Undo after dismissing a finding, and a "dismissed" link in the header that shows dismissed findings.
- Settings: delete all reviews saved for the current site.
- Scan comparison: each scan is compared with the previous scan of the same page. The header shows how many findings are new, fixed and unchanged.
- "New" flag on findings that appeared since the last scan, and **New since last scan** / **Fixed since last scan** options in the findings filter.
- Markdown and JSON exports include the changes since the last scan and the list of fixed findings.
- Settings: delete the scan history saved for the current site.
- DOM Sentinel logo as the extension icon (toolbar, extensions page, DevTools tab), with `icons/make-icons.ps1` to regenerate the sizes from the source logo.

### Changed
- The severity bar, counts and tab badge now leave out dismissed findings.
- Markdown export lists each finding's review and moves dismissed findings to their own section. JSON export adds a `review` field to each finding.
- "Explain and prioritise findings" no longer sends dismissed findings to the AI.

## [2.1.0] - 2026-11-06

### Added
- Threat spectrum bar in the header that shows the page's severity mix and works as a severity filter.
- Light and dark themes that follow the system setting, or the DevTools theme inside DevTools.
- Empty states that explain what each tab does before the first scan.
- Keyboard and screen-reader support: visible focus outlines, expandable finding rows, and announced status messages.

### Changed
- Redesigned the panel with ruled finding rows, a "How to fix or verify" note on each finding, and plainer labels.
- Findings, hidden elements and recon data are now shown as rows on one sheet instead of separate cards.

## [2.0.1] - 2026-11-06

### Fixed
- The side panel header no longer shows "null" after the domain on root URLs such as `https://example.com/`.
- AI requests now retry when Gemini is temporarily overloaded (HTTP 503/429/500).
- AI requests now raise the token limit when a "thinking" model uses it all before answering (`MAX_TOKENS`).

## [2.0.0] - 2026-11-05

### Added
- Local rule-based scanner covering security headers, cookie flags, secrets and JWTs, DOM XSS hints, forms, mixed content, Subresource Integrity, source maps, vulnerable libraries and console errors.
- Hidden element discovery with reveal and restore on the live page.
- Recon view, JavaScript runner with snippets, element picker and editor.
- DevTools "Security" panel and Elements sidebar, alongside the side panel.
- Optional opt-in active checks for well-known sensitive paths.
- Markdown and JSON report export.

### Changed
- Gemini AI is now optional. The model is picked automatically from those your key can use.
- Replaced the popup with a side panel, so results stay visible while you browse.

[2.1.0]: https://github.com/<your-username>/dom-sentinel/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/<your-username>/dom-sentinel/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/<your-username>/dom-sentinel/releases/tag/v2.0.0
