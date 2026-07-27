# Snapshot reference images

Reference PNGs for `Tests/MailSecurityUITests/MailSecurityBannerSnapshotTests.swift`.

Each image is the rendered `MailSecurityBannerView` for one signature/trust
combination, rendered at 360pt width on macOS. The tests record an image here
when it is missing and compare against it otherwise.

When the banner UI intentionally changes, delete the affected PNGs and re-run
`swift test` to re-record them, then review the new images before committing.
Reference images are machine-specific (fonts, anti-aliasing); re-record them
when moving to a different macOS version or rendering environment.
