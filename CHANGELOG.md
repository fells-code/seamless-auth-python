# Changelog

## [0.6.0](https://github.com/fells-code/seamless-auth-python/compare/v0.5.0...v0.6.0) (2026-11-06)


### ⚠ BREAKING CHANGES

* FastAPI RequireUser refusals (unauthenticated, insufficient_role, enrollment_required, cross_site_request_blocked) answer {"error": "<code>"} instead of {"detail": "<code>"}. A client that reads body.detail must read body.error. They also no longer reach an application's own HTTPException handler. To change them, register a handler for GuardHTTPException.

### Added

* **guard:** add an organization-aware permission guard ([#38](https://github.com/fells-code/seamless-auth-python/issues/38)) ([002ecb4](https://github.com/fells-code/seamless-auth-python/commit/002ecb4b8cff57984525b87be0862621d3ab0ffc)), closes [#32](https://github.com/fells-code/seamless-auth-python/issues/32)
* let verify-only resource servers require a user ([#35](https://github.com/fells-code/seamless-auth-python/issues/35)) ([d095109](https://github.com/fells-code/seamless-auth-python/commit/d09510916ab386186e22c3ddb3ad3869695b6764))


### Fixed

* answer FastAPI session guard refusals under error ([#39](https://github.com/fells-code/seamless-auth-python/issues/39)) ([76739c1](https://github.com/fells-code/seamless-auth-python/commit/76739c1b560e8fc9419eec6b647ba4434f0f32af))
* keep the session cookies when a refresh fails transiently ([#37](https://github.com/fells-code/seamless-auth-python/issues/37)) ([586b933](https://github.com/fells-code/seamless-auth-python/commit/586b933ba88f99a0cd1f17dd320c55f4cf2068ef))
* origin check whatever the SameSite setting, and no JWKS lock across the fetch ([#33](https://github.com/fells-code/seamless-auth-python/issues/33)) ([3f8e828](https://github.com/fells-code/seamless-auth-python/commit/3f8e8287b5129b66783bc53576ee3653f8f0802f))
* sync the bundled adapter manifest with API 0.22.0 ([5de9986](https://github.com/fells-code/seamless-auth-python/commit/5de9986529789f4b5a804b3bf8166463e4b79fef))
* sync the bundled adapter manifest with API 0.22.0 ([f89c39c](https://github.com/fells-code/seamless-auth-python/commit/f89c39c38ffd1d65c22f92c97a3c513a6e8ec9c1))

## [0.5.0](https://github.com/fells-code/seamless-auth-python/compare/v0.4.0...v0.5.0) (2026-11-01)


### Added

* first-party role guard, optional user and organization on User ([171babb](https://github.com/fells-code/seamless-auth-python/commit/171babbcaa6cb5544cbf97fd5d30520a581de89b))
* first-party role guard, optional user and organization on User ([0c97616](https://github.com/fells-code/seamless-auth-python/commit/0c9761609fbfc2ba9483b898614d6bc683db0297)), closes [#28](https://github.com/fells-code/seamless-auth-python/issues/28)


### Fixed

* skip the origin check for bearer-transport auth requests ([ea1898d](https://github.com/fells-code/seamless-auth-python/commit/ea1898da7f3f075b342e95150b791efdd4024eb8)), closes [#28](https://github.com/fells-code/seamless-auth-python/issues/28)
* sync the bundled adapter manifest with API 0.21.1 ([ede9798](https://github.com/fells-code/seamless-auth-python/commit/ede97982542715484853ebeee6fdaf2024b8e196)), closes [#27](https://github.com/fells-code/seamless-auth-python/issues/27)
* sync the bundled adapter manifest with API 0.21.1 and check it in CI ([08a98d5](https://github.com/fells-code/seamless-auth-python/commit/08a98d5c454beb52986c4669c76320728de0cbbd))

## [0.4.0](https://github.com/fells-code/seamless-auth-python/compare/v0.3.0...v0.4.0) (2026-11-01)


### Added

* verify-only resource server mode with audience, scope, role and step-up guards ([f5b58bf](https://github.com/fells-code/seamless-auth-python/commit/f5b58bfc6eeee24af3161505e6800a6d70349605))
* verify-only resource server mode with audience, scope, role and step-up guards ([8187925](https://github.com/fells-code/seamless-auth-python/commit/8187925c5d9afb294c242860a8f2d06c2203e22b))


### Fixed

* Origin allowlist with Sec-Fetch-Site, and verify the cookie's inner access token ([2e52141](https://github.com/fells-code/seamless-auth-python/commit/2e521414a22c6ea8f3e4463d384a0a45cb2517f9))
* Origin allowlist with Sec-Fetch-Site, and verify the cookie's inner access token ([46af635](https://github.com/fells-code/seamless-auth-python/commit/46af63556f4665f46395ff212dde2c665f11cee6)), closes [#15](https://github.com/fells-code/seamless-auth-python/issues/15)


### Documentation

* show unsubscribe headers from your own sender and the invite's signInUrl ([1d5087f](https://github.com/fells-code/seamless-auth-python/commit/1d5087fb51f0c00959178c4216c4ef4d59d05708))
* show unsubscribe headers from your own sender and the invite's signInUrl ([1aa4db4](https://github.com/fells-code/seamless-auth-python/commit/1aa4db447690831079fa943c30d9b8aaf925f0f0))

## [0.3.0](https://github.com/fells-code/seamless-auth-python/compare/v0.2.2...v0.3.0) (2026-10-25)


### Added

* deliver account recovery notices and serve the v0.20 recovery routes ([9ebf903](https://github.com/fells-code/seamless-auth-python/commit/9ebf903a4e33bf18513be465b11cb606b6296e1f)), closes [#13](https://github.com/fells-code/seamless-auth-python/issues/13)
* refuse recovery sessions in the guard and refresh after enrollment ([94e381d](https://github.com/fells-code/seamless-auth-python/commit/94e381d4f6a6165aa151a0d5a81bd676c4493f88))
* v0.20 recovery sessions, account notice delivery and console headers ([8247e20](https://github.com/fells-code/seamless-auth-python/commit/8247e20a6028db4a0b0bdffc4cb3fc1f58e7ec04))


### Fixed

* cancel a recovery request when no owner notice is delivered ([15d0fdf](https://github.com/fells-code/seamless-auth-python/commit/15d0fdf68e753b99ad2a26476bf85ca3311f9b0f)), closes [#13](https://github.com/fells-code/seamless-auth-python/issues/13)
* **console:** keep the API's framing and sniffing headers on the console proxy ([2ab4430](https://github.com/fells-code/seamless-auth-python/commit/2ab4430f5733cf2cd2157d3b8bbb2b0f193586cc)), closes [#12](https://github.com/fells-code/seamless-auth-python/issues/12)
* refuse known placeholder secrets at startup ([731a719](https://github.com/fells-code/seamless-auth-python/commit/731a719a814d4e6abb6d9b41c78e789961905e2b))


### Documentation

* link the governance document and license pledge ([3478bcf](https://github.com/fells-code/seamless-auth-python/commit/3478bcf36492742ba1b4d1fc51d900bb9c50f943))
* link the governance document and license pledge ([44fe697](https://github.com/fells-code/seamless-auth-python/commit/44fe697feef842946c9081ec13b916882f05c518))

## [0.2.2](https://github.com/fells-code/seamless-auth-python/compare/v0.2.1...v0.2.2) (2026-10-18)


### Fixed

* forward the pre-auth token on magic link verify and serve the confirm route ([#8](https://github.com/fells-code/seamless-auth-python/issues/8)) ([5994d28](https://github.com/fells-code/seamless-auth-python/commit/5994d28aa78a20e1d614949d3691487b2a25755e))

## [0.2.1](https://github.com/fells-code/seamless-auth-python/compare/v0.2.0...v0.2.1) (2026-10-13)


### Documentation

* name the app-side service token SEAMLESS_SERVICE_TOKEN ([8872754](https://github.com/fells-code/seamless-auth-python/commit/887275490f3559d44e27c1673d2c2006c62dca6a))
* name the app-side service token SEAMLESS_SERVICE_TOKEN ([034b7fa](https://github.com/fells-code/seamless-auth-python/commit/034b7faea1e08acb0fee117e34c9046fc8dd9545))

## [0.2.0](https://github.com/fells-code/seamless-auth-python/compare/v0.1.0...v0.2.0) (2026-10-08)


### Added

* serve the admin console from FastAPI and Django ([2f522be](https://github.com/fells-code/seamless-auth-python/commit/2f522be806b21427d2a55eb2ef37c4b010ecc195))
* serve the admin console from FastAPI and Django ([b2acdee](https://github.com/fells-code/seamless-auth-python/commit/b2acdee36292f874ea9d5c46c3155f0939cbd85a))

## 0.1.0 (2026-10-08)


### Added

* Seamless Auth server adapter for FastAPI and Django ([1f3fab7](https://github.com/fells-code/seamless-auth-python/commit/1f3fab7ff35fa44b5587a6a095c24c4b05888166))

## Changelog

All notable changes to this project are documented in this file. The release
automation (release-please) writes each entry from the Conventional Commits it
releases.
