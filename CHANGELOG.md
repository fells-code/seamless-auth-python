# Changelog

## [0.4.0](https://github.com/fells-code/seamless-auth-python/compare/v0.3.0...v0.4.0) (2026-10-31)


### Added

* verify-only resource server mode with audience, scope, role and step-up guards ([f5b58bf](https://github.com/fells-code/seamless-auth-python/commit/f5b58bfc6eeee24af3161505e6800a6d70349605))
* verify-only resource server mode with audience, scope, role and step-up guards ([8187925](https://github.com/fells-code/seamless-auth-python/commit/8187925c5d9afb294c242860a8f2d06c2203e22b))


### Fixed

* Origin allowlist with Sec-Fetch-Site, and verify the cookie's inner access token ([2e52141](https://github.com/fells-code/seamless-auth-python/commit/2e521414a22c6ea8f3e4463d384a0a45cb2517f9))
* Origin allowlist with Sec-Fetch-Site, and verify the cookie's inner access token ([46af635](https://github.com/fells-code/seamless-auth-python/commit/46af63556f4665f46395ff212dde2c665f11cee6)), closes [#15](https://github.com/fells-code/seamless-auth-python/issues/15)

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
