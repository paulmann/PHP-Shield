## What this changes

<!-- One paragraph: the defect or the feature, and why it matters. -->

## Type

- [ ] Bug fix
- [ ] New detection rule
- [ ] New storage / rate-limiter / reputation backend
- [ ] Documentation
- [ ] Refactoring without behaviour change

## Checklist

- [ ] `composer test` is green (a new rule has **positive and negative** cases)
- [ ] `composer phpstan` reports zero errors at level max
- [ ] `composer cs-check` is clean
- [ ] `CHANGELOG.md` has an entry under `Unreleased`
- [ ] `README.md` and the [wiki](https://github.com/paulmann/PHP-Shield/wiki) are updated if the public API, configuration or rule table changed
- [ ] No secret, real customer address or production host name is committed
- [ ] A configuration example points at an environment variable, never at a literal key

## False positives

<!-- For a detection change: which legitimate request could this rule now catch? -->

## Verification

<!-- Commands you ran and their result, not "it works". -->
