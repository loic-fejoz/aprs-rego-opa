# aprs-rego-opa

An [OpenPolicyAgent](https://www.openpolicyagent.org/) / [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/#what-is-rego) implementation of APRS digipeating rules.

APRS digipeating rules are presented in https://raw.githubusercontent.com/wb2osz/aprsspec/main/APRS-Digipeater-Algorithm.pdf 

Best up-to-date information about APRS is to be found at https://how.aprs.works/

The goal of this project is thus to understand those rules
and implement them in a formal way thanks to Rego.
Moreover eventually it could be usefull for a modern digipeater to have
a flexible policy to add blacklist, corrector and other similar feature.

The main policy is in [digipeat.rego](./aprs/digipeat/).
Some tests could be found in [digipeat_test.rego](./aprs/digipeat/digipeat_test.rego).

## how to use

Either copy paste into the online playground: https://play.openpolicyagent.org
Either install opa locally and run all tests:

```bash
cd aprs/digipeat/
opa test . -v
```

## Development environment

* [VSCode plugin by Torin Sandall](https://marketplace.visualstudio.com/items?itemName=tsandall.opa)

## Related projects

* https://github.com/wb2osz/aprsspec/
* https://github.com/iontodirel/libaprsroute
* https://github.com/iontodirel/aprs-test-data
