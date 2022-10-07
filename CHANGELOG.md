# CHANGELOG

## 0.91.10

* [Feature] Added Wintun support. Dll downloaded from www.wintun.net is needed for standalone_client to run under Windows.

## 0.90.15

* [Feature] Route QUIC connections according to the VPN mode instead of always dropping or redirecting them

## 0.90.13

* [Fix] Fix leaks and memory bugs in `tls_serialize_cert_chain`, `tls_free_serialized_chain`. Add tests.

## 0.90.12

* [Fix] Change signature of some exported functions to be more consistent with the rest and simpler for C# bindings.

## 0.90.6

* [Fix] Fix version increment script.

## 0.90.4

* [Feature] VpnLibs is now open-source.
