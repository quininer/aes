AES implementation
------------------

Performance is not the goal of this implementation.
Unless your platform does not support `AES-NI`, otherwise you should always use `openssl` / `rust-crypto`.


| name			| performance
|---------------|------------------------
| aes			| 2,404 ns/iter	(+/- 117)
| rust-crypto	| 489 ns/iter	(+/- 24)
| openssl		| 320 ns/iter	(+/- 39)
