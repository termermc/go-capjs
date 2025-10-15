# go-capjs

<img align="left" width="75" height="75" src="./logo.png">

```
Go implementation of Cap.js, proof-of-work captcha
with support for modular storage drivers.
```

---

[Cap.js](https://capjs.js.org/) is a proof-of-work "captcha" that requires website visitors to solve a cryptographic challenge in lieu of a traditional captcha.

It does not prevent automated traffic, but it does make it significantly more expensive in high volumes.
For a comparison of Cap with other captchas, check out [this page](https://capjs.js.org/guide/alternatives.html).
The most important part of Cap is that it is both effective in limiting mass spam and fully self-hostable.

## Modules

The main module, [cap](./cap) provides challenge creation and validation functions, but it does not provide storage for the actual challenges.
Instead, storage is implemented using drivers.
This allows for multiple different ways of storing challenges, and allows the main module to stay dependency-free.

This project includes the following modules:

 - [cap](./cap) The base for implementing a Cap.js server, including `http.HandlerFunc` implementations for endpoints
 - [sqlitedriver](./sqlitedriver) SQLite storage driver
 - [redisdriver](./redisdriver) Redis storage driver
 - [demo](./demo) A simple demo using the SQLite driver and a form widget

<details>
<summary>Where's the in-memory driver?</summary>
While there is no dedicated in-memory driver, you can use the SQLite driver with an in-memory SQLite connection to achieve the same result.
You're always free to implement your own driver, though!
</details>
