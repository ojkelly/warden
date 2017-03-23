# Bunjil

Authentication and authorization tokens designed specifically for use with zero-trust microservices.

**Is it done?**
Almost.

## What is this?

A cryptographically secure token that can be passed from an `iam service` to an internal `service`
via a public untrusted medium (browser, mobile device).

The `Card` functions as a bearer token, where the bearer of the token/`Card` has access to the resources
avaible to the `Card`.

The `iam service` should be the only entity that can create the `Card`, but any
internal `service` should be able to decrypt the token, read it's content, and verify that
the contents were created by `iam service`.

## Getting Started

This package is split into 3 main classes.

The *Forge* manages your keys. It will generate and rotate keys for you. This is implemented as a discrete service.

A *Warden* can create a `Card`, this is the bearer token you can pass around. This is implemented as a discrete service, the `IAM service`.

A *Guard* can validate and extract the contents of a card. This is integrated into every service that needs to read a `Card`.

In the `./examples` folder you will find an example of each service you need to implement.

With Docker/Kubernetes or any other good container service you can manage the keys and key rotation easily. To ensure the ability to safely and regularly rotate keys, we will always maintain a key collection of at least 4 `key sets`. A `key set` contains a `public`/`private` RSA key pair, a 256 bit `symmetric` key, a 256 `hmac` key, and a timestamp of the `key set's` `expiry` date. These are split into two types of `key set`, the `WardenKeySet` which contains everything mentioned above, and a `GuardKeySet` which contains everything **except the `private` key**.

Because we have at least 4 `key sets` we group them into `WardenKeySetCollection` and `GuardKeySetCollection`.

You need two file mounts. One for the `WardenKeySetCollection` and one for the `GuardKeySetCollection`. Both must be mounted as read/write to the `forge service`. Then the `WardenKeySetCollection` should be mounted read-only to the `warden service`, and th `GuardKeySetCollection` should be mounted to any service implementing a `Guard`.

---

## Design

### Requirements

1. A `Card` must function as a bearer token, where the bearer of the `Card` has access to resources allowed for that `Card`.
2. A `Card` must only be created from a single anointed service deemed the `iam service` for Identity and Access Management; this requirement must be cryptographically guarenteed.
3. A `Card's` contents must be opaque to the public, but transparent to internal services.
4. A `Card's` integrity must be ensured (else the card is invalid) when in transit, this must be cryptographically guarenteed.
5. A `Card` must have a well defined expiry time, that must be enforced.
6. A `Card` expiration time is set by the `Warden` and must be enforced by the `Guards`.

### Explanation

The `Card` is designed with a few layers for specific functions. From the inside out we have a JSON object representing the actual contents.

First we sign the contents of the `Card` object (specifically we stringify the object, then sign the resulting string).

We encrypt the `Card` and the `signature` with authentitcated encryption with a key shared between services, so our other services can decrypt it. We use authenticated encryption to ensure; the contents can only be read by
our services, the integrity of the contents is assured, we have assurance that the contents was encrypted by us (that is, by any service with the key), and by signing it with the `private key`, we have assurance that it could only have come from the `iam service`.

The authenticated encrypted uses an Initialisation Vector (`iv`) and outputs an `encrypted chunk` and
an `authorisation tag`.

We concatencate these together with periods (`.`) and sign the result with the
private key (only held by the `iam service`). This provides a guareentee that the encrypted contents of the `Card` we're created by `iam service` (as that's the only service with the
private key).

We then HMAC that. This guarentees that the contents has not been modified in transit.


Assumptions:
There a a set of key pairs.
Each key pair contains a `private`, `public` and `symmetric` key.

`iam service` is the sole holder of the `private` keys.
All `services` are holders of the `public` and `symmetric` keys.
Clients (browsers/mobile) hold no keys, but do transit the token.

### Protocol

*Warden*

**A Warden can issue cards to users.**

1. Create a `Card`, which contains information about the user, and their roles.
2. Choose a `keySet`.
3. Sign the `Card` with the private key `keySet.privateKey`.
4. Encrypt the `Card` and `signature` (from #3) with a shared key `keySet.symmetric`.
5. Create a HMAC for the the encrypted `Card` + `signature` (result of #4).
6. Concatenate `encrypted` and `hmac` into `encrypted.hmac`.

*Guard*

**A Guard can verify the authenticity and integrity of a card, and return the information stored on
that card.**

1. Split into `encrypted` and `hmac`.
2. Check HMAC for `hmac` with all keys in the keySets, if valid return the keySet (else card invalid)
3. Decrypt `encrypted` with `keySet` from #2.
4. Check signature from result of #3 with `key.publicKey` from the `keySet` from #2.
5. Hydrate the `Card` (property names are shrunk when sent on the wire).
6. Check the `Card` has not expired.
7. Return the `Card` object.


*In practice*

1. The `token` is created by the `iam service`.
2. The `token` is delivered to the users browser as a `HttpOnly` cookie.
  - There is no reason or need for the browser to read the `token`, as it should be completely
  opaque and unreadable. The browser will know the `token` is correct based on the response from
  calling services with the `token`.
3. The `token` is passed from the browser to a `service`.
4. The `service` first checks the authenticity of the `token`, that it was created by `iam service`.
5. Then the `service` decrypts the payload of the `token`, revealing some information about the user.


TODO: examples with full docker/docker-compose examples of `forge service` container, `auth service` container, and `service` container.

---
hawkly.io
Owen Kelly
