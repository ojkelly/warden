# Bunjil

[![Build Status](https://travis-ci.org/hawkly/bunjil.svg?branch=master)](https://travis-ci.org/hawkly/bunjil)
[![codecov](https://codecov.io/gh/hawkly/bunjil/branch/master/graph/badge.svg)](https://codecov.io/gh/hawkly/bunjil)
[![NSP Status](https://nodesecurity.io/orgs/hawklyio/projects/574d2c40-3802-4b60-9881-19845bf69b50/badge)](https://nodesecurity.io/orgs/hawklyio/projects/574d2c40-3802-4b60-9881-19845bf69b50)
[![Known Vulnerabilities](https://snyk.io/test/npm/bunjil/badge.svg)](https://snyk.io/test/npm/bunjil)

Authentication and authorization tokens designed specifically for use with zero-trust microservices.

**Is it done?**
Yes. But it needs a security review.

## Getting Started

This package is split into 3 main classes.

The `Forge` manages your keys. It will generate and rotate keys for you. You implemented this as a discrete service. Ideally as it's own container. The `Forge` manages two file shares, one for the `Warden` and one for the `Guard`. The keys are kept on these shares.

A `Warden` can create a `Card`, this is the bearer token you can pass around. You add this to the service that provides authentication.

A `Guard` can validate and extract the contents of a card. This is integrated into every service that needs to read a `Card`.


**How to create a `Card`**

```javascript
import { Warden } from 'bunjil';
import fsp from 'fs-promise';

const wardenKeySetCollection = await fsp.readJson(`${Shared Warden keys folder}/wardenKeySetCollection.json`);

// Create a new warden
const warden = new Warden(wardenKeySetCollection);
const card = await warden.createCard({
  uuid: 'string',
  tenant: [
    'string',
  ],
  roles: [
    'admin',
    'editor',
  ],
  hoursUntilExpiry: 1,
});
console.log(card);
// card:
// ODJmY2ZiYTIyYzJhZjlmMjc2ZWNlZjhlY2QxNjIwN2ZkOWMzNWRkODBlOWY3MGJkM2EzYWM0MzQ2MzRhNTY0NjU3YjgzYzY1NWM2MmNjNmRmNGJlOGQ5NjA0YmRmY2JiMWZkZGRmN2QwMDc1M2RiZDkwZWY5Y2IyY2MxZjQzNzBjZDI3ZDM3NDFhOGZlZjY1MGM3Yjk2ZDgyNjhhZTU3M2MzZGUzODQ2YjJmM2E1OWUwZjUwZDNjOGU4MjcxNzBlZTZmYmM1YjkwZWMwOWRhNmVhZTZjMTE3ODI4YzhlZThiMWZjYWE4OThhNTc1MmYwYjYxMzU3NmYzMjlhZThjM2E3ZmEwNDg2MTc2YTJlYmY0OTljYTY5M2Q0ZDhlYzY4ZDZkZjUxZGY2NzkzYzdhODEzOTAzMmVjYTdlMTNiNjZkZjFjNTFjMDQ4NzdkZmY4YWFlZTQ5YmNkMjllOTJhOGEyMDVkNTdkMThjMWZjYWQyMDk2ZGRjMjZlNDc5MTViMWRjNWE4YWQ4MTEyN2E5M2I4MGMyYWJjM2Y0YzIyMGFjNzc1ZTY3OGJjOGVlOWQ2Y2JjY2NkMjVlOGI1OWYzNDIzNDM2OTNhYjRmYTYyNzgwMTU1NDEwZDY2YjA3NWQwNDY3NWE3YWM1ZGU0NTllODBhNTJjZDczZGM2N2E3MGUxOGNmNWE4OGUyODFiZWVlY2U5MTg3ZmRiNzYyYjk3YjhkZmNmYzVjZDI2YTJlOTMxMDkxOWQ1NWIwZTEwNjhiNGM5MzkwNzhhNzgzMjI0NTdlNzQ3NDAzZDE4ZDgwZTFiNGY4N2I0M2M1ZWFlZjVkNmJlNGM5ZmIyNjA1MThkYTRhOWJiZTFjY2YxY2E3MTM2OGEwNzk2ZjYzNTQzZTg4YTZhMDE5OTI0NDFiMmU1NjVmMTAwM2FlZDc1ZDI0YjBhNjk3MWM0NTJhNzMzNTlkMTRhZDdmZTYyMjg0MDRkZjhkZGUzMzBkZWM5NDQzMWU0YTBlNzMzOTYxZTIzNWY0ODg4ODhjZDEwNzZmMWNjZDg4ZTY5Y2FmMGEyZGZlMmUwMWVjLjBiNTlhODcxM2JhODI5MWUwM2UzZTg5ZDhlMWJiMWM5LjdiMjVjMTMyNTk4NDZiY2YuODJmNTM5NGQ1MTFiMWQxYzQ0Y2Q5ZDBlZTU4NGEzNTIxZDViNzE3ZTFmMWJhMDlhMzY3MjNkYzhlOWFkOTJmMA==

```

How to use a card with a `Guard`

```javascript
import { Guard } from 'bunjil';
import fsp from 'fs-promise';

const wardenKeySetCollection = await fsp.readJson(`${Shared Guard keys folder}/guardKeySetCollection.json`);

try {
    const checkedCard = await guard.checkCard(card);
    console.log(checkedCard);
  } catch (err) {
    // Card is invalid
  }


// checkedCard:
// {
//    uuid: '523b519b-cb8b-4fd5-8a46-ff4bab206fad',
//    roles: [ 'engineer', 'onCall' ],
//    expires: 1490232381669,
//    tenant: [ '48d2d67d-2452-4828-8ad4-cda87679fc91' ]
//  }

```

The key sets are managed by the `Forge` class. This class looks after key rotate and the initial generation.
You should implement this as a completely seperate container, either running with an internal cronjob, or
set to spin up every hour.

Inside the container you need to have two file mounts, one for the Wardens keys and one the Guards. Pass the 
location of these to the `Forge` constructor. The `Forge` will load up the files, check if any keys have expired,
and rotate the collection if they have.

How to check and rotate the keys with `Forge`

```javascript
import { Forge } from 'bunjil';

const forge = new Forge({
    // The path to the directory where the Warden keys are stored.
    // This should be a mount shared with the Wardens.
    // Forge needs read-write access, Wardens must have read-only
    wardenKeySetDirectory: '/srv/wardenKeys',

    // The path to the directory where the Guards keys are stored.
    // This should be a mount shared with the Guards.
    // Forge needs read-write access, Guards must have read-only
    guardKeySetDirectory: '/srv/guardKeys',

    // Optionally you can set the maximum number of key sets to
    // keep on rotation. When a keyset expires it is replace with
    // a new one.
    maxKeySetsValid: 3,

    // Optionally you can set the maximum number of days a keyset
    // is valid for.
    // This must be greater or equal to the maximum time a Card
    // is valid for, becuase once the key a Card was created with
    // is rotated, that Card becomes invalid.
    maxKeySetValidDays: 5,
})

// This will check to see if any keys exist
// Then it will either create new ones, or cycle through
// and replace exipered ones.
try {
  await forge.rotateKeys();
} catch(err){
  console.warn(err);
  // If this fails you should crash the process and try again
  process.exit(1);
}
```

## Configuration

This module is an answer to the state of JWT. In learning from the mistakes there, and apply that to
the specific problem of authentication and authorization in a zero-trust microservices system, you have
almost no configuration options.

There is no capability to change the cryptography used, or how it's used. These options are baked into
the library itself. Any change to the cryptography used, is considred a breaking change and will
be identified with a major version bump.

You do however have control over the expiry length of `Cards`.

TODO: examples with full docker/docker-compose examples of `forge service` container, `auth service` container, and `service` container.

---
(hawkly.io)[https://hawkly.io]

(Owen Kelly)[https://owenkelly.com.au]
