import * as crypto from 'crypto';
import * as fsp from 'fs-promise';

import { Forge, ForgeInitKeySet, ForgeKeySet } from './Forge';

import { GuardKeySet } from './Guard';
import { WardenKeySet } from './Warden';
import { test } from 'ava';

// We need some random in some tests
function getRandom(length = 24): Promise<string> {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(Math.ceil(length / 2), (err, buf) => {
      if (err) {
        reject(err);
      } else {
        resolve(buf.toString('hex'));
      }
    });
  });
}

test.before(async () => {
  // clean up the tmp folder
  await fsp.remove('./tmp');
});

test('can create a forge with options', (t: any) => {
  const forge: Forge = new Forge({
    wardenKeySetDirectory: 'warden',
    guardKeySetDirectory: 'guard',
    maxKeySetsValid: 3,
    maxKeySetValidDays: 5,
  });

  t.is(forge.wardenKeySetDirectory, 'warden');
  t.is(forge.guardKeySetDirectory, 'guard');
  t.is(forge.maxKeySetsValid, 3);
  t.is(forge.maxKeySetValidDays, 5);
});

test('forge can create ForgeKeySet', async (t: any) => {
  // Construct a new Forge
  const forge: Forge = new Forge();
  const keySet: ForgeKeySet = await forge.createNewKeySet();
  t.is(keySet.wardenKeySet.publicKey, keySet.guardKeySet.publicKey);
  t.is(keySet.wardenKeySet.symmetric, keySet.guardKeySet.symmetric);
  t.is(keySet.wardenKeySet.hmac, keySet.guardKeySet.hmac);
  t.is(keySet.wardenKeySet.expires, keySet.guardKeySet.expires);

});
test('forge can create ForgeKeySet with custom expires', async (t: any) => {
  // Construct a new Forge
  const forge: Forge = new Forge();
  const dayMultiple: number = 7;
  const expires: any = new Date();
  expires.setTime(expires.getTime() + dayMultiple * 86400000);
  const expiry: number = expires.getTime();
  const keySet: ForgeKeySet = await forge.createNewKeySet(expiry);

  t.is(keySet.wardenKeySet.publicKey, keySet.guardKeySet.publicKey);
  t.is(keySet.wardenKeySet.symmetric, keySet.guardKeySet.symmetric);
  t.is(keySet.wardenKeySet.hmac, keySet.guardKeySet.hmac);
  t.is(keySet.wardenKeySet.expires, keySet.guardKeySet.expires);
  // Check this keySet has our custom expires time
  t.is(expiry, keySet.guardKeySet.expires);
  t.is(expiry, keySet.wardenKeySet.expires);
});
test('forge can create complete keySetCollections', async (t: any) => {
  // Construct a new Forge
  const forge: Forge = new Forge();

  // Generate a brand new set of keySets
  const keySetCollection: ForgeInitKeySet = await forge.initKeySetCollections();

  let matchingKeys: number = 0;

  keySetCollection.wardenKeySetCollection.forEach((wardenKeySet: WardenKeySet) => {
    // Find the matching guardKeySet
    keySetCollection.guardKeySetCollection.forEach((guardKeySet: GuardKeySet) => {
      // Match the wardenKeySet with the guardKeySet based on the symmetric key matching
      if (wardenKeySet.symmetric === guardKeySet.symmetric) {
        // Log the match
        matchingKeys = matchingKeys + 1;
        // Now double check all the paired fields do actually match
        t.is(wardenKeySet.publicKey, guardKeySet.publicKey);
        t.is(wardenKeySet.symmetric, guardKeySet.symmetric);
        t.is(wardenKeySet.hmac, guardKeySet.hmac);
        t.is(wardenKeySet.expires, guardKeySet.expires);
      }
    });
  });

  // The number of matching keys should match the length of the keys generated
  t.true(matchingKeys === keySetCollection.wardenKeySetCollection.length);
  t.true(matchingKeys === keySetCollection.guardKeySetCollection.length);

});

test('forge rotate expired key', async (t: any) => {
  // Construct a new Forge
  const randomString = await getRandom();
  const wardenKeySetDirectory: string = `./tmp/${randomString}/warden`;
  const guardKeySetDirectory: string = `./tmp/${randomString}/guard`;
  const forge: Forge = new Forge({
    wardenKeySetDirectory,
    guardKeySetDirectory,
  });

  // Clear the tmp folder
  await fsp.remove(`./tmp/${randomString}`);


  const dayMultiple: number = -7;
  const expires: any = new Date();
  expires.setTime(expires.getTime() + dayMultiple * 86400000);
  const expiry: number = expires.getTime();

  // Create our expired keyset
  const keySet: ForgeKeySet = await forge.createNewKeySet(expiry);

  t.is(keySet.wardenKeySet.publicKey, keySet.guardKeySet.publicKey);
  t.is(keySet.wardenKeySet.symmetric, keySet.guardKeySet.symmetric);
  t.is(keySet.wardenKeySet.hmac, keySet.guardKeySet.hmac);
  t.is(keySet.wardenKeySet.expires, keySet.guardKeySet.expires);
  // Check this keySet has our custom expires time
  t.is(expiry, keySet.guardKeySet.expires);
  t.is(expiry, keySet.wardenKeySet.expires);

  // Create a full keySetCollection
  const keySetCollection: ForgeInitKeySet = await forge.initKeySetCollections();

  // Add our expired keyset
  keySetCollection.wardenKeySetCollection.push(keySet.wardenKeySet);
  keySetCollection.guardKeySetCollection.push(keySet.guardKeySet);

  // confirm the expired keyset is in our collections
  const searchForWardenKeySet: WardenKeySet | undefined =
    keySetCollection.wardenKeySetCollection.find((wardenKeySet: WardenKeySet) => {
      return wardenKeySet.symmetric === keySet.wardenKeySet.symmetric;
    });
  if (typeof searchForWardenKeySet === undefined || searchForWardenKeySet === undefined) {
    t.fail();
    return;
  }
  t.is(searchForWardenKeySet.symmetric, keySet.wardenKeySet.symmetric);

  const searchForGuardKeySet: GuardKeySet | undefined =
    keySetCollection.guardKeySetCollection.find((guardKeySet: GuardKeySet) => {
      return guardKeySet.symmetric === keySet.guardKeySet.symmetric;
    });
  if (typeof searchForGuardKeySet === undefined || searchForGuardKeySet === undefined) {
    t.fail();
    return;
  }
  t.is(searchForGuardKeySet.symmetric, keySet.guardKeySet.symmetric);

  // Rotate the collection
  await forge.processKeySetCollections(keySetCollection.wardenKeySetCollection, keySetCollection.guardKeySetCollection);

  const wardenFileSearch = await fsp.exists(`${wardenKeySetDirectory}/wardenKeySetCollection.json`);
  const guardFileSearch = await fsp.exists(`${guardKeySetDirectory}/guardKeySetCollection.json`);

  if (wardenFileSearch && guardFileSearch) {
    const wardenKeySetCollection = await fsp.readJson(`${wardenKeySetDirectory}/wardenKeySetCollection.json`);
    const guardKeySetCollection = await fsp.readJson(`${guardKeySetDirectory}/guardKeySetCollection.json`);
    // Confirm the expired keys are not in the collection
    const searchForExpiredWardenKeySet: WardenKeySet | undefined =
      wardenKeySetCollection.find((wardenKeySet: WardenKeySet) => {
        return wardenKeySet.symmetric === keySet.wardenKeySet.symmetric;
      });
    t.is(searchForExpiredWardenKeySet, undefined);
    const searchForExpiredGuardKeySet: GuardKeySet | undefined =
      guardKeySetCollection.find((guardKeySet: GuardKeySet) => {
        return guardKeySet.symmetric === keySet.guardKeySet.symmetric;
      });
    t.is(searchForExpiredGuardKeySet, undefined);
  } else {
    t.fail();
  }
});

test('forge can cretae keySetCollections on disk', async (t: any) => {
  const randomString = await getRandom();
  const wardenKeySetDirectory: string = `./tmp/${randomString}/warden`;
  const guardKeySetDirectory: string = `./tmp/${randomString}/guard`;
  const forge: Forge = new Forge({
    wardenKeySetDirectory,
    guardKeySetDirectory,
    maxKeySetsValid: 3,
    maxKeySetValidDays: 5,
  });

  // Clear the tmp folder
  await fsp.remove(`./tmp/${randomString}`);

  // init the keys
  await forge.rotateKeys();

  const wardenFileSearch = await fsp.exists(`${wardenKeySetDirectory}/wardenKeySetCollection.json`);
  const guardFileSearch = await fsp.exists(`${guardKeySetDirectory}/guardKeySetCollection.json`);

  if (wardenFileSearch && guardFileSearch) {
    const wardenKeySetCollection = await fsp.readJson(`${wardenKeySetDirectory}/wardenKeySetCollection.json`);
    const guardKeySetCollection = await fsp.readJson(`${guardKeySetDirectory}/guardKeySetCollection.json`);

    let matchingKeys: number = 0;

    wardenKeySetCollection.forEach((wardenKeySet: WardenKeySet) => {
      // Find the matching guardKeySet
      guardKeySetCollection.forEach((guardKeySet: GuardKeySet) => {
        // Match the wardenKeySet with the guardKeySet based on the symmetric key matching
        if (wardenKeySet.symmetric === guardKeySet.symmetric) {
          // Log the match
          matchingKeys = matchingKeys + 1;
          // Now double check all the paired fields do actually match
          t.is(wardenKeySet.publicKey, guardKeySet.publicKey);
          t.is(wardenKeySet.symmetric, guardKeySet.symmetric);
          t.is(wardenKeySet.hmac, guardKeySet.hmac);
          t.is(wardenKeySet.expires, guardKeySet.expires);
        }
      });
    });
    // The number of matching keys should match the length of the keys generated
    t.true(matchingKeys === wardenKeySetCollection.length);
    t.true(matchingKeys === guardKeySetCollection.length);
  }
});


test('forge can cretae and rotate keySetCollections on disk', async (t: any) => {
  const randomString = await getRandom();
  const wardenKeySetDirectory: string = `./tmp/${randomString}/warden`;
  const guardKeySetDirectory: string = `./tmp/${randomString}/guard`;
  const forge: Forge = new Forge({
    wardenKeySetDirectory,
    guardKeySetDirectory,
    maxKeySetsValid: 3,
    maxKeySetValidDays: 5,
  });

  // Clear the tmp folder
  await fsp.remove(`./tmp/${randomString}`);

  const firstAttempt: any = await new Promise(async (resolve: Function) => {
    // init the keys
    await forge.rotateKeys();

    const wardenFileSearch = await fsp.exists(`${wardenKeySetDirectory}/wardenKeySetCollection.json`);
    const guardFileSearch = await fsp.exists(`${guardKeySetDirectory}/guardKeySetCollection.json`);

    if (wardenFileSearch && guardFileSearch) {
      const wardenKeySetCollection = await fsp.readJson(`${wardenKeySetDirectory}/wardenKeySetCollection.json`);
      const guardKeySetCollection = await fsp.readJson(`${guardKeySetDirectory}/guardKeySetCollection.json`);

      let matchingKeys: number = 0;

      wardenKeySetCollection.forEach((wardenKeySet: WardenKeySet) => {
        // Find the matching guardKeySet
        guardKeySetCollection.forEach((guardKeySet: GuardKeySet) => {
          // Match the wardenKeySet with the guardKeySet based on the symmetric key matching
          if (wardenKeySet.symmetric === guardKeySet.symmetric) {
            // Log the match
            matchingKeys = matchingKeys + 1;
            // Now double check all the paired fields do actually match
            t.is(wardenKeySet.publicKey, guardKeySet.publicKey);
            t.is(wardenKeySet.symmetric, guardKeySet.symmetric);
            t.is(wardenKeySet.hmac, guardKeySet.hmac);
            t.is(wardenKeySet.expires, guardKeySet.expires);
          }
        });
      });
      // The number of matching keys should match the length of the keys generated
      t.true(matchingKeys === wardenKeySetCollection.length);
      t.true(matchingKeys === guardKeySetCollection.length);
    }
    resolve(true);
  });
  t.true(firstAttempt);
  if (firstAttempt) {
    // --- Now rotate the keys
    const secondAttempt: any = await new Promise(async (resolve: Function) => {

      // init the keys
      await forge.rotateKeys();

      const wardenFileSearch = await fsp.exists(`${wardenKeySetDirectory}/wardenKeySetCollection.json`);
      const guardFileSearch = await fsp.exists(`${guardKeySetDirectory}/guardKeySetCollection.json`);

      if (wardenFileSearch && guardFileSearch) {
        const wardenKeySetCollection = await fsp.readJson(`${wardenKeySetDirectory}/wardenKeySetCollection.json`);
        const guardKeySetCollection = await fsp.readJson(`${guardKeySetDirectory}/guardKeySetCollection.json`);

        let matchingKeys: number = 0;

        wardenKeySetCollection.forEach((wardenKeySet: WardenKeySet) => {
          // Find the matching guardKeySet
          guardKeySetCollection.forEach((guardKeySet: GuardKeySet) => {
            // Match the wardenKeySet with the guardKeySet based on the symmetric key matching
            if (wardenKeySet.symmetric === guardKeySet.symmetric) {
              // Log the match
              matchingKeys = matchingKeys + 1;
              // Now double check all the paired fields do actually match
              t.is(wardenKeySet.publicKey, guardKeySet.publicKey);
              t.is(wardenKeySet.symmetric, guardKeySet.symmetric);
              t.is(wardenKeySet.hmac, guardKeySet.hmac);
              t.is(wardenKeySet.expires, guardKeySet.expires);
            }
          });
        });
        // The number of matching keys should match the length of the keys generated
        t.true(matchingKeys === wardenKeySetCollection.length);
        t.true(matchingKeys === guardKeySetCollection.length);
      }
      resolve(true);
    });

    t.true(secondAttempt);
  }
});
