import { Forge, ForgeInitKeySet, ForgeKeySet } from './Forge';

import { GuardKeySet } from './Guard';
import { WardenKeySet } from './Warden';
import { test } from 'ava';

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

test('forge can rotate keySetCollections', (t: any) => {
  t.pass();
});

test('forge can rotate keySetCollections on disk', (t: any) => {
  t.pass();
});
