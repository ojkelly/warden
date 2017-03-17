import {
  Card,
  CardClassification,
  Forge,
  Guard,
  Warden,
} from './index';

import { test } from 'ava';

test('can encrypt and decrypt bearer token', async (t: any): Promise<void> => {
  const forge: Forge = new Forge();
  const keys: any = await forge.initKeySetCollections();
  const uuid: string = '523b519b-cb8b-4fd5-8a46-ff4bab206fad';
  const tenant: string = '48d2d67d-2452-4828-8ad4-cda87679fc91';
  const roles: string[] = [
    'engineer',
    'onCall',
  ];

  const warden: Warden = new Warden(keys.wardenKeySetCollection);
  const card: any = await warden.createCard({
    uuid,
    tenant,
    classification: CardClassification.access,
    roles,
  });

  const guard: Guard = new Guard(keys.guardKeySetCollection);

  try {
    const userCard: Card = await guard.checkCard(card);
    t.is(userCard.uuid, uuid);
    t.is(userCard.tenant, tenant);
    t.is(userCard.classification, CardClassification.access);
    t.deepEqual(userCard.roles, roles);
    t.pass();
  } catch (err) {
    console.warn(err);
    t.fail(err.message);
  }
});
