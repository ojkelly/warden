import * as crypto from 'crypto';

import {
  Card,
  CardClassification,
  CardClassificationExpiryLengths,
} from './index';

import {
  DehydratedCard,
} from './Warden';

export class Guard {

  private keys: GuardKeySet[];

  constructor(keys: GuardKeySet[]) {
    if (Array.isArray(keys) === false) {
      throw new TypeError('key is not an array');
    }

    // Check the keys are of the correct type
    keys.forEach((key: GuardKeySet) => {
      if (typeof key.publicKey !== 'string') {
        throw new TypeError('A public key is not a string');
      }
      if (typeof key.symmetric !== 'string') {
        throw new TypeError('A symmetric key is not a string');
      }
      if (typeof key.hmac !== 'string') {
        throw new TypeError('A hmac key is not a string');
      }
      if (typeof key.expires !== 'number') {
        throw new TypeError('A key expires is not a number');
      }
    });


    this.keys = keys;
  }

  // Check the card is valid, and if it is return the card
  public checkCard(cardString: string): Card {

    const cardBuffer = new Buffer(cardString, 'base64').toString('utf8');

    const cardArray: string[] = cardBuffer.split('.');
    const encrypted: string = cardArray[0];
    const encryptedAuth: string = cardArray[1];
    const iv: string = cardArray[2];
    const hmac: string = cardArray[3];

    // Check the HMAC
    const keySet: GuardKeySet = this.checkHMAC(`${encrypted}.${encryptedAuth}.${iv}`, hmac);


    // Decypt the card
    const decrypted: any = this.decryptCard(encrypted, encryptedAuth, keySet.symmetric, iv);
    const checkSignature = this.checkSignature(
      decrypted.c,
      decrypted.s,
      keySet.publicKey,
    );
    if (checkSignature !== true) {
      throw Error('Card is not valid');
    }

    const card: Card = this.hyrdateCard(decrypted.c);
    // Check the cards signature is intact


    // Check the card as not expired
    const expiryTime: number = this.getClassificationExpiryTime(card.classification);
    if (expiryTime < card.issued) {
      throw new Error('Card has expired');
    }
    return card;
  }

  // Check the HMAC and if correct, return the keys used
  private checkHMAC(payload: string, HMAC: string): GuardKeySet {
    const keySet: GuardKeySet | undefined = this.keys.find(
      (keySet: GuardKeySet) => {
        const ourHMAC: string = crypto.createHmac(
          'sha256',
          keySet.hmac,
        )
          .update(payload)
          .digest('hex');

        if (
          crypto.timingSafeEqual(
            new Buffer(ourHMAC, 'hex'),
            new Buffer(HMAC, 'hex'),
          )
        ) {
          return true;
        }
        return false;
      });

    if (typeof keySet === undefined || keySet === undefined) {
      throw Error('Card is invalid');
    }
    return keySet;
  }

  private decryptCard(encrypted: string, auth: string, symmetric: string, iv: string): any {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      new Buffer(symmetric, 'hex'),
      new Buffer(iv, 'hex'),
    );
    decipher.setAuthTag(new Buffer(auth, 'hex'));
    let deciphered = '';
    deciphered += decipher.update(encrypted, 'hex', 'utf8');
    deciphered += decipher.final('utf8');
    return JSON.parse(deciphered);
  }

  private checkSignature(
    card: DehydratedCard,
    signature: string,
    publicKey: string,
  ): boolean {
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(JSON.stringify(card));
    return verify.verify(publicKey, new Buffer(signature, 'hex'));
  }

  private hyrdateCard(dehydratedCard: DehydratedCard): Card {

    // check all the required fields are here, or throw
    const card: Card = {
      uuid: dehydratedCard.u,
      classification: dehydratedCard.c,
      roles: dehydratedCard.r,
      issued: dehydratedCard.i,
    };
    if (dehydratedCard.t) {
      card.tenant = dehydratedCard.t;
    }
    return card;
  }

  private getClassificationExpiryTime(classification: CardClassification): number {
    const expires: Date = new Date();
    switch (classification) {
      case CardClassification.access:
        expires.setMinutes(expires.getMinutes() + CardClassificationExpiryLengths.access);
        return expires.getTime();

      case CardClassification.refresh:
        expires.setMinutes(expires.getMinutes() + CardClassificationExpiryLengths.refresh);
        return expires.getTime();

      case CardClassification.mfa:
        expires.setMinutes(expires.getMinutes() + CardClassificationExpiryLengths.mfa);
        return expires.getTime();

      default:
        throw new Error('Invalid card');
    }
  }
}

export interface GuardKeySet {
  publicKey: string;
  symmetric: string;
  hmac: string;
  // Keys are tried in order of newest to oldest
  expires: number;
}
