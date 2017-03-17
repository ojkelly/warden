import * as crypto from 'crypto';

import {
  CardClassification,
} from './index';

export class Warden {

  private keys: WardenKeySet[];

  constructor(keys: WardenKeySet[]) {
    if (Array.isArray(keys) === false) {
      throw new TypeError('key is not an array');
    }

    // Check the keys are of the correct type
    keys.forEach((key: WardenKeySet) => {
      if (typeof key.privateKey !== 'string') {
        throw new TypeError('A private key is not a string');
      }
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
    // TODO parse the keys so the newest is first, and any expired keys are discarded
    this.keys = keys;
  }

  /**
   * Return the newest key
   */
  private getKeyPair(): WardenKeySet {
    return this.keys.reduce((prev, current) => {
      return (prev.expires > current.expires) ? prev : current;
    });
  }
  private getRandom(length = 24): Promise<string> {
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

  public async createCard(options: CreateCardOptions): Promise<string> {
    // TODO: typecheck the options

    // Assemble the card
    const card: DehydratedCard = {
      u: options.uuid,
      c: options.classification,
      r: options.roles,
      i: options.issued || Date.now(),
    };

    // Add the tenant if there is one
    if (options.tenant) {
      card.t = options.tenant;
    }

    return await this.secureCard(card);
  }

  private async secureCard(card: DehydratedCard): Promise<string> {
    const keySet: WardenKeySet = this.getKeyPair();
    const iv = await this.getRandom(16);
    const cardSignature = this.createCardSignature(card, keySet.privateKey);
    const {
      encrypted,
      auth,
    }: {
        encrypted: string,
        auth: string,
      } = this.createCardCipher(card, cardSignature, keySet.symmetric, iv);
    const payload: string = `${encrypted}.${auth}.${iv}`;
    const hmac: string = this.createCardHMAC(payload, keySet.hmac);

    return new Buffer(`${payload}.${hmac}`, 'utf8').toString('base64');
  }

  // Create the card signature
  // This allows the Guard to verify the contents of
  // card came from a Warden
  private createCardSignature(card, privateKey) {
    const signature = crypto.createSign('RSA-SHA256');
    signature.update(JSON.stringify(card));
    return signature.sign(privateKey).toString('hex');
  }

  // Encrypt the card and it's signature
  private createCardCipher(card: DehydratedCard, cardSignature: string, symmetric: string, iv: string): {
    encrypted: string,
    auth: string,
  } {
    const cipher = crypto.createCipheriv(
      'aes-256-gcm',
      new Buffer(symmetric, 'hex'),
      new Buffer(iv, 'hex'),
    );
    let encrypted: string = cipher.update(
      JSON.stringify({
        c: card,
        s: cardSignature,
      }),
      'utf8',
      'hex',
    );
    encrypted += cipher.final('hex');
    const auth: string = cipher.getAuthTag().toString('hex');
    return {
      encrypted,
      auth,
    };
  }

  // now create a HMAC of the crypted card
  private createCardHMAC(encrypted, hmacKey) {
    return crypto.createHmac(
      'sha256',
      hmacKey,
    )
      .update(encrypted)
      .digest('hex');
  }

}

export interface CreateCardOptions {
  // A unique identifier for the card holder
  uuid: string;
  // Optionally the tenant of which the card holder is part of
  tenant?: string;

  // This card's classification
  classification: CardClassification;

  // Roles assigned to the user, typically used for permissions
  roles: string[];

  // The time when this card was created
  // This should be used for testing the library, or if you need to correct
  // for clock skew
  issued?: number;
};

export interface WardenKeySet {
  publicKey: string;
  privateKey: string;
  symmetric: string;
  hmac: string;
  // Keys are tried in order of newest to oldest
  expires: number;
}


export interface DehydratedCard {
  // uuid: A unique identifier for the card holder
  u: string;

  // tenant: Optionally the tenant of which the card holder is part of
  t?: string;

  // classification: This card's classification
  c: CardClassification;

  // roles: Roles assigned to the user, typically used for permissions
  r: string[];

  // issued: The time when this card was created
  i: number;
}
