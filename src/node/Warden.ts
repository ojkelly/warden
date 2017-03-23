import * as crypto from 'crypto';

export class Warden {

  private keys: WardenKeySet[];

  // By default, how long an access token will be valid for
  private defaultCardHoursValid: number;

  constructor(keys: WardenKeySet[], defaultCardHoursValid?: number) {
    if (Array.isArray(keys) === false) {
      throw new TypeError('keys is not an array');
    }
    if (typeof defaultCardHoursValid === undefined) {
      // this libraries default is 1 hour. You can set it to whatever is appropriate for
      // your use case by passing a number to the constructor
      this.defaultCardHoursValid = 1;
    } else {
      if (typeof defaultCardHoursValid === 'number') {
        this.defaultCardHoursValid = defaultCardHoursValid;
      } else {
        throw new TypeError('defaultCardHoursValid passed to the Warden was not a number');
      }
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
    this.keys = keys;
  }

  /**
   * Return the newest key
   */
  private getKeyPair(): WardenKeySet {
    return this.keys.reduce((prev: WardenKeySet, current: WardenKeySet) => {
      return (prev.expires > current.expires) ? prev : current;
    });
  }
  private getRandom(length: number = 24): Promise<string> {
    return new Promise((resolve: Function, reject: Function) => {
      crypto.randomBytes(Math.ceil(length / 2), (err: any, buf: Buffer) => {
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
    let expires: number;

    if (options.hoursUntilExpiry === undefined) {
      // this libraries default is 1 hour. You can set it to whatever is appropriate for
      // your use case by passing a number to the constructor
      const now: Date = new Date();

      now.setHours(now.getHours() + this.defaultCardHoursValid);

      expires = now.getTime();
    } else {
      if (typeof options.hoursUntilExpiry === 'number') {
        expires = options.hoursUntilExpiry;
      } else {
        throw new TypeError('options.expires passed to createCard but was not a number');
      }
    }

    // Assemble the card
    const card: DehydratedCard = {
      u: options.uuid,
      r: options.roles,
      e: expires,
    };

    // Add the tenant if there is one
    if (options.tenant) {
      card.t = options.tenant;
    }

    return await this.secureCard(card);
  }

  private async secureCard(card: DehydratedCard): Promise<string> {
    const keySet: WardenKeySet = this.getKeyPair();
    const iv: string = await this.getRandom(16);
    const cardSignature: string = this.createCardSignature(card, keySet.privateKey);
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
  private createCardSignature(card: DehydratedCard, privateKey: string): string {
    const signature: any = crypto.createSign('RSA-SHA256');
    signature.update(JSON.stringify(card));
    return signature.sign(privateKey).toString('hex');
  }

  // Encrypt the card and it's signature
  private createCardCipher(card: DehydratedCard, cardSignature: string, symmetric: string, iv: string): {
    encrypted: string,
    auth: string,
  } {
    const cipher: any = crypto.createCipheriv(
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
  private createCardHMAC(encrypted: string, hmacKey: string): string {
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
  tenant?: string[];

  // Roles assigned to the user, typically used for permissions
  roles: string[];

  // When this card is no longer valid
  hoursUntilExpiry?: number;
}

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
  t?: string[];

  // classification: This card's classification

  // roles: Roles assigned to the user, typically used for permissions
  r: string[];

  // issued: The time when this card was created
  e: number;
}
