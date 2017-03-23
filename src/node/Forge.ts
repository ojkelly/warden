import * as Debug from 'debug';
import * as createKeys from 'rsa-json';
import * as crypto from 'crypto';
import * as fsp from 'fs-promise';

import { GuardKeySet } from './Guard';
import { WardenKeySet } from './Warden';

const debug: Function = Debug('bunjil');
export class Forge {
  public wardenKeySetDirectory: string;
  public guardKeySetDirectory: string;

  public maxKeySetsValid: number = 4;

  public maxKeySetValidDays: number = 8;

  constructor(options?: ForgeOptions) {
    if (typeof options === 'object') {
      if (typeof options.wardenKeySetDirectory === 'string') {
        this.wardenKeySetDirectory = options.wardenKeySetDirectory;
      }
      if (typeof options.guardKeySetDirectory === 'string') {
        this.guardKeySetDirectory = options.guardKeySetDirectory;
      }
      if (typeof options.maxKeySetValidDays === 'number') {
        this.maxKeySetValidDays = options.maxKeySetValidDays;
      }

      if (typeof options.maxKeySetsValid === 'number') {
        if (options.maxKeySetsValid < 10) {
          this.maxKeySetsValid = options.maxKeySetsValid;
        } else {
          throw new Error('More than 10 valid keySets is likely to be slow.');
        }
      }
    }
  }

  public async createNewKeySet(expiry?: number): Promise<ForgeKeySet> {
    const keyPair: RsaJSONKeys = createKeys.native();
    // Keys are valid for 3 weeks (21 days), and should be rotated after 2 (14 days)
    let expires: number;
    if (typeof expiry === 'number') {
      expires = expiry;
    } else {
      const expireDate: Date = new Date();
      expireDate.setTime(expireDate.getTime() + 21 * 86400000);
      expires = expireDate.getTime();
    }

    // Add a symmetric key to each key pair
    const symmetric: string = crypto.randomBytes(32).toString('hex'); // 256bit
    const hmac: string = crypto.randomBytes(32).toString('hex');     // 256bit
    debug('Created a new keySet');
    return {
      wardenKeySet: {
        publicKey: keyPair.public,
        privateKey: keyPair.private,
        symmetric,
        hmac,
        expires,
      },
      guardKeySet: {
        publicKey: keyPair.public,
        symmetric,
        hmac,
        expires,
      },
    };
  };

  /**
   * Use this function to create a complete collection of keys.
   * After this, you only need to rotate the generated keys.
   * However you may want to call this function again, if you need to
   * rotate all your keys.
   */
  public async initKeySetCollections(numberOfKeySets?: number): Promise<ForgeInitKeySet> {
    const keySetCreateCount: number = numberOfKeySets || this.maxKeySetsValid;

    const rawKeys: ForgeKeySet[] = await Promise.all(
      [...Array(keySetCreateCount)].map(
        async (_, i: number) => {
          // Set a custom expiry time, to mimick if all these keys have been rotated
          const dayMultiple: number = i + 1 * 7;
          const expires: any = new Date();
          expires.setTime(expires.getTime() + dayMultiple * 86400000);
          return await this.createNewKeySet(expires.getTime());
        },
      ));

    const wardenKeySetCollection: WardenKeySet[] = rawKeys.map(
      (keySet: ForgeKeySet) => {
        return keySet.wardenKeySet;
      });
    const guardKeySetCollection: GuardKeySet[] = rawKeys.map(
      (keySet: ForgeKeySet) => {
        return keySet.guardKeySet;
      });
    debug(`Created an init keyset with ${keySetCreateCount} keys.`);
    return {
      wardenKeySetCollection,
      guardKeySetCollection,
    };
  }

  /**
 * Load the keys, find the one that is expiring in less than 8 days, and rotate it out.
 */
  public async processKeySetCollections(wardenKeySetCollection: WardenKeySet[], guardKeySetCollection: GuardKeySet[]): Promise<void> {
    // TODO, remove expired keys
    // Find the keyId of the expiring key - if any
    const expiringKeys: string[] = [];

    wardenKeySetCollection.find((key: any) => {
      const expireTimeCheck = new Date();
      expireTimeCheck.setTime(expireTimeCheck.getTime() + 8 * 86400000);

      if (key.expires > expireTimeCheck.getTime()) {
        expiringKeys.push(key.symmetric);
        return true;
      }
      return false;
    });

    // Remove expiringKeySets
    const cleanedWardenKeySetCollection: WardenKeySet[] =
      wardenKeySetCollection.filter((keySet: WardenKeySet) => {
        // return true if this key is expiring
        return expiringKeys.find((symmetric: string) => {
          // return true if this key is expiring
          return keySet.symmetric === symmetric;
        });
      });
    const cleanedGuardKeySetCollection: GuardKeySet[] =
      guardKeySetCollection.filter((keySet: GuardKeySet) => {
        // return true if this key is expiring
        return expiringKeys.find((symmetric: string) => {
          // return true if this key is expiring
          return keySet.symmetric === symmetric;
        });
      });

    if (
      typeof expiringKeys === undefined
      || expiringKeys === undefined
      || expiringKeys.length === 0
    ) {
      debug('No keys to rotate');
    } else {
      debug(`Rotating ${expiringKeys.length} keys`);
    }

    const newKeySet: ForgeInitKeySet = await this.initKeySetCollections(1);

    // Add our new primary key
    cleanedWardenKeySetCollection.push(newKeySet.wardenKeySetCollection[0]);

    cleanedGuardKeySetCollection.push(newKeySet.guardKeySetCollection[0]);

    await fsp.outputJSON(`${this.wardenKeySetDirectory}/wardenKeySetCollection.json`, cleanedWardenKeySetCollection);
    await fsp.outputJSON(`${this.guardKeySetDirectory}/guardKeySetCollection.json`, cleanedGuardKeySetCollection);
  }

  public async rotateKeys(): Promise<void> {
    if (typeof this.wardenKeySetDirectory !== 'string') {
      throw new Error('wardenKeySetDirectory is not set');
    }
    if (typeof this.guardKeySetDirectory !== 'string') {
      throw new Error('guardKeySetDirectory is not set');
    }
    const wardenFileSearch = await fsp.exists(`${this.wardenKeySetDirectory}/wardenKeySetCollection.json`);
    const guardFileSearch = await fsp.exists(`${this.guardKeySetDirectory}/guardKeySetCollection.json`);

    if (wardenFileSearch && guardFileSearch) {
      const wardenFile = await fsp.readJson(`${this.wardenKeySetDirectory}/wardenKeySetCollection.json`);
      const guardFile = await fsp.readJson(`${this.guardKeySetDirectory}/guardKeySetCollection.json`);
      // rotate the keys
      await this.processKeySetCollections(wardenFile, guardFile);
    } else {
      // create them new.
      const {
        wardenKeySetCollection,
        guardKeySetCollection,
      } = await this.initKeySetCollections();
      await fsp.outputJSON(
        `${this.wardenKeySetDirectory}/wardenKeySetCollection.json`,
        wardenKeySetCollection,
      );
      await fsp.outputJSON(
        `${this.guardKeySetDirectory}/guardKeySetCollection.json`,
        guardKeySetCollection,
      );

    }
  }
}

export interface ForgeOptions {
  wardenKeySetDirectory?: string;
  guardKeySetDirectory?: string;

  // The maximum number of keySets to keep valid on key rotation and generation
  maxKeySetsValid?: number;

  // The maximum number of days a keySet can be valid for. After this day it will
  // be rotated out (removed).
  maxKeySetValidDays?: number;
}

interface RsaJSONKeys {
  // tslint:disable-next-line:no-reserved-keywords
  private: string;
  // tslint:disable-next-line:no-reserved-keywords
  public: string;
}

export interface ForgeKeySet {
  wardenKeySet: WardenKeySet;
  guardKeySet: GuardKeySet;
}

export interface ForgeInitKeySet {
  wardenKeySetCollection: WardenKeySet[];
  guardKeySetCollection: GuardKeySet[];
}
