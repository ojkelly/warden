import * as createKeys from 'rsa-json';
import * as crypto from 'crypto';
import * as fsp from 'fs-promise';

import { GuardKeySet } from './Guard';
import { WardenKeySet } from './Warden';

/**
 * 
 */
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
  public async initKeySetCollections(): Promise<ForgeInitKeySet> {
    // Generate new keySets equal to the maxValidKeySets
    const rawKeys: ForgeKeySet[] = await Promise.all(
      [...Array(this.maxKeySetsValid)].map(
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

    return {
      wardenKeySetCollection,
      guardKeySetCollection,
    };
  }

  /**
 * Load the keys, find the one that is expiring in less than 8 days, and rotate it out.
 */
  public async rotateKeys(wardenKeySetCollection: WardenKeySet[], guardKeySetCollection: GuardKeySet[]): Promise<void> {
    // TODO, remove expired keys
    // Find the keyId of the expiring key - if any
    let expiringKeySetIndex: number;

    const expiringKeySet = wardenKeySetCollection.find((key: any, i: number) => {
      const expireTimeCheck = new Date();
      expireTimeCheck.setTime(expireTimeCheck.getTime() + 8 * 86400000);

      if (key.expires > expireTimeCheck.getTime()) {
        // key needs to be rotate
        console.log('key needs to be rotate:', key.id);
        expiringKeySetIndex = i;
        return true;
      }
      return false;
    });

    // Remove expiringKeySet
    // if (typeof expiringKeySetIndex !== 'undefined') {
    //   wardenKeySetCollection.splice(expiringKeySetIndex);
    //   // const expiringWardenKeySetIndex: number;
    //   // guardKeySetCollection.forEach((key: any, i: number) => {
    //   //   if (key.id === expiringKeySet.id) {
    //   //     expiringWardenKeySetIndex = i;
    //   //   }
    //   // });
    //   if (typeof expiringWardenKeySetIndex !== 'undefined') {
    //     guardKeySetCollection.splice(expiringWardenKeySetIndex);
    //   }
    // }

    if (typeof expiringKeySet !== 'undefined') {
      if (wardenKeySetCollection.length >= 4) {
        console.log('You asked to rotate the keys, but theres 4 or more keys, so Im not doing it');
      }
    } else {
      console.log('You asked to rotate the keys, but there is no expiring key');
    }

    const newKeySet: any = await this.initKeySetCollections();
    const newWardenKeySet: any = {
      id: newKeySet.id,
      private: newKeySet.keys.private,
      public: newKeySet.keys.public,
      expires: newKeySet.expires,
      isPrimary: true,
    };

    const newGuardKeySet: any = {
      id: newKeySet.id,
      public: newKeySet.keys.public,
      expires: newKeySet.expires,
    };

    // Make all the old keys as not primary
    const updatedwardenKeySetCollection: any[] = wardenKeySetCollection.map((key: any) => {
      return Object.assign(
        {},
        key,
        {
          isPrimary: false,
        });
    });

    // Add our new primary key
    updatedwardenKeySetCollection.push(newWardenKeySet);

    const updatedguardKeySetCollection = guardKeySetCollection;
    updatedguardKeySetCollection.push(newGuardKeySet);

    await fsp.outputJSON(`${this.wardenKeySetDirectory}/wardenKeySetCollection.json`, updatedwardenKeySetCollection);
    await fsp.outputJSON(`${this.guardKeySetDirectory}/guardKeySetCollection.json`, updatedguardKeySetCollection);
  }

  public async checkIfJWTKeyFileExists() {
    if (typeof this.wardenKeySetDirectory !== 'string') {
      throw new Error('wardenKeySetDirectory is not set');
    }
    if (typeof this.guardKeySetDirectory !== 'string') {
      throw new Error('guardKeySetDirectory is not set');
    }
    const wardenFileSearch = await fsp.existsSync(`${this.wardenKeySetDirectory}/wardenKeySetCollection.json`);
    const guardFileSearch = await fsp.existsSync(`${this.guardKeySetDirectory}/guardKeySetCollection.json`);

    if (wardenFileSearch && guardFileSearch) {
      const wardenFile = await fsp.readJson(`${this.wardenKeySetDirectory}/wardenKeySetCollection.json`);
      const guardFile = await fsp.readJson(`${this.guardKeySetDirectory}/guardKeySetCollection.json`);

      // rotate the keys
      console.log('Check to rotate');
      await this.rotateKeys(wardenFile, guardFile);
    } else {
      // create them new.
      console.log('creating fresh keys');
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
