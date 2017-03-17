import { Forge } from './Forge';
import { Guard } from './Guard';
import { Warden } from './Warden';

enum CardClassification {
  access = 1,
  refresh = 2,
  mfa = 3,
}

// All measured in minutes
const CardClassificationExpiryLengths: {
  access: number;
  refresh: number;
  mfa: number;
} = {
    access: 60,          // 1 hour
    refresh: 60 * 24,   // 24 hours
    mfa: 5,            // 5 minutes
  };

interface Card {
  // A unique identifier for the card holder
  uuid: string;
  // Optionally the tenant of which the card holder is part of
  tenant?: string;

  // This card's classification
  classification: CardClassification;

  // Roles assigned to the user, typically used for permissions
  roles: string[];

  // The time when this card was created
  issued: number;
}

export {
  Warden,
  Guard,
  Forge,
  Card,
  CardClassification,
  CardClassificationExpiryLengths,
}
