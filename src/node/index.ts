import { Forge } from './Forge';
import { Guard } from './Guard';
import { Warden } from './Warden';

interface Card {
  // A unique identifier for the card holder
  uuid: string;
  // Optionally the tenant of which the card holder is part of
  tenant?: string[];

  // Roles assigned to the user, typically used for permissions
  roles: string[];

  // The time when this card was created
  expires: number;
}

export {
  Warden,
  Guard,
  Forge,
  Card,
}
