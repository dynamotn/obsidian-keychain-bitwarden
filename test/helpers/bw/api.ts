// Frozen test-only copy of the wire types of src/bw/api.ts (M6 Task 8): what the fake server stores and serves.

export interface FieldDto {
  type: number;
  name: string | null;
  value: string | null;
  linkedId?: number | null;
}

export interface CipherDto {
  id: string;
  type: number;
  folderId: string | null;
  organizationId: string | null;
  name: string;
  notes: string | null;
  fields: FieldDto[] | null;
  login?: Record<string, unknown> | null;
  secureNote?: { type: number } | null;
  key?: string | null;
  passwordHistory?: PasswordHistoryDto[] | null;
  favorite?: boolean;
  reprompt?: number;
  revisionDate: string;
  /** Set by the server when the item is created and never changed; decides between duplicate ids. */
  creationDate?: string | null;
  deletedDate?: string | null;
  /** Organization items only: false when the user may not change the item. */
  edit?: boolean;
  /** Organization items only: false when the organization hides the password from this user. */
  viewPassword?: boolean;
  /** A JSON string; `{"format_version":..}` marks Bitwarden's blob-encrypted items, whose other fields are empty. */
  data?: string | null;
}

export interface PasswordHistoryDto {
  password: string;
  lastUsedDate: string;
}

export interface FolderDto {
  id: string;
  name: string;
}

export interface OrganizationDto {
  id: string;
  /** The organization key, RSA-encrypted to this account; absent until the membership is confirmed. */
  key?: string | null;
  enabled?: boolean;
  /** Plain text, chosen by the organization's owners. */
  name?: string | null;
}

export interface CipherRequest {
  type: number;
  folderId: string | null;
  /** Kept as is on edits; new items are always personal. */
  organizationId: string | null;
  name: string;
  notes: string | null;
  fields: FieldDto[];
  favorite: boolean;
  reprompt: number;
  key: string | null;
  login?: Record<string, unknown> | null;
  secureNote?: { type: number } | null;
  passwordHistory?: PasswordHistoryDto[] | null;
  lastKnownRevisionDate?: string;
  /** Account the item is encrypted for. Required by Vaultwarden 1.37+, optional on bitwarden.com. */
  encryptedFor?: string;
}
