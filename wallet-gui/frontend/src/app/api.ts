export interface TxView {
  txid: string;
  from: string;
  to: string;
  amount: number;
  timestamp: number;
  block_index: number;
  confirmations: number;
  direction: "sent" | "received";
  signature: string;
}

export interface AppStateResponse {
  has_wallet_files: boolean;
  wallet_unlocked: boolean;
  wallet_address: string | null;
  wallet_public_key: string | null;
  min_broadcast_peers: number;
  biometric_supported: boolean;
  biometric_enabled: boolean;
  biometric_label: string;
  biometric_error?: string | null;
  peers_known: number;
  peers_online: number;
  balance: number | null;
  transactions: TxView[];
}

export interface WalletOperationResult {
  address: string;
  public_key: string;
  mnemonic: string | null;
  derivation_path: string;
  biometric_warning?: string | null;
}

export interface SendTxResult {
  txid: string;
  signature: string;
  sent_to: string[];
  required_peers: number;
  sent_peers: number;
}

export interface PassphraseChangeResult {
  updated: boolean;
  biometric_warning?: string | null;
}

export interface PrivateKeyAccessResult {
  private_key_hex: string;
  dat_base64: string;
}

export interface WalletDeleteResult {
  deleted: boolean;
}

export interface SettingsUpdateResult {
  min_broadcast_peers: number;
}

interface ApiEnvelope<T> {
  ok: boolean;
  data?: T;
  error?: string;
}

const apiBase = window.__LOFSWAP_API_BASE__ ?? "/api";

function buildUrl(path: string): string {
  if (path.startsWith("/")) {
    return `${apiBase}${path}`;
  }
  return `${apiBase}/${path}`;
}

async function apiCall<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(buildUrl(path), {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });

  const body = (await response.json()) as ApiEnvelope<T>;
  if (!response.ok || !body.ok || body.data === undefined) {
    throw new Error(body.error ?? "Request failed");
  }

  return body.data;
}

export function getAppState(): Promise<AppStateResponse> {
  return apiCall<AppStateResponse>("/state", { method: "GET" });
}

export function refreshNetworkState(): Promise<AppStateResponse> {
  return apiCall<AppStateResponse>("/state/refresh", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function createWallet(payload: {
  passphrase: string;
  use_biometric: boolean;
  mnemonic_passphrase?: string;
}): Promise<WalletOperationResult> {
  return apiCall<WalletOperationResult>("/wallet/create", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function importPrivateKey(payload: {
  private_key_hex: string;
  passphrase: string;
  use_biometric: boolean;
}): Promise<WalletOperationResult> {
  return apiCall<WalletOperationResult>("/wallet/import-private-key", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function importDat(payload: {
  dat_base64: string;
  passphrase: string;
  use_biometric: boolean;
}): Promise<WalletOperationResult> {
  return apiCall<WalletOperationResult>("/wallet/import-dat", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function unlockWallet(payload: { passphrase: string }): Promise<WalletOperationResult> {
  return apiCall<WalletOperationResult>("/wallet/unlock", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function unlockWalletWithBiometric(): Promise<WalletOperationResult> {
  return apiCall<WalletOperationResult>("/wallet/unlock-biometric", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function lockWallet(): Promise<{ locked: boolean }> {
  return apiCall<{ locked: boolean }>("/wallet/lock", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function changeWalletPassphrase(payload: {
  current_passphrase: string;
  new_passphrase: string;
}): Promise<PassphraseChangeResult> {
  return apiCall<PassphraseChangeResult>("/wallet/change-passphrase", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function revealPrivateKey(payload: { passphrase: string }): Promise<PrivateKeyAccessResult> {
  return apiCall<PrivateKeyAccessResult>("/wallet/reveal-private-key", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function exportPrivateKey(payload: { passphrase: string }): Promise<PrivateKeyAccessResult> {
  return apiCall<PrivateKeyAccessResult>("/wallet/export-private-key", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function deleteWalletConfig(): Promise<WalletDeleteResult> {
  return apiCall<WalletDeleteResult>("/wallet/delete-config", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function updateMinBroadcastPeers(payload: {
  min_broadcast_peers: number;
}): Promise<SettingsUpdateResult> {
  return apiCall<SettingsUpdateResult>("/settings/update", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function sendTransaction(payload: {
  to: string;
  amount: number;
  min_peers?: number;
}): Promise<SendTxResult> {
  return apiCall<SendTxResult>("/tx/send", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
