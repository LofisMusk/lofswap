import { useCallback, useEffect, useMemo, useState, type KeyboardEvent } from "react";
import {
  AlertTriangle,
  Copy,
  Download,
  Eye,
  EyeOff,
  Fingerprint,
  KeyRound,
  Lock,
  RefreshCw,
  Settings,
  Send,
  ShieldCheck,
  Trash2,
  Wallet,
  X,
} from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { toast, Toaster } from "sonner";

import {
  type AppStateResponse,
  changeWalletPassphrase,
  createWallet,
  deleteWalletConfig,
  exportPrivateKey,
  getAppState,
  importDat,
  importPrivateKey,
  lockWallet,
  revealPrivateKey,
  refreshNetworkState as refreshNetworkStateApi,
  sendTransaction,
  unlockWallet,
  unlockWalletWithBiometric,
  updateMinBroadcastPeers,
} from "./api";

type OnboardingTab = "import_private" | "import_dat" | "create";

function formatTimestamp(ts: number): string {
  if (!ts) {
    return "Unknown";
  }
  return new Date(ts * 1000).toLocaleString();
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const output = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    output[i] = binary.charCodeAt(i);
  }
  return output;
}

export default function App() {
  const [state, setState] = useState<AppStateResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [fatalError, setFatalError] = useState<string | null>(null);

  const refreshState = useCallback(async () => {
    try {
      const next = await getAppState();
      setState(next);
      setFatalError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load app state";
      setFatalError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshNetworkState = useCallback(async () => {
    setRefreshing(true);
    try {
      const next = await refreshNetworkStateApi();
      setState(next);
      setFatalError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to refresh network state";
      toast.error(message);
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void refreshState();
  }, [refreshState]);

  useEffect(() => {
    if (!state?.wallet_unlocked) {
      return undefined;
    }

    let timer: number | null = null;

    const tick = () => {
      if (document.visibilityState === "visible") {
        void refreshNetworkState();
      }
    };

    const startTimer = () => {
      if (timer === null) {
        timer = window.setInterval(tick, 10_000);
      }
    };

    const stopTimer = () => {
      if (timer !== null) {
        window.clearInterval(timer);
        timer = null;
      }
    };

    const handleVisibility = () => {
      if (document.visibilityState === "visible") {
        void refreshNetworkState();
        startTimer();
      } else {
        stopTimer();
      }
    };

    handleVisibility();
    document.addEventListener("visibilitychange", handleVisibility);

    return () => {
      stopTimer();
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [refreshNetworkState, state?.wallet_unlocked]);

  const content = useMemo(() => {
    if (loading && !state) {
      return (
        <div className="min-h-screen bg-black text-white flex items-center justify-center">
          <div className="text-zinc-400">Loading wallet...</div>
        </div>
      );
    }

    if (fatalError && !state) {
      return (
        <div className="min-h-screen bg-black text-white flex items-center justify-center px-6">
          <div className="max-w-xl w-full rounded-2xl border border-zinc-800 bg-zinc-950 p-8 space-y-4">
            <h1 className="text-xl font-semibold">Failed to load LofSwap Wallet</h1>
            <p className="text-zinc-400">{fatalError}</p>
            <button
              onClick={() => void refreshState()}
              className="px-4 py-2 rounded-lg bg-white text-black font-medium"
            >
              Retry
            </button>
          </div>
        </div>
      );
    }

    if (!state) {
      return null;
    }

    if (!state.has_wallet_files) {
      return <OnboardingView appState={state} onRefresh={refreshState} />;
    }

    if (!state.wallet_unlocked) {
      return <UnlockView appState={state} onRefresh={refreshState} />;
    }

    return (
      <WalletView
        appState={state}
        onRefreshLocal={refreshState}
        onRefreshNetwork={refreshNetworkState}
        refreshing={refreshing}
      />
    );
  }, [fatalError, loading, refreshNetworkState, refreshState, refreshing, state]);

  return (
    <>
      <Toaster theme="dark" position="top-right" />
      {content}
    </>
  );
}

function OnboardingView({
  appState,
  onRefresh,
}: {
  appState: AppStateResponse;
  onRefresh: () => Promise<void>;
}) {
  const [tab, setTab] = useState<OnboardingTab>("import_private");
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [useBiometric, setUseBiometric] = useState(false);
  const [privateKeyHex, setPrivateKeyHex] = useState("");
  const [datFile, setDatFile] = useState<File | null>(null);
  const [creating, setCreating] = useState(false);
  const [createdMnemonic, setCreatedMnemonic] = useState<string | null>(null);

  const biometricToggleAllowed = appState.biometric_supported;
  const biometricLabel = appState.biometric_label;

  const passwordsValid = passphrase.trim().length > 0 && passphrase === confirmPassphrase;

  function handlePasswordEnter(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key !== "Enter") {
      return;
    }
    event.preventDefault();
    if (creating) {
      return;
    }
    if (tab === "import_private") {
      void handleImportPrivateKey();
      return;
    }
    if (tab === "import_dat") {
      void handleImportDat();
      return;
    }
    void handleCreate();
  }

  async function handleCreate() {
    if (!passwordsValid) {
      toast.error("Set a wallet password and confirm it");
      return;
    }
    setCreating(true);
    try {
      const result = await createWallet({
        passphrase,
        use_biometric: useBiometric,
      });
      if (result.biometric_warning) {
        toast.warning(result.biometric_warning);
      }
      setCreatedMnemonic(result.mnemonic ?? null);
      toast.success("Wallet created and encrypted with Argon2");
      await onRefresh();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Wallet creation failed";
      toast.error(message);
    } finally {
      setCreating(false);
    }
  }

  async function handleImportPrivateKey() {
    if (!passwordsValid) {
      toast.error("Set a wallet password and confirm it");
      return;
    }
    if (!privateKeyHex.trim()) {
      toast.error("Private key is required");
      return;
    }
    setCreating(true);
    try {
      const result = await importPrivateKey({
        private_key_hex: privateKeyHex.trim(),
        passphrase,
        use_biometric: useBiometric,
      });
      if (result.biometric_warning) {
        toast.warning(result.biometric_warning);
      }
      toast.success("Private key imported and encrypted");
      await onRefresh();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Private key import failed";
      toast.error(message);
    } finally {
      setCreating(false);
    }
  }

  async function handleImportDat() {
    if (!passwordsValid) {
      toast.error("Set a wallet password and confirm it");
      return;
    }
    if (!datFile) {
      toast.error(".dat file is required");
      return;
    }
    setCreating(true);
    try {
      const bytes = new Uint8Array(await datFile.arrayBuffer());
      const datBase64 = toBase64(bytes);
      const result = await importDat({
        dat_base64: datBase64,
        passphrase,
        use_biometric: useBiometric,
      });
      if (result.biometric_warning) {
        toast.warning(result.biometric_warning);
      }
      toast.success(".dat wallet imported and encrypted");
      await onRefresh();
    } catch (err) {
      const message = err instanceof Error ? err.message : ".dat import failed";
      toast.error(message);
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="h-full min-h-full overflow-y-auto bg-black text-white p-6 md:p-10 overscroll-none">
      <div className="max-w-5xl mx-auto">
        <header className="mb-8">
          <div className="inline-flex items-center gap-3 px-4 py-2 rounded-full border border-zinc-800 bg-zinc-950">
            <Wallet className="w-5 h-5 text-blue-400" />
            <span className="text-sm uppercase tracking-[0.2em] text-zinc-400">LofSwap Wallet</span>
          </div>
          <h1 className="text-3xl md:text-4xl font-semibold mt-5">Wallet onboarding</h1>
          <p className="text-zinc-400 mt-2">
            No wallet files were found. Import an existing wallet or create a new encrypted wallet.
          </p>
        </header>

        <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6 md:p-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-7">
            <TabButton
              active={tab === "import_private"}
              onClick={() => setTab("import_private")}
              label="Import Private Key"
            />
            <TabButton
              active={tab === "import_dat"}
              onClick={() => setTab("import_dat")}
              label="Import .dat File"
            />
            <TabButton
              active={tab === "create"}
              onClick={() => setTab("create")}
              label="Create New Wallet"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div>
              <label className="block text-sm text-zinc-400 mb-2">Wallet password</label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                onKeyDown={handlePasswordEnter}
                className="w-full h-11 rounded-lg border border-zinc-700 bg-zinc-900 px-3 outline-none focus:border-blue-500"
                placeholder="Enter password"
              />
            </div>
            <div>
              <label className="block text-sm text-zinc-400 mb-2">Confirm password</label>
              <input
                type="password"
                value={confirmPassphrase}
                onChange={(e) => setConfirmPassphrase(e.target.value)}
                onKeyDown={handlePasswordEnter}
                className="w-full h-11 rounded-lg border border-zinc-700 bg-zinc-900 px-3 outline-none focus:border-blue-500"
                placeholder="Confirm password"
              />
            </div>
          </div>

          {biometricToggleAllowed && (
            <label className="flex items-center gap-3 mb-8 text-sm text-zinc-300">
              <input
                type="checkbox"
                checked={useBiometric}
                onChange={(e) => setUseBiometric(e.target.checked)}
                className="accent-blue-500"
              />
              Enable {biometricLabel} unlock for this wallet
            </label>
          )}

          {tab === "import_private" && (
            <div className="space-y-4">
              <label className="block text-sm text-zinc-400">Private key hex</label>
              <textarea
                value={privateKeyHex}
                onChange={(e) => setPrivateKeyHex(e.target.value)}
                className="w-full min-h-[120px] rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-3 outline-none focus:border-blue-500 font-mono text-sm"
                placeholder="Paste 64-char private key hex"
              />
              <button
                onClick={() => void handleImportPrivateKey()}
                disabled={creating}
                className="h-11 px-5 rounded-lg bg-white text-black font-medium disabled:opacity-50"
              >
                {creating ? "Importing..." : "Import Private Key"}
              </button>
            </div>
          )}

          {tab === "import_dat" && (
            <div className="space-y-4">
              <label className="block text-sm text-zinc-400">Wallet .dat file (32-byte key)</label>
              <input
                type="file"
                accept=".dat,application/octet-stream"
                onChange={(e) => setDatFile(e.target.files?.[0] ?? null)}
                className="block w-full text-sm text-zinc-300"
              />
              <button
                onClick={() => void handleImportDat()}
                disabled={creating}
                className="h-11 px-5 rounded-lg bg-white text-black font-medium disabled:opacity-50"
              >
                {creating ? "Importing..." : "Import .dat Wallet"}
              </button>
            </div>
          )}

          {tab === "create" && (
            <div className="space-y-4">
              <p className="text-zinc-400 text-sm">
                A 12-word mnemonic will be generated and converted with the same derivation path used by
                `wallet-cli`, then encrypted with Argon2id.
              </p>
              <button
                onClick={() => void handleCreate()}
                disabled={creating}
                className="h-11 px-5 rounded-lg bg-white text-black font-medium disabled:opacity-50"
              >
                {creating ? "Creating..." : "Create New Wallet"}
              </button>
              {createdMnemonic && (
                <div className="rounded-xl border border-emerald-800 bg-emerald-900/20 p-4">
                  <p className="text-xs uppercase tracking-[0.2em] text-emerald-400 mb-2">Recovery phrase</p>
                  <p className="font-mono text-sm leading-6 break-words">{createdMnemonic}</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function UnlockView({
  appState,
  onRefresh,
}: {
  appState: AppStateResponse;
  onRefresh: () => Promise<void>;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [unlocking, setUnlocking] = useState(false);

  async function handleUnlock() {
    if (!passphrase.trim()) {
      toast.error("Password is required");
      return;
    }
    setUnlocking(true);
    try {
      const result = await unlockWallet({ passphrase });
      if (result.biometric_warning) {
        toast.warning(result.biometric_warning);
      }
      toast.success("Wallet unlocked");
      await onRefresh();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unlock failed";
      toast.error(message);
    } finally {
      setUnlocking(false);
    }
  }

  async function handleBiometricUnlock() {
    setUnlocking(true);
    try {
      await unlockWalletWithBiometric();
      toast.success("Wallet unlocked");
      await onRefresh();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Biometric unlock failed";
      toast.error(message);
    } finally {
      setUnlocking(false);
    }
  }

  return (
    <div className="h-full min-h-full overflow-y-auto bg-black text-white flex items-center justify-center px-6 overscroll-none">
      <div className="w-full max-w-xl rounded-2xl border border-zinc-800 bg-zinc-950 p-8 space-y-6">
        <div className="flex items-center gap-3">
          <Lock className="w-6 h-6 text-blue-400" />
          <h1 className="text-2xl font-semibold">Unlock wallet</h1>
        </div>

        <p className="text-zinc-400">
          Wallet files were found. Enter your password to decrypt and load the wallet.
        </p>
        {appState.biometric_error && (
          <p className="rounded-lg border border-amber-700/40 bg-amber-900/20 px-3 py-2 text-amber-200 text-sm">
            {appState.biometric_error}
          </p>
        )}

        <div className="space-y-2">
          <label className="text-sm text-zinc-400">Wallet password</label>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            onKeyDown={(event) => {
              if (event.key !== "Enter") {
                return;
              }
              event.preventDefault();
              if (!unlocking) {
                void handleUnlock();
              }
            }}
            className="w-full h-11 rounded-lg border border-zinc-700 bg-zinc-900 px-3 outline-none focus:border-blue-500"
            placeholder="Enter password"
          />
        </div>

        <div className="flex flex-col md:flex-row gap-3">
          <button
            onClick={() => void handleUnlock()}
            disabled={unlocking}
            className="h-11 px-5 rounded-lg bg-white text-black font-medium disabled:opacity-50"
          >
            {unlocking ? "Unlocking..." : "Unlock with Password"}
          </button>

          {appState.biometric_supported && appState.biometric_enabled && (
            <button
              onClick={() => void handleBiometricUnlock()}
              disabled={unlocking}
              className="h-11 px-5 rounded-lg border border-zinc-700 bg-zinc-900 text-white font-medium disabled:opacity-50 inline-flex items-center gap-2"
            >
              <Fingerprint className="w-4 h-4" />
              Unlock with {appState.biometric_label}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function WalletView({
  appState,
  onRefreshLocal,
  onRefreshNetwork,
  refreshing,
}: {
  appState: AppStateResponse;
  onRefreshLocal: () => Promise<void>;
  onRefreshNetwork: () => Promise<void>;
  refreshing: boolean;
}) {
  const [toAddress, setToAddress] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [sending, setSending] = useState(false);
  const [locking, setLocking] = useState(false);
  const [minPeersInput, setMinPeersInput] = useState(() =>
    String(appState.min_broadcast_peers || 2),
  );
  const [savingMinPeers, setSavingMinPeers] = useState(false);
  const [currentPassphrase, setCurrentPassphrase] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [confirmNewPassphrase, setConfirmNewPassphrase] = useState("");
  const [changingPassphrase, setChangingPassphrase] = useState(false);
  const [revealPassphrase, setRevealPassphrase] = useState("");
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [revealingPrivateKey, setRevealingPrivateKey] = useState(false);
  const [exportingPrivateKey, setExportingPrivateKey] = useState(false);
  const [revealedPrivateKeyHex, setRevealedPrivateKeyHex] = useState<string | null>(null);
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [deletingWalletConfig, setDeletingWalletConfig] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const receiveAddress = appState.wallet_address ?? "";
  const parsedMinPeers = Number.parseInt(minPeersInput, 10);
  const minPeersValid = Number.isFinite(parsedMinPeers) && parsedMinPeers >= 1;

  useEffect(() => {
    setMinPeersInput(String(appState.min_broadcast_peers || 2));
  }, [appState.min_broadcast_peers]);

  useEffect(() => {
    if (!settingsOpen) {
      return undefined;
    }
    const handleGlobalKeydown = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setSettingsOpen(false);
      }
    };
    window.addEventListener("keydown", handleGlobalKeydown);
    return () => {
      window.removeEventListener("keydown", handleGlobalKeydown);
    };
  }, [settingsOpen]);

  async function handleCopyAddress() {
    if (!receiveAddress) {
      return;
    }
    try {
      await navigator.clipboard.writeText(receiveAddress);
      toast.success("Address copied");
    } catch {
      toast.error("Failed to copy address");
    }
  }

  async function handleCopyValue(value: string, label: string) {
    if (!value) {
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      toast.success(`${label} copied`);
    } catch {
      toast.error(`Failed to copy ${label.toLowerCase()}`);
    }
  }

  async function handleSend() {
    const to = toAddress.trim();
    const amount = Number.parseInt(sendAmount, 10);
    if (!to) {
      toast.error("Destination address is required");
      return;
    }
    if (!Number.isFinite(amount) || amount <= 0) {
      toast.error("Amount must be a positive integer");
      return;
    }

    setSending(true);
    try {
      if (appState.min_broadcast_peers === 1) {
        toast.warning(
          "Min peers is set to 1. Transaction may not execute correctly across the whole network.",
        );
      }
      const result = await sendTransaction({
        to,
        amount,
        min_peers: appState.min_broadcast_peers,
      });
      toast.success(`Transaction sent to ${result.sent_peers}/${result.required_peers} peers`);
      setToAddress("");
      setSendAmount("");
      await onRefreshNetwork();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Send failed";
      toast.error(message);
    } finally {
      setSending(false);
    }
  }

  async function handleSaveMinPeers() {
    if (!minPeersValid) {
      toast.error("Minimum peers must be at least 1");
      return;
    }
    setSavingMinPeers(true);
    try {
      const result = await updateMinBroadcastPeers({
        min_broadcast_peers: parsedMinPeers,
      });
      setMinPeersInput(String(result.min_broadcast_peers));
      if (result.min_broadcast_peers === 1) {
        toast.warning("With min peers = 1, transaction propagation may be incomplete");
      } else {
        toast.success("Minimum peers setting saved");
      }
      await onRefreshLocal();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to save settings";
      toast.error(message);
    } finally {
      setSavingMinPeers(false);
    }
  }

  async function handleChangePassphrase() {
    if (!currentPassphrase.trim()) {
      toast.error("Current wallet password is required");
      return;
    }
    if (!newPassphrase.trim()) {
      toast.error("New wallet password is required");
      return;
    }
    if (newPassphrase !== confirmNewPassphrase) {
      toast.error("New password confirmation does not match");
      return;
    }

    setChangingPassphrase(true);
    try {
      const result = await changeWalletPassphrase({
        current_passphrase: currentPassphrase,
        new_passphrase: newPassphrase,
      });
      if (result.biometric_warning) {
        toast.warning(result.biometric_warning);
      }
      toast.success("Wallet password updated");
      setCurrentPassphrase("");
      setNewPassphrase("");
      setConfirmNewPassphrase("");
      await onRefreshLocal();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Password change failed";
      toast.error(message);
    } finally {
      setChangingPassphrase(false);
    }
  }

  async function handleRevealPrivateKey() {
    if (!revealPassphrase.trim()) {
      toast.error("Wallet password is required");
      return;
    }
    setRevealingPrivateKey(true);
    try {
      const result = await revealPrivateKey({ passphrase: revealPassphrase });
      setRevealedPrivateKeyHex(result.private_key_hex);
      setShowPrivateKey(true);
      toast.success("Private key revealed");
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to reveal private key";
      toast.error(message);
    } finally {
      setRevealingPrivateKey(false);
    }
  }

  async function handleExportPrivateKey() {
    if (!exportPassphrase.trim()) {
      toast.error("Wallet password is required");
      return;
    }
    setExportingPrivateKey(true);
    try {
      const result = await exportPrivateKey({ passphrase: exportPassphrase });
      const bytes = fromBase64(result.dat_base64);
      const blob = new Blob([bytes], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "lofswap-wallet-private-key.dat";
      anchor.click();
      URL.revokeObjectURL(url);
      toast.success("Private key exported (.dat)");
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to export private key";
      toast.error(message);
    } finally {
      setExportingPrivateKey(false);
    }
  }

  async function handleDeleteWalletConfig() {
    const confirmed = window.confirm(
      "Delete current wallet files and reset to onboarding? This cannot be undone.",
    );
    if (!confirmed) {
      return;
    }

    setDeletingWalletConfig(true);
    try {
      await deleteWalletConfig();
      toast.success("Wallet configuration removed");
      await onRefreshLocal();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to delete wallet configuration";
      toast.error(message);
    } finally {
      setDeletingWalletConfig(false);
    }
  }

  async function handleLock() {
    setLocking(true);
    try {
      await lockWallet();
      await onRefreshLocal();
      toast.success("Wallet locked");
    } catch (err) {
      const message = err instanceof Error ? err.message : "Lock failed";
      toast.error(message);
    } finally {
      setLocking(false);
    }
  }

  return (
    <div className="h-full min-h-full bg-black text-white flex flex-col overflow-hidden">
      <header className="border-b border-zinc-800 bg-zinc-950/60 backdrop-blur px-6 md:px-10 py-5">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <Wallet className="w-6 h-6 text-blue-400" />
              <h1 className="text-2xl font-semibold">LofSwap Wallet</h1>
            </div>
            <p className="text-zinc-400 text-sm mt-1">
              Address: {appState.wallet_address ?? "N/A"}
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="px-3 py-2 rounded-lg border border-zinc-800 bg-zinc-900 text-sm text-zinc-300">
              Peers online: {appState.peers_online}/{appState.peers_known}
            </div>
            <button
              onClick={() => void onRefreshNetwork()}
              className="h-10 px-3 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 inline-flex items-center gap-2"
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`} />
              Refresh
            </button>
            <button
              onClick={() => setSettingsOpen(true)}
              className="h-10 w-10 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 inline-flex items-center justify-center"
              title="Settings"
              aria-label="Open settings"
            >
              <Settings className="w-4 h-4" />
            </button>
            <button
              onClick={() => void handleLock()}
              disabled={locking}
              className="h-10 px-3 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 inline-flex items-center gap-2 disabled:opacity-50"
            >
              <ShieldCheck className="w-4 h-4" />
              {locking ? "Locking..." : "Lock"}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl w-full mx-auto flex-1 min-h-0 p-6 md:p-10 grid grid-cols-1 lg:grid-cols-3 gap-6 overflow-y-auto lg:overflow-hidden overscroll-none">
        <section className="lg:col-span-1 space-y-6 lg:overflow-y-auto lg:pr-1">
          <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
            <p className="text-sm text-zinc-500 uppercase tracking-[0.2em]">Balance</p>
            <h2 className="text-4xl font-light mt-3">{appState.balance ?? 0} LFS</h2>
            <p className="text-zinc-500 mt-2">Live value fetched from running peers</p>
          </div>

          <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6 space-y-4">
            <h3 className="text-lg font-medium inline-flex items-center gap-2">
              <Send className="w-4 h-4" />
              Send LFS
            </h3>

            <div className="space-y-2">
              <label className="text-sm text-zinc-400">Destination address</label>
              <input
                value={toAddress}
                onChange={(e) => setToAddress(e.target.value)}
                className="w-full h-11 rounded-lg border border-zinc-700 bg-zinc-900 px-3 outline-none focus:border-blue-500"
                placeholder="LFS..."
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm text-zinc-400">Amount (integer LFS)</label>
              <input
                value={sendAmount}
                onChange={(e) => setSendAmount(e.target.value)}
                className="w-full h-11 rounded-lg border border-zinc-700 bg-zinc-900 px-3 outline-none focus:border-blue-500"
                placeholder="10"
              />
            </div>

            <button
              onClick={() => void handleSend()}
              disabled={sending}
              className="h-11 px-5 rounded-lg bg-white text-black font-medium disabled:opacity-50"
            >
              {sending ? "Sending..." : "Send Transaction"}
            </button>
            <p className="text-xs text-zinc-500">
              Current minimum broadcast peers: {appState.min_broadcast_peers}
            </p>
          </div>

          <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6 space-y-3">
            <h3 className="text-lg font-medium inline-flex items-center gap-2">
              <KeyRound className="w-4 h-4" />
              Receive
            </h3>
            <div className="rounded-xl bg-white p-3 w-fit">
              {receiveAddress ? (
                <QRCodeSVG
                  value={receiveAddress}
                  size={180}
                  bgColor="#ffffff"
                  fgColor="#0a0a0a"
                  level="M"
                  includeMargin
                />
              ) : (
                <div className="w-[180px] h-[180px] text-xs text-zinc-600 flex items-center justify-center">
                  Address unavailable
                </div>
              )}
            </div>
            <p className="text-zinc-400 text-sm break-all">{receiveAddress || "Address unavailable"}</p>
            <button
              onClick={() => void handleCopyAddress()}
              disabled={!receiveAddress}
              className="h-10 px-4 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 inline-flex items-center gap-2"
            >
              <Copy className="w-4 h-4" />
              Copy Address
            </button>
          </div>
        </section>

        <section className="lg:col-span-2 lg:min-h-0 lg:flex lg:flex-col">
          <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6 flex flex-col lg:flex-1 lg:min-h-0">
            <h3 className="text-lg font-medium mb-5">Recent Transactions</h3>

            {appState.transactions.length === 0 ? (
              <div className="flex-1 min-h-0 rounded-xl border border-zinc-800 bg-zinc-900/30 p-4 text-zinc-400">
                No on-chain transactions found for this wallet yet.
              </div>
            ) : (
              <div className="space-y-3 flex-1 min-h-0 overflow-y-auto pr-1">
                {appState.transactions.map((tx) => (
                  <div
                    key={`${tx.txid}-${tx.signature}`}
                    className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-4"
                  >
                    <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2">
                      <div>
                        <p className="font-medium">
                          <span
                            className={tx.direction === "received" ? "text-emerald-400" : "text-red-400"}
                          >
                            {tx.direction === "received" ? "IN" : "OUT"}
                          </span>{" "}
                          {tx.amount} LFS
                        </p>
                        <p className="text-xs text-zinc-500 mt-1">
                          {formatTimestamp(tx.timestamp)} | block #{tx.block_index} | confirmations:{" "}
                          {tx.confirmations}
                        </p>
                      </div>
                      <p className="text-xs text-zinc-400 font-mono break-all md:text-right">
                        txid: {tx.txid}
                      </p>
                    </div>
                    <div className="mt-3 text-xs text-zinc-500 space-y-1">
                      <p className="break-all">from: {tx.from}</p>
                      <p className="break-all">to: {tx.to}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </main>

      {settingsOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm p-4 md:p-8">
          <div className="max-w-4xl mx-auto max-h-[92vh] overflow-y-auto rounded-2xl border border-zinc-800 bg-zinc-950 p-6 space-y-6">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-medium inline-flex items-center gap-2">
                <Settings className="w-4 h-4" />
                Settings
              </h3>
              <button
                onClick={() => setSettingsOpen(false)}
                className="h-10 w-10 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 inline-flex items-center justify-center"
                aria-label="Close settings"
                title="Close settings"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 space-y-3">
              <p className="text-sm text-zinc-400">Public key</p>
              <p className="font-mono text-xs text-zinc-300 break-all">
                {appState.wallet_public_key ?? "Public key unavailable"}
              </p>
              <button
                onClick={() => void handleCopyValue(appState.wallet_public_key ?? "", "Public key")}
                disabled={!appState.wallet_public_key}
                className="h-10 px-4 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 inline-flex items-center gap-2 disabled:opacity-50"
              >
                <Copy className="w-4 h-4" />
                Copy Public Key
              </button>
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 space-y-3">
              <p className="text-sm text-zinc-400">Minimum peers for transaction broadcast</p>
              <div className="flex flex-col md:flex-row gap-3 md:items-center">
                <input
                  type="number"
                  min={1}
                  step={1}
                  value={minPeersInput}
                  onChange={(e) => setMinPeersInput(e.target.value)}
                  onKeyDown={(event) => {
                    if (event.key !== "Enter") {
                      return;
                    }
                    event.preventDefault();
                    if (!savingMinPeers) {
                      void handleSaveMinPeers();
                    }
                  }}
                  className="w-full md:w-44 h-11 rounded-lg border border-zinc-700 bg-zinc-900 px-3 outline-none focus:border-blue-500"
                  placeholder="2"
                />
                <button
                  onClick={() => void handleSaveMinPeers()}
                  disabled={savingMinPeers}
                  className="h-11 px-5 rounded-lg bg-white text-black font-medium disabled:opacity-50"
                >
                  {savingMinPeers ? "Saving..." : "Save Minimum Peers"}
                </button>
              </div>
              <p className="text-xs text-zinc-500">Default is 2 peers.</p>
              {minPeersValid && parsedMinPeers === 1 && (
                <p className="rounded-lg border border-amber-700/40 bg-amber-900/20 px-3 py-2 text-amber-200 text-sm inline-flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                  Transaction may not execute correctly across the whole network with only 1 peer.
                </p>
              )}
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 space-y-3">
              <p className="text-sm text-zinc-400">Change wallet encryption password</p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <input
                  type="password"
                  value={currentPassphrase}
                  onChange={(e) => setCurrentPassphrase(e.target.value)}
                  onKeyDown={(event) => {
                    if (event.key !== "Enter") {
                      return;
                    }
                    event.preventDefault();
                    if (!changingPassphrase) {
                      void handleChangePassphrase();
                    }
                  }}
                  className="h-11 rounded-lg border border-zinc-700 bg-zinc-900 px-3 outline-none focus:border-blue-500"
                  placeholder="Current password"
                />
                <input
                  type="password"
                  value={newPassphrase}
                  onChange={(e) => setNewPassphrase(e.target.value)}
                  onKeyDown={(event) => {
                    if (event.key !== "Enter") {
                      return;
                    }
                    event.preventDefault();
                    if (!changingPassphrase) {
                      void handleChangePassphrase();
                    }
                  }}
                  className="h-11 rounded-lg border border-zinc-700 bg-zinc-900 px-3 outline-none focus:border-blue-500"
                  placeholder="New password"
                />
                <input
                  type="password"
                  value={confirmNewPassphrase}
                  onChange={(e) => setConfirmNewPassphrase(e.target.value)}
                  onKeyDown={(event) => {
                    if (event.key !== "Enter") {
                      return;
                    }
                    event.preventDefault();
                    if (!changingPassphrase) {
                      void handleChangePassphrase();
                    }
                  }}
                  className="h-11 rounded-lg border border-zinc-700 bg-zinc-900 px-3 outline-none focus:border-blue-500"
                  placeholder="Confirm new password"
                />
              </div>
              <button
                onClick={() => void handleChangePassphrase()}
                disabled={changingPassphrase}
                className="h-11 px-5 rounded-lg bg-white text-black font-medium disabled:opacity-50"
              >
                {changingPassphrase ? "Updating..." : "Change Password"}
              </button>
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 space-y-4">
              <p className="text-sm text-zinc-400">Private key tools</p>

              <div className="space-y-3">
                <label className="text-xs text-zinc-500">Reveal private key (requires password)</label>
                <div className="flex flex-col md:flex-row gap-3">
                  <input
                    type="password"
                    value={revealPassphrase}
                    onChange={(e) => setRevealPassphrase(e.target.value)}
                    onKeyDown={(event) => {
                      if (event.key !== "Enter") {
                        return;
                      }
                      event.preventDefault();
                      if (!revealingPrivateKey) {
                        void handleRevealPrivateKey();
                      }
                    }}
                    className="w-full h-11 rounded-lg border border-zinc-700 bg-zinc-900 px-3 outline-none focus:border-blue-500"
                    placeholder="Wallet password"
                  />
                  <button
                    onClick={() => void handleRevealPrivateKey()}
                    disabled={revealingPrivateKey}
                    className="h-11 px-5 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 font-medium disabled:opacity-50"
                  >
                    {revealingPrivateKey ? "Revealing..." : "Reveal Private Key"}
                  </button>
                </div>
                {revealedPrivateKeyHex && (
                  <div className="rounded-lg border border-zinc-700 bg-zinc-950 p-3 space-y-3">
                    <p className="font-mono text-xs break-all text-zinc-300">
                      {showPrivateKey
                        ? revealedPrivateKeyHex
                        : "................................................................"}
                    </p>
                    <div className="flex flex-wrap gap-2">
                      <button
                        onClick={() => setShowPrivateKey((v) => !v)}
                        className="h-9 px-3 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 inline-flex items-center gap-2"
                      >
                        {showPrivateKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        {showPrivateKey ? "Hide Key" : "Show Key"}
                      </button>
                      <button
                        onClick={() => void handleCopyValue(revealedPrivateKeyHex, "Private key")}
                        className="h-9 px-3 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 inline-flex items-center gap-2"
                      >
                        <Copy className="w-4 h-4" />
                        Copy Key
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <div className="space-y-3">
                <label className="text-xs text-zinc-500">Export private key to .dat (requires password)</label>
                <div className="flex flex-col md:flex-row gap-3">
                  <input
                    type="password"
                    value={exportPassphrase}
                    onChange={(e) => setExportPassphrase(e.target.value)}
                    onKeyDown={(event) => {
                      if (event.key !== "Enter") {
                        return;
                      }
                      event.preventDefault();
                      if (!exportingPrivateKey) {
                        void handleExportPrivateKey();
                      }
                    }}
                    className="w-full h-11 rounded-lg border border-zinc-700 bg-zinc-900 px-3 outline-none focus:border-blue-500"
                    placeholder="Wallet password"
                  />
                  <button
                    onClick={() => void handleExportPrivateKey()}
                    disabled={exportingPrivateKey}
                    className="h-11 px-5 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 font-medium disabled:opacity-50 inline-flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    {exportingPrivateKey ? "Exporting..." : "Export .dat"}
                  </button>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-red-700/40 bg-red-950/20 p-4 space-y-3">
              <p className="text-sm text-red-200">Danger zone</p>
              <p className="text-xs text-red-200/80">
                Delete current wallet files and reset the app to onboarding.
              </p>
              <button
                onClick={() => void handleDeleteWalletConfig()}
                disabled={deletingWalletConfig}
                className="h-11 px-5 rounded-lg border border-red-700 bg-red-900/40 text-red-100 font-medium disabled:opacity-50 inline-flex items-center gap-2"
              >
                <Trash2 className="w-4 h-4" />
                {deletingWalletConfig ? "Deleting..." : "Delete Wallet Configuration"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function TabButton({
  active,
  label,
  onClick,
}: {
  active: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`h-11 rounded-lg border text-sm font-medium transition ${
        active
          ? "border-blue-500 bg-blue-500/15 text-blue-200"
          : "border-zinc-700 bg-zinc-900 text-zinc-300 hover:bg-zinc-800"
      }`}
    >
      {label}
    </button>
  );
}
