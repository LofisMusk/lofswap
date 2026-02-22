import { ArrowUpRight, ArrowDownLeft, Clock, X, CheckCircle2, AlertCircle, Loader2 } from "lucide-react";
import { useState } from "react";

interface Transaction {
  id: string;
  type: 'sent' | 'received' | 'pending';
  amount: string;
  value: string;
  address: string;
  timestamp: string;
  status: 'completed' | 'pending' | 'failed';
  signature: string;
  from: string;
  to: string;
  confirmations: number;
  blockId: string;
}

const transactions: Transaction[] = [
  {
    id: "1",
    type: "received",
    amount: "+125.50 LFS",
    value: "$2,340.00",
    address: "0x742...f21",
    timestamp: "2 hours ago",
    status: "completed",
    signature: "5J7K9mN2pQ3rS4tU6vW8xY9zA1bC3dE5fG7hI9jK1mN3pQ5rS7tU9vW",
    from: "0x8a3d35Bc6634C0532925a3b844Bc9e3f213d14",
    to: "0x742d35Cc6634C0532925a3b844Bc9e3f213f21",
    confirmations: 124,
    blockId: "0x00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054"
  },
  {
    id: "2",
    type: "sent",
    amount: "-85.25 LFS",
    value: "$945.00",
    address: "0x8a3...d14",
    timestamp: "5 hours ago",
    status: "completed",
    signature: "2A3B4c5D6e7F8g9H0i1J2k3L4m5N6o7P8q9R0s1T2u3V4w5X6y7Z8a9B",
    from: "0x742d35Cc6634C0532925a3b844Bc9e3f213f21",
    to: "0x8a3d35Bc6634C0532925a3b844Bc9e3f213d14",
    confirmations: 89,
    blockId: "0x00000000000000000001b8f3a2d47e65b4c26801054b159045c6a7d61617b043"
  },
  {
    id: "3",
    type: "pending",
    amount: "+50.00 LFS",
    value: "$675.00",
    address: "0x4f5...a92",
    timestamp: "1 day ago",
    status: "pending",
    signature: "7C8D9e0F1g2H3i4J5k6L7m8N9o0P1q2R3s4T5u6V7w8X9y0Z1a2B3c4D",
    from: "0x4f5a26Dd7634C0532925a3b844Bc9e3f213a92",
    to: "0x742d35Cc6634C0532925a3b844Bc9e3f213f21",
    confirmations: 3,
    blockId: "pending"
  },
];

export function TransactionHistory() {
  const [selectedTx, setSelectedTx] = useState<Transaction | null>(null);

  return (
    <div className="rounded-2xl bg-zinc-900/50 border border-zinc-800 p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-medium text-white">Recent Transactions</h2>
        <button 
          onClick={() => {}}
          className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          View All
        </button>
      </div>

      <div className="space-y-2">
        {transactions.map((tx) => (
          <div
            key={tx.id}
            onClick={() => setSelectedTx(tx)}
            className="flex items-center justify-between p-4 rounded-xl hover:bg-zinc-900/80 transition-colors cursor-pointer"
          >
            <div className="flex items-center gap-4">
              <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                tx.type === 'sent' ? 'bg-red-500/10' :
                tx.type === 'received' ? 'bg-emerald-500/10' :
                'bg-yellow-500/10'
              }`}>
                {tx.type === 'sent' ? (
                  <ArrowUpRight className="w-5 h-5 text-red-400" />
                ) : tx.type === 'received' ? (
                  <ArrowDownLeft className="w-5 h-5 text-emerald-400" />
                ) : (
                  <Clock className="w-5 h-5 text-yellow-400" />
                )}
              </div>

              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-white font-medium capitalize">{tx.type}</span>
                  <span className="text-zinc-500 text-sm">·</span>
                  <span className="text-zinc-500 text-sm">{tx.amount}</span>
                </div>
                <div className="text-sm text-zinc-500">{tx.address}</div>
              </div>
            </div>

            <div className="text-right">
              <div className={`font-medium ${
                tx.type === 'sent' ? 'text-red-400' :
                tx.type === 'received' ? 'text-emerald-400' :
                'text-yellow-400'
              }`}>
                {tx.amount}
              </div>
              <div className="text-sm text-zinc-500">{tx.value}</div>
              <div className="text-xs text-zinc-600 mt-1">{tx.timestamp}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Transaction Details Modal */}
      {selectedTx && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            {/* Header */}
            <div className="flex items-center justify-between p-6 border-b border-zinc-800">
              <h3 className="text-xl font-semibold text-white">Transaction Details</h3>
              <button
                onClick={() => setSelectedTx(null)}
                className="w-8 h-8 rounded-lg bg-zinc-800 hover:bg-zinc-700 flex items-center justify-center transition-colors"
              >
                <X className="w-4 h-4 text-zinc-400" />
              </button>
            </div>

            {/* Content */}
            <div className="p-6 space-y-6">
              {/* Status Badge */}
              <div className="flex items-center gap-3">
                {selectedTx.status === 'completed' && (
                  <>
                    <div className="w-10 h-10 rounded-full bg-emerald-500/10 flex items-center justify-center">
                      <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    </div>
                    <div>
                      <div className="text-white font-medium">Completed</div>
                      <div className="text-sm text-zinc-500">Transaction successful</div>
                    </div>
                  </>
                )}
                {selectedTx.status === 'pending' && (
                  <>
                    <div className="w-10 h-10 rounded-full bg-yellow-500/10 flex items-center justify-center">
                      <Loader2 className="w-5 h-5 text-yellow-400 animate-spin" />
                    </div>
                    <div>
                      <div className="text-white font-medium">Pending</div>
                      <div className="text-sm text-zinc-500">Awaiting confirmation</div>
                    </div>
                  </>
                )}
                {selectedTx.status === 'failed' && (
                  <>
                    <div className="w-10 h-10 rounded-full bg-red-500/10 flex items-center justify-center">
                      <AlertCircle className="w-5 h-5 text-red-400" />
                    </div>
                    <div>
                      <div className="text-white font-medium">Failed</div>
                      <div className="text-sm text-zinc-500">Transaction failed</div>
                    </div>
                  </>
                )}
              </div>

              {/* Amount */}
              <div className="rounded-xl bg-zinc-800/50 p-4">
                <div className="text-sm text-zinc-500 mb-1">Amount</div>
                <div className={`text-2xl font-semibold ${
                  selectedTx.type === 'sent' ? 'text-red-400' :
                  selectedTx.type === 'received' ? 'text-emerald-400' :
                  'text-yellow-400'
                }`}>
                  {selectedTx.amount}
                </div>
                <div className="text-zinc-400 mt-1">{selectedTx.value}</div>
              </div>

              {/* Details Grid */}
              <div className="space-y-4">
                <div>
                  <div className="text-sm text-zinc-500 mb-2">From</div>
                  <div className="bg-zinc-800/50 rounded-lg p-3 font-mono text-sm text-zinc-300 break-all">
                    {selectedTx.from}
                  </div>
                </div>

                <div>
                  <div className="text-sm text-zinc-500 mb-2">To</div>
                  <div className="bg-zinc-800/50 rounded-lg p-3 font-mono text-sm text-zinc-300 break-all">
                    {selectedTx.to}
                  </div>
                </div>

                <div>
                  <div className="text-sm text-zinc-500 mb-2">Signature</div>
                  <div className="bg-zinc-800/50 rounded-lg p-3 font-mono text-sm text-zinc-300 break-all">
                    {selectedTx.signature}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="text-sm text-zinc-500 mb-2">Confirmations</div>
                    <div className="bg-zinc-800/50 rounded-lg p-3 text-white font-medium">
                      {selectedTx.confirmations} nodes
                    </div>
                  </div>

                  <div>
                    <div className="text-sm text-zinc-500 mb-2">Timestamp</div>
                    <div className="bg-zinc-800/50 rounded-lg p-3 text-white font-medium">
                      {selectedTx.timestamp}
                    </div>
                  </div>
                </div>

                <div>
                  <div className="text-sm text-zinc-500 mb-2">Block ID</div>
                  <div className="bg-zinc-800/50 rounded-lg p-3 font-mono text-sm text-zinc-300 break-all">
                    {selectedTx.blockId}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
