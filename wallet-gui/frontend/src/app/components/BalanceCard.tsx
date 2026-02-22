import { ArrowUpRight, ArrowDownLeft, Eye, EyeOff } from "lucide-react";
import { Button } from "./ui/button";
import { useState } from "react";

interface BalanceCardProps {
  onSend: () => void;
  onReceive: () => void;
}

export function BalanceCard({ onSend, onReceive }: BalanceCardProps) {
  const [showBalance, setShowBalance] = useState(true);

  return (
    <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-zinc-900 to-zinc-950 p-8 border border-zinc-800">
      <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/5 rounded-full blur-3xl" />
      
      <div className="relative">
        <div className="flex items-center justify-between mb-6">
          <span className="text-sm text-zinc-500 uppercase tracking-wider">Total Balance</span>
          <button
            onClick={() => setShowBalance(!showBalance)}
            className="text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            {showBalance ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
          </button>
        </div>

        <div className="mb-8">
          {showBalance ? (
            <>
              <div className="text-5xl font-light text-white mb-2">
                $24,582.43
              </div>
              <div className="flex items-center gap-2 text-sm">
                <span className="text-emerald-400">+4.23%</span>
                <span className="text-zinc-500">($984.12 today)</span>
              </div>
            </>
          ) : (
            <div className="text-5xl font-light text-white mb-2">••••••••</div>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Button
            onClick={onSend}
            className="bg-white hover:bg-zinc-200 text-black font-medium h-12 rounded-xl transition-all"
          >
            <ArrowUpRight className="w-4 h-4 mr-2" />
            Send
          </Button>
          <Button
            onClick={onReceive}
            className="bg-zinc-800 hover:bg-zinc-700 text-white font-medium h-12 rounded-xl transition-all"
          >
            <ArrowDownLeft className="w-4 h-4 mr-2" />
            Receive
          </Button>
        </div>
      </div>
    </div>
  );
}
