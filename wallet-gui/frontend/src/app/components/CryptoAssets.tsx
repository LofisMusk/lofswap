import { TrendingUp, TrendingDown } from "lucide-react";
import { toast } from "sonner";

interface Asset {
  id: number;
  name: string;
  symbol: string;
  amount: string;
  value: string;
  change: string;
  isPositive: boolean;
}

const assets: Asset[] = [
  {
    id: 1,
    name: "LofSwap",
    symbol: "LFS",
    amount: "1,250.50",
    value: "$15,234.50",
    change: "+5.2%",
    isPositive: true,
  },
];

export function CryptoAssets() {
  return (
    <div className="rounded-2xl bg-zinc-900/50 border border-zinc-800 p-6">
      <h2 className="text-lg font-medium text-white mb-4">Assets</h2>
      
      <div className="space-y-3">
        {assets.map((asset) => (
          <div
            key={asset.id}
            onClick={() => toast.success(`Viewing ${asset.name} details`)}
            className="flex items-center justify-between p-4 rounded-xl bg-zinc-900/80 hover:bg-zinc-800/80 transition-colors cursor-pointer border border-zinc-800/50"
          >
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-full bg-zinc-800 flex items-center justify-center text-xl">
                {asset.symbol}
              </div>
              <div>
                <div className="text-white font-medium">{asset.name}</div>
                <div className="text-sm text-zinc-500">
                  {asset.amount} {asset.symbol}
                </div>
              </div>
            </div>

            <div className="text-right">
              <div className="text-white font-medium">
                {asset.value}
              </div>
              <div className={`text-sm flex items-center gap-1 justify-end ${
                asset.isPositive ? 'text-emerald-400' : 'text-red-400'
              }`}>
                {asset.isPositive ? (
                  <TrendingUp className="w-3 h-3" />
                ) : (
                  <TrendingDown className="w-3 h-3" />
                )}
                {asset.change}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
