import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./ui/dialog";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Button } from "./ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { ArrowRight } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

interface SendDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function SendDialog({ open, onOpenChange }: SendDialogProps) {
  const [amount, setAmount] = useState("");
  const maxAmount = 1250.50;

  const handleMaxClick = () => {
    setAmount(maxAmount.toString());
    toast.success(`Set to max: ${maxAmount} LFS`);
  };

  const handleSend = () => {
    if (!amount || parseFloat(amount) <= 0) {
      toast.error("Please enter a valid amount");
      return;
    }
    toast.success(`Sending ${amount} LFS successfully!`);
    setTimeout(() => {
      onOpenChange(false);
      setAmount("");
    }, 1000);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-zinc-900 border-zinc-800 text-white sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-2xl">Send Crypto</DialogTitle>
          <DialogDescription className="sr-only">
            Send cryptocurrency to another wallet address
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 py-4">
          <div className="space-y-2">
            <Label htmlFor="asset" className="text-zinc-400">Asset</Label>
            <Select defaultValue="lfs">
              <SelectTrigger id="asset" className="bg-zinc-800 border-zinc-700">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-800 border-zinc-700">
                <SelectItem value="lfs">LofSwap (LFS)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="address" className="text-zinc-400">Recipient Address</Label>
            <Input
              id="address"
              placeholder="0x..."
              className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-600"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="amount" className="text-zinc-400">Amount</Label>
            <div className="relative">
              <Input
                id="amount"
                type="number"
                placeholder="0.00"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-600"
              />
              <button className="absolute right-3 top-1/2 -translate-y-1/2 text-sm text-blue-400 hover:text-blue-300" onClick={handleMaxClick}>
                Max
              </button>
            </div>
            <div className="text-sm text-zinc-500">≈ $0.00 USD</div>
          </div>

          <div className="rounded-lg bg-zinc-800/50 p-4 space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-zinc-500">Network Fee</span>
              <span className="text-white">$2.43</span>
            </div>
            <div className="flex justify-between">
              <span className="text-zinc-500">Total</span>
              <span className="text-white font-medium">$0.00</span>
            </div>
          </div>

          <Button className="w-full bg-white hover:bg-zinc-200 text-black font-medium h-12 rounded-xl" onClick={handleSend}>
            <ArrowRight className="w-4 h-4 mr-2" />
            Confirm Send
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
