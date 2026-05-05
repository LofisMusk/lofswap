import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./ui/dialog";
import { Button } from "./ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { Label } from "./ui/label";
import { Copy, Download } from "lucide-react";
import { toast } from "sonner";

interface ReceiveDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function ReceiveDialog({ open, onOpenChange }: ReceiveDialogProps) {
  const address = "0x742d35Cc6634C0532925a3b844Bc9e3f213f21";

  const handleCopy = () => {
    navigator.clipboard.writeText(address);
    toast.success("Address copied to clipboard!");
  };

  const handleDownload = () => {
    toast.success("QR code downloaded successfully!");
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-zinc-900 border-zinc-800 text-white sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-2xl">Receive Crypto</DialogTitle>
          <DialogDescription className="sr-only">
            Receive cryptocurrency from another wallet
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 py-4">
          <div className="space-y-2">
            <Label htmlFor="receive-asset" className="text-zinc-400">Asset</Label>
            <Select defaultValue="lfs">
              <SelectTrigger id="receive-asset" className="bg-zinc-800 border-zinc-700">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-zinc-800 border-zinc-700">
                <SelectItem value="lfs">LofSwap (LFS)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-4">
            <div className="bg-white p-6 rounded-xl flex items-center justify-center">
              <div className="w-48 h-48 bg-zinc-900 rounded-lg flex items-center justify-center">
                <svg viewBox="0 0 192 192" className="w-full h-full p-4">
                  {/* QR Code placeholder pattern */}
                  <rect width="192" height="192" fill="white"/>
                  <g fill="black">
                    <rect x="16" y="16" width="48" height="48"/>
                    <rect x="128" y="16" width="48" height="48"/>
                    <rect x="16" y="128" width="48" height="48"/>
                    <rect x="72" y="72" width="48" height="48"/>
                  </g>
                </svg>
              </div>
            </div>

            <div className="space-y-2">
              <Label className="text-zinc-400">Your Address</Label>
              <div className="flex gap-2">
                <div className="flex-1 bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-zinc-300 font-mono overflow-hidden text-ellipsis">
                  {address}
                </div>
                <Button
                  variant="outline"
                  size="icon"
                  className="bg-zinc-800 border-zinc-700 hover:bg-zinc-700 text-white h-11 w-11 rounded-lg"
                  onClick={handleCopy}
                >
                  <Copy className="w-4 h-4" />
                </Button>
              </div>
            </div>
          </div>

          <div className="rounded-lg bg-zinc-800/50 p-4 text-sm text-zinc-400">
            <p>Send only LFS to this address. Sending any other asset may result in permanent loss.</p>
          </div>

          <Button
            variant="outline"
            className="w-full bg-zinc-800 border-zinc-700 hover:bg-zinc-700 text-white font-medium h-12 rounded-xl"
            onClick={handleDownload}
          >
            <Download className="w-4 h-4 mr-2" />
            Download QR Code
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
