1. working upnp on most routers -- done
2. sync between nodes  -- done
3. peer discovery  -- solution: acquire node's public ip for it to work
4. custom port args
5. simple wallet gui
6. private key signing while offline (local mempool)  -- partially done
7. implement miner's ip in the block
8. finish ip finding via other peers. currently need to modify /whoami to work without known ip.

known bugs:

1. nodes sending a block back to the original miner making it stuck -- solution: add miner's ip to the block and make other nodes ignore it when verification is successful, if failed, send the miner info about rejected block.
2. network reject a transaction when the same amount of tokens is sent twice from a wallet even if it has the balance to do so.
3. 