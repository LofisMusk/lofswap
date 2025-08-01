1. working upnp on most routers -- done
2. sync between nodes  -- done
3. peer discovery  -- solution: acquire node's public ip for it to work
4. custom port args
5. simple wallet gui
6. private key signing while offline (local mempool)  -- done

known bugs:

1. nodes sending a block back to the original miner making it stuck -- solution: add miner's ip to the block and make other nodes ignore it when verification is successful, if failed, send the miner info about rejected block.