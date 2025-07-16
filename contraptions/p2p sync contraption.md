node1 --- longest chain (eg. whole chain) => blockchain.json   =>    node2 --- <hash recieved-blockchain.json>

node1 --- <hash blockchain.json>    =>    node2 --- <hash blockchain.json> = <hash recieved-blockchain.json>

node2 --- override blockchain.json with recieved-blockchain.json, adding the transactions that happened while the transfer

node2 --- shorter chain (eg. half of the full chain)
                           


node3 --- new node, no chain



node3 --- ping atleast 2 nodes with the longest chain (here node1 and node2)  => recieved-blockchain_node1.json + recieved-blockchain_node2.json

node3 --- recieves hashes of both chains and compares them => <hash recieved-blockchain_node1.json> + <hash recieved-blockchain_node2.json> if <hash recieved-blockchain_node1.json> = <hash recieved-blockchain_node2.json> merge recieved-blockchain_node1.json + recieved-blockchain_node2.json into blockchain.json