# XEPAY RPC API Reference

JSON-RPC over HTTP. Authentication uses the cookie file of the network
(`~/.xepay/.cookie`, `~/.xepay-testnet/.cookie`, `~/.xepay-regtest/.cookie`) or
`rpcuser` / `rpcpassword` from `xepay.conf`. Every method below is available through
the `xepay` command line client (`xepay help`).

## Blockchain

- `getinfo`: general node information.
- `getsupplyinfo`: maximum, circulating and remaining supply, percent mined, current era, estimated remaining blocks.
- `getblockchaininfo`: chain state, active proof-of-work algorithm, retarget interval (3,600 blocks once Xephash is active), activation heights and checkpoint count.
- `getblockcount`, `getbestblockhash`, `getdifficulty`, `getchaintips`.
- `getblockhash <height>`, `getblock <hash>`, `getblockheader <hash>`.
- `getgenesishash`, `getgenesis`.
- `getrawtransaction <txid>`, `decoderawtransaction <txid>`.
- `verifychain`: verify the whole chain.

## Checkpoints

- `getcheckpoints`: the genesis block (checkpoint 0) and the checkpoints of this network.
- `getcheckpoint [height]`: one ready-to-paste line (default: 1000 blocks below the tip).
- `generatecheckpoints [step] [depth]`: a whole table (default: every 1000 blocks, 100 confirmations).

## Mempool and fees

- `getmempoolinfo`: size, total fees, capacity and the fee rate needed for the next block.
- `estimatefee`: default fee (0.01 XEPC), suggested fee now and whether the mempool is congested.
- `testmempoolaccept <txid>`, `validatemempool`.
- `getnonce [address]`: next expected nonce.

## Wallet

- `getbalance [address]`, `getlistwallet`, `getaddressinfo <address>`, `setlabel <address> <label>`.
- `getcreatewallet` (Legacy / Base58Check), `getcreatewalletbech32` (Bech32).
- `sendtoaddress <amount> <to> [from] [fee] [nonce]`: the wallet picks the source address and the fee (0.01 XEPC by default, higher when the mempool is congested).
- `sendmessage <msg> [from] [fee]`, `getmessages [address] [start] [end]`: on-chain messages.
- `importprivkey`, `dumpprivkey`, `dumpwallet`, `backupwallet`, `encryptwallet`, `walletpassphrase`.

## Mining

- `getblocktemplate <mining_address>`: template with transactions chosen by fee rate and the `state_root` to commit to.
- `submitblock <block_json>`: validate and connect a mined block.
- `generatetoaddress <n> <address>`: mine n blocks (useful on regtest).
- `getaddtowallet`, `getaddtoaddress <address>`: choose the mining target.

## Network and control

- `getnetworkinfo`, `getpeerinfo`.
- `stop`: save the chain and stop the node.
