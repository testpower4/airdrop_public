# JUST FOR REFERENCE and discussion, good luck in web3 exploration

etherscan_key_1 = 'DGS'

chain_is_poa = ['optimism', 'arbitrum', 'fantom', 'bsc', 'polygon', 'scroll']
api_dict = {
    'mainnet': f'https://api.etherscan.io/api?module=contract&apikey={etherscan_key_2}&action=getabi&address=',
    'goerli': f'https://api-goerli.etherscan.io/api?module=contract&apikey={etherscan_key_2}&action=getabi&address=',
    'optimism': f'https://api-optimistic.etherscan.io/api?module=contract&apikey={optimistic_key}&action=getabi&address=',
    'zk-era': 'https://api.zksync.io/jsrpc',  # https://docs.zksync.io/api/v0.1/
}


rpc_dict = {
    'mainnet': 'https://eth-mainnet.g.alchemy.com/v2/Z',
    'linea': 'https://rpc.goerli.linea.build',
}

gas_dict = {
    'mainnet': 99000,
    'optimism': 888888,  # chain 110
    'arbitrum': 2888888,  # chain 42161
    'goerli': 220000,
    'zk-goerli': 700001,
    'zk-era': 700001,  # chain 324
    'scroll': 2200009,  # chainid 534353
}