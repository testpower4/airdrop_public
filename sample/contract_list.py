'''
if no api for abi decoder, then use https://calldata-decoder.apoorv.xyz/ OR https://lab.miguelmota.com/ethereum-input-data-decoder

for zk-era which has no abi service, either config 'abi': None, or hard-code 'abi' in here

to improve: read balanceOf still needs a separate entry despite of existing zkape
'''
# contract_file = pathlib.Path(__file__).parent.joinpath('contract_list.json')
# contract_content = open(contract_file, mode='r').read()
token_list = {
    "arbitrum.USDT": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
    "arbitrum.ARB": "0x912ce59144191c1204e64559fe8253a0e49e6548 ",
  
}
contract_col = {
    'syncswap.swap': {  # Swap (Address, Bytes, Address, Bytes, [], Address, Uint256, [], Uint256, Uint256)
        'zk-era': {  # GPT: functionName(address,uint256[],uint256,uint256,uint256[],uint256,uint256,uint256,uint256[],uint256[],uint256[])
            'contract': '0x2da10A1e27bF85cEdD8FFb1AbBe97e53391C0295',  #
            'proxy': '0x2da10A1e27bF85cEdD8FFb1AbBe97e53391C0295',  #
            'abi': None,
        },
    },
    # https://optimism.decent.xyz/ free SBT
    # zpc zeropanda
    'decentxyz.mint': {
        'optimism': {
            'contract': '0x6a886c76693ed6f4319a289e3fe2e670b803a2da',  #
            'proxy': '0x4056334cdca09a54ad0e99c195a8de321406c242',  #
        },
    },
 
}

