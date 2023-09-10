from web3 import Web3
import requests
import json
from time import sleep

from web3.middleware import geth_poa_middleware
from web3._utils.events import get_event_data
import sys
import datetime
import logging
import time

# import msvcrt
from functools import lru_cache
import ast
import os

import dicts
import statistics

api_dict = dicts.api_dict
rpc_dict = dicts.rpc_dict
CHAIN_POA = dicts.chain_is_poa
# https://docs.alchemy.com/docs/how-to-add-alchemy-rpc-endpoints-to-metamask#4.-fill-in-the-required-information
GAS_LIMIT = 30  # gw
GAS_FLUCTUATION = 1.16
GWEI = 1e9
ETH_DECIMAL = 1e18
# chain = "optimism"
gas_dict = dicts.gas_dict
#' Failed to submit transaction: invalid sender. can't start a transaction from a non-account' means no-gas specified zksync.  Someone use 8e7 as zk gasLimit, other use 1000000

logging.basicConfig()
logging.getLogger().setLevel(logging.ERROR)


def read_eventlog(tx_hash='0xb05e2178d5cd389c8ba65f8e5167b54fba36ed73a5ae5872190e4811895de32d'):
    binary_hash = bytes.fromhex(tx_hash[2:])  # to reverse back to binaryb
    print(f'{tx_hash} has binary form {binary_hash}')

    tx_receipt = w3.eth.getTransactionReceipt(tx_hash)
    # The regular getTransaction allows you to get details (such as from, to, data and value) for transactions that are not yet mined
    logs = tx_receipt['logs']
    event_abi = {
        'anonymous': False,
        'inputs': [
            {'indexed': True, 'name': 'orderId', 'type': 'uint256'},
            {'indexed': True, 'name': 'recipient', 'type': 'address'},
            {'indexed': True, 'name': 'bundleId', 'type': 'uint64'},
            {'indexed': False, 'name': 'zero', 'type': 'bool'},
            {'indexed': False, 'name': 'boundaryLower', 'type': 'int24'},
            {'indexed': False, 'name': 'amount', 'type': 'uint128'},
        ],
        'name': 'PlaceMakerOrder',
        'type': 'event',
    }
    # EXAMPLE contract = web3.eth.contract(address=Web3.toChecksumAddress(CONTRACT_ADDRESS), abi=ABI)
    # events = contract.events.Transfer.getLogs(fromBlock=CONTRACT_CREATION_BLOCK)

    parsed_logs = []
    for log in logs:
        parsed_log = get_event_data(event_abi, log)
        # eth.abi.decode_log(event_abi, log.data, log.topics)
        parsed_logs.append(parsed_log)

    # Print the parsed logs
    return parsed_logs


def safe_gas_price():

    if chain == 'scroll':
        return 250000000
    return round(w3.eth.gasPrice * GAS_FLUCTUATION)


def _estimate_gas(transactions) -> int:
    # Returns the median of the gas in previous block transactions
    return int(statistics.median(t.gas for t in transactions))


def choice_break():
    while True:
        continue_method, *args = input("How do you want to continue?").strip().split()
        if continue_method in ['c', 'continue']:
            return 'c'
            # c
        elif continue_method in ['e', 'exit']:
            return 'e'
        elif continue_method in ['s', 'sleep']:
            time.sleep(int(args[0]))
            return 'sleep'
            # sleep NUMBER
        else:
            print("invalid")


def display_chain():
    return w3.eth.chain_id


def chain_gas(chain: str):
    default_gas = gas_dict.get(chain)
    if default_gas:
        return default_gas
    else:
        print('CANT get gas')
        sys.exit()
        return 0


def init_w3(chain_id, fast=False):
    # adding web socket, can define and init global in subfunction, other functions can use later
    global w3
    global chain
    chain = chain_id
    if 'wss:' in rpc_dict[chain]:
        w3 = Web3(Web3.WebsocketProvider(rpc_dict[chain]))
    else:
        w3 = Web3(Web3.HTTPProvider(rpc_dict[chain]))

    # add the geth_poa_middleware to handle the PoA consensus like Polygon, BSC, Fantom
    # otherwise trigger The field extraData is 97 bytes, but should be 32. It is quite likely that you are connected to a POA chain
    if chain_id in CHAIN_POA:
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    logging.info(f'{chain}, connect to {rpc_dict[chain]}')
    if not fast:
        logging.info(f'Connection {w3.isConnected()}, last black {w3.eth.block_number}')


def save_gas(limit: int = GAS_LIMIT, time_pause=30, eth_limit=0.004):
    # msvcrt is Windows only
    while w3.eth.gasPrice > GAS_LIMIT * GWEI:
        t0 = time.time()
        print("press enter to stop waiting for lower network fee, g for Go")
        choice = input(f"gas is {w3.eth.gasPrice/GWEI}, input: stop, pause, go")
        if choice == 'stop':
            sys.exit()
        if choice == 'pause':
            sleep(time_pause)
            return
        if choice == 'go':
            return
        # below also works, but only windows
        '''while time.time() - t0 < 30:
            if msvcrt.kbhit():
                if msvcrt.getch() == b'\r':  # not '\n'
                    sys.exit()
                elif msvcrt.getch() == b'g':
                    return
                # time.sleep(1)
        continue'''

    logging.info('gas price check passed, okay to proceed')
    return


def get_from_blockchain(contract, func_name, *args):
    return contract.functions[func_name](*args).call()


# Write data to blockchain, not working
def write_to_blockchain(
    construct_txn: dict,
    private_key,
    contract=None,
    func_name=None,
    **kwargs,  # I modify to **kwargs form *args
) -> bool:

    gas = w3.eth.estimateGas(construct_txn)
    construct_txn.update({'gas': gas})
    # Sign the transaction using the private key
    signed_tx = w3.eth.account.sign_transaction(construct_txn, private_key)
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt['status'] == 1


# https://stackoverflow.com/questions/70583907/how-to-get-an-unsigned-transaction-data-from-web3-py-using-contract-interaction
'''
contract.functions.transfer(paymentrequest.wallet, tokenamount * pow(10, paymentrequest.token.decimals)).call({"to": tokenaddress, "from": "0xbunchoflettersandnumbers"}, )
not good as
txn = contract.encodeABI(fn_name="transfer", args=[paymentrequest.wallet, tokenamount * pow(10, paymentrequest.token.decimals)])
can use either CALL or TRANSACT
diff: A call is a local invocation of a contract function that does not broadcast or publish anything on the blockchain. use it before transact
'''


def write_to_blockchain_ori(contract, func_name, *args) -> bool:
    tx_hash = contract.functions[func_name](*args).transact()
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

    tx_data = w3.eth.getTransaction(tx_receipt['transactionHash'])
    func_obj, func_params = contract.decode_function_input(tx_data.input)
    print(f"func_obj: {func_obj}, func_params: {func_params}")
    return tx_receipt['status'] == 1


def barebone_tx(chain_id):
    # depends on chain and contract (say zk-era tevaera mint: it requires {'chainId': 324, 'gasPrice': 290000000, 'amount': 300000000000000, 'from': '0x520c2465317799867a2cCe2a8Dae0F64f18E7122'} to build)
    block = w3.eth.get_block("latest", full_transactions=True)
    try:
        md_gas = _estimate_gas(block.transactions)
        print(md_gas, ' median gas from prev block')
    except Exception as e:
        md_gas = gas_dict.get(w3.eth.chain_id)
    return {
        "chainId": w3.eth.chain_id,
        # "gas": md_gas,  # chain_gas(chain),
        "gasPrice": safe_gas_price(),  # w3.toWei('50', 'gwei')
    }


def create_tx(
    contract,
    func_name,
    *args,
    # unverified_contract: str = None,
    add_from_addr: str = None,
    eth_amt=0,
    # estimate_gas: bool = True,  # update gas from default gas to tx_estimated
):
    # Purpose: build calldata section, append to tx_json
    # unverified_contract: When using `ContractFunction.build_transaction` from a contract factory you must provide a `to` address with the transaction
    # then Failed to submit transaction: invalid sender. can't start a transaction from a non-account
    # Cannot set 'to' field in contract call build transaction, so only append TO after buildTransaction

    # gas estimation fine for zk-goerli, but base-goerli fails'execution reverted'
    global chain
    for index, arg in enumerate(args):
        logging.debug(f"Positional argument {index + 1}: {arg}")
    tx_json = barebone_tx(chain)
    # if eth_amt >0:
    tx_json["value"] = int(eth_amt * ETH_DECIMAL)
    if add_from_addr:
        tx_json["from"] = add_from_addr  # w3.eth.defaultAccount
        # tx_json["chainId"] = 5  # use goerli=5 as chain (logging), own zk-goerli chain=280
    # https://stackoverflow.com/questions/57580702/how-to-call-a-smart-contract-function-using-python-and-web3-py
    # msg = f'args are{args},  chain_id {display_chain(), TX_JSON: {tx_json}}'
    # if unverified_contract:
    # msg += f'UNVERIFIED CONTRACT FROM {unverified_contract}'
    '''logging.info(f'to build tx:{tx_json}')
    try:
        gas_estimate = contract.functions[func_name](*args).estimateGas(tx_json)
        print(f"Gas estimate: {gas_estimate}")
    except Exception as e:
        print(f"Error estimating gas: {e}")'''
    construct_txn = contract.functions[func_name](*args).buildTransaction(
        tx_json
    )  # this takes *args
    # if unverified_contract:
    # tx_json["to"] = w3.toChecksumAddress(unverified_contract)
    logging.info(f'to sign:{construct_txn}')
    return construct_txn


# NOT support cache
def write_(
    sign_wallet,
    construct_txn,
    eth_value=0,
    key_field="privateKey",
    estimate_gas=True,
    unverified_contract: str = None,
    final_gas_price=None,
):
    '''
    ?arbitrum or rpw was wrong so will fail on estimateGas: web3.exceptions.ContractLogicError: execution reverted: 26
    ValueError: {'code': -32000, 'message': 'gas required exceeds allowance (550000000)'} on Optimism velodrome eth->velo means tx actually will fail, even if we push without estimate, the txhash is out of gas
    '''
    global chain
    logging.info(f'start transacting with ETH transfer{eth_value}')
    if unverified_contract:
        construct_txn["to"] = w3.toChecksumAddress(unverified_contract)
    if eth_value > 0:
        construct_txn.update({'value': eth_value})
    logging.info(f'TX to move {eth_value} ETH. estimate gas:{construct_txn}')
    gas_now = w3.eth.gasPrice

    if estimate_gas:
        save_gas()
        est_gas = w3.eth.estimateGas(construct_txn)
        total_burn = gas_now * est_gas / 1e18
        logging.info(
            f'{gas_now > GAS_LIMIT * GWEI} {gas_now} price > {GAS_LIMIT * GWEI}. TOTAL {total_burn} WILL BE BURNT',
        )

        #'can skip for mainnet as estimating aavi deposit will fail, okay for arbi'

        if not chain == 'goerli':

            print("ADJUSTING GAS")
            construct_txn['gas'] = est_gas
    if final_gas_price:
        construct_txn['gasPrice'] = final_gas_price
    signed_txn = w3.eth.account.signTransaction(construct_txn, sign_wallet[key_field])
    tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    logging.info(f'******tx_hash: {tx_hash.hex()}')  # b'\xa5\xc4\' type into hex
    # bytes.fromhex(tx_hash_hex[2:]) to reverse back to binary
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    logging.info(tx_receipt)
    return tx_receipt['status'] == 1


@lru_cache(maxsize=30)
# Dynamically fetch the ABI of the Smart Contract from Etherscan API
def fetch_abi(address):
    global chain

    print('fetch_abi', ('%s%s' % (api_dict[chain], address)))
    response = requests.get(
        '%s%s' % (api_dict[chain], address),
        headers={
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'
        },
    )
    sleep(0.5)
    if (
        "Just a moment" in response.text
        or "the security" in response.text
        or response.status_code == '403'
    ):
        print(response.status_code, response.text)  # or .content
    response_json = response.json()
    # logging.info(f"response: {response_json['result']}")
    abi_json = json.loads(response_json['result'])
    result = json.dumps(abi_json)

    '''
    # for uniswap.vote triggers TypeError: 'list' object is not callable
    if "implementation" in result:
        logging.debug(abi_json)
        imp_contract_addr = abi_json(
            "implementation"
        )  # seems old logic, doesn't know using the EIP-897 DelegateProxy concept. like ABI for the implementation contract at 0x47ebab13b806773ec2a2d16873e2df770d130b50,
        result = fetch_abi(imp_contract_addr)'''

    return result


def block_time(num_blocks=100):
    current_block = w3.eth.blockNumber

    # Get the average block time
    block_time_sum = 0

    for i in range(current_block - num_blocks + 1, current_block + 1):
        block = w3.eth.getBlock(i)
        parent_block = w3.eth.getBlock(i - 1)
        block_time_sum += block.timestamp - parent_block.timestamp

    average_block_time = block_time_sum / num_blocks
    return average_block_time


def to_epoch(date_string: str):
    # "Apr-18-2023 08:31:31"
    datetime_obj = datetime.datetime.strptime(date_string, '%b-%d-%Y %H:%M:%S')
    epoch_time = int(datetime_obj.timestamp())
    return epoch_time


@lru_cache(maxsize=20)
def init_contract(contract_address: str, proxy_contract: str):
    '''
    if proxy is different, then get abi from it, but call origin contract

    if no api then use https://calldata-decoder.apoorv.xyz/ OR https://lab.miguelmota.com/ethereum-input-data-decoder
    '''

    address = w3.toChecksumAddress(contract_address)
    proxy_address = w3.toChecksumAddress(proxy_contract)
    abi = fetch_abi(proxy_address)
    logging.debug(f'fetched ABI from rpc: {abi}')
    return w3.eth.contract(address=address, abi=abi)

    '''
    contract_address = '0xae7ab96520de3a18e5e111b5eaab095312d7fe84'  #'' # Lido sTEH, proxyed to 0x47ebab13b806773ec2a2d16873e2df770d130b50 
    proxy_contract = '0x47ebab13b806773ec2a2d16873e2df770d130b50'
    # proxy_abi = w3.eth.contract(address=w3.toChecksumAddress(proxy_contract)).abi
    address = w3.toChecksumAddress(contract_address)
    proxy_address = w3.toChecksumAddress(proxy_contract)
    abi = fetch_abi(proxy_address)
    return w3.eth.contract(address=address, abi=abi)
    '''
def try_swap():
    # not finished
    # https://www.publish0x.com/web3dev/web3py-walkthrough-to-swap-tokens-on-uniswap-pancakeswap-ape-xqmpllz
    input_quantity_wei = 1000000000000000000
    swap_path = [input_token_address, output_token_address]
    swap_contract.functions.getAmountsOut(input_quantity_wei, swap_path).call()

    account_address = '0xffffffffffffffffffffffffffffff'
    input_quantity_wei = 1000000000000000000
    minimum_input_quantity_wei = 997000000000000000
    deadline = int(time.time() + 60)
    fun = contract.functions.swapExactTokensForTokens(
        input_quantity_wei, minimum_input_quantity_wei, swap_path, account_address, deadline
    )
    tx = fun.buildTransaction(
        {
            'from': account_address,
            'nonce': w3.eth.getTransactionCount(account_address),
            'gasPrice': Web3.toWei('30', 'gwei'),
        }
    )
    signed_tx = w3.eth.account.signTransaction(tx, my_account.key)
    emitted = w3.eth.sendRawTransaction(signed_tx.rawTransaction)


def add_epoch(start=datetime.datetime.now(), gap=365 * 3):
    return round((start + datetime.timedelta(days=gap)).timestamp())


import random


def big_head_tail_dist(range_start, range_end, num_samples):
    mid = (range_end - range_start) // 2
    head_size = random.randint(0, mid)
    tail_size = num_samples - head_size
    head_samples = random.sample(range(range_start, range_end + 1), head_size)
    tail_samples = random.sample(range(range_start, range_end + 1), tail_size)[::-1]
    return head_samples + tail_samples


import time

# use this to retry with proper gas
def retry_with_decrement(max_retries=3, start_value=10, decrement=1):
    """
    Decorator that retries a function with a decremental argument until it succeeds.
    :param max_retries: The maximum number of times to retry the function.
    :param start_value: The initial value to pass as an argument to the function.
    :param decrement: The amount to decrement the argument value by for each retry.
    :return: The result of the function.

    value needs to be the argument of func
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            retries = 0
            value = start_value

            while retries < max_retries:
                try:
                    result = func(*args, **kwargs, value=value)
                    return result
                except Exception as e:
                    print(f"Exception raised: {e}, retry with new value")
                    # time.sleep(5)
                    value -= decrement
                    retries += 1

            print("Max retries reached, giving up.")

        return wrapper

    return decorator
