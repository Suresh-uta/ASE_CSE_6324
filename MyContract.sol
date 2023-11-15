// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyGuard {
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "Reentrant call detected");
        locked = true;
        _;
        locked = false;
    }
}

contract ParentContract is ReentrancyGuard {
    uint256 public balance;

    function deposit() public payable {
        balance += msg.value;
    }

    function withdraw(uint256 amount) public nonReentrant {
        require(balance >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balance -= amount;
    }
}

contract ChildContract is ParentContract {
    // This function inherits the reentrancy vulnerability from ParentContract
    function executeVulnerableFunction(uint256 amount) public {
        // An attacker's malicious contract can exploit the reentrancy vulnerability here
        withdraw(amount);
    }
}
