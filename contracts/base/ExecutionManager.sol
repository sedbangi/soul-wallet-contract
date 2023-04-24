// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import "./AccountManager.sol";
import "./ModuleManager.sol";
import "./ReceiveManager.sol";

abstract contract ExecutionManager is AccountManager, ModuleManager, ReceiveManager {

    constructor(uint64 _safeLockPeriod, ITrustedModuleManager _trustedModuleManager) ModuleManager(_safeLockPeriod, _trustedModuleManager){}

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }

    /**
     * execute a sequence of transactions
     */
    function executeBatch(
        address[] calldata dest,
        bytes[] calldata func
    ) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        preHook(target, value, data);
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        postHook(target, value, data);
    }

    function _beforeFallback() internal virtual override {
        super._beforeFallback();
    }
}