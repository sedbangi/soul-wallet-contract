pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ClaimInterest
 * @dev This contract allows users to claim their interest.
 * The interest claim is authenticated by a signature from a trusted signer.
 * The owner of the contract can change the signer.
 */
contract ClaimInterest is Ownable {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    address public signer;
    IERC20 public token;
    mapping(address => uint256) public nonces;

    constructor(address _owner, address _signer, address _token) Ownable(_owner) {
        signer = _signer;
        token = IERC20(_token);
    }

    /**
     * @notice Claim the interest amount.
     * @dev The claim is authenticated by a signature from the trusted signer.
     * @param interestAmount The amount of interest to claim.
     * @param signature The signature from the signer.
     */
    function claimInterest(uint256 interestAmount, uint256 nonce, uint256 expiryTime, bytes memory signature) public {
        require(nonce == nonces[msg.sender], "Invalid nonce");
        require(block.timestamp <= expiryTime, "Signature expired");
        bytes32 message = keccak256(abi.encodePacked(msg.sender, interestAmount, nonce, expiryTime));
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(message);
        require(ethSignedMessageHash.recover(signature) == signer, "Invalid signature");
        nonces[msg.sender] += 1; // Increment nonce for the user
        token.safeTransfer(msg.sender, interestAmount);
    }

    /**
     * @notice Change the trusted signer.
     * @dev Only the owner can change the signer.
     * @param newSigner The address of the new signer.
     */
    function changeSigner(address newSigner) public onlyOwner {
        require(newSigner != address(0), "Invalid address");
        signer = newSigner;
    }

    /**
     * @notice Admin function to force increment a user's nonce
     * @dev signer can increment a user's nonce to invalidate previous signatures
     * @param user The address of the user nonce to change.
     */
    function incrementNonce(address user) public {
        require(msg.sender == signer, "Only signer can change user nonce");
        nonces[user] += 1;
    }
}
