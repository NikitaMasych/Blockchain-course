MAE-VOTING GOVERNMENT SCALE PROTOCOL

1. Check whether the user is eligible to vote.
2. User creates symmetric key (AES_GBC) and encrypts his passportID, after that it gets hashed. - adress creation (privacy guarantee)
	* redo for non-govenment level
3. Server generates asymmetric key pair (RSA) and provides user with it's public content. 
4. User encrypts desired ballot with that key. (noone can see preliminary results and noone can get his/her own choice after voting) 
5. User creates asymmetric key pair (ECDSA/ecp256r1) and signs his encrypted choice. 
6. User creates operation sence is that the user sends his only vote, encrypted choice and choice signature to the server.
	* voted param is set to true when final block, including corresponding operation, gets added to blockchain
7. After the end of the voting, server publishes private choice decryption key corresponding to particular user address to the open source. 

This approach guarantees:

	• Eligibility: only legitimate voters can take part in voting.
	• Unreusability: each voter can vote only once.
	• Anonymity: no one can track user address to the particular person. 
	• Fairness: no one can obtain intermediate voting results.
	• Soundness: invalid ballots are detected and not taken into account during tallying.
	• Completeness: all valid ballots are tallied correctly.
