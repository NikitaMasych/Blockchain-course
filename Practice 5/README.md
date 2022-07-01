MAE-VOTING GOVERNMENT SCALE PROTOCOL

1. Check whether the user is eligible to vote.
2. User creates symmetric key (AES_GBC) and encrypts his ID, after that it gets hashed. - adress creation (privacy)
	* redo for non-govenment level
3. Server generates asymmetric key pair and provides user with it's public content. 
4. User encrypts desired ballot with that key. (noone can count all choices and noone can get his/her own choice) 
5. User creates asymmetric key pair and signs his encrypted choice, providing server with public key.
6. Pair (encrypted choice, digital signature) gets send to the server.
7. Operation sence is that user sends his only vote, encrypted choice and choice signature to the server.
