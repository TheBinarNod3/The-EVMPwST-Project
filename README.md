# The-EVMPwST-Project
This is the repository of the EVMPwST project. This is a one-person project that aims to make life even more private. It features a new type of "binary PNG codes" (not QR codes), encrypted using ChaCha20.

**EVMPwST** is a private, one-person project that aims to provide highly private offline communication using tokens/keys. It features the ability to connect to the recipient/sender using **X25519** public keys, which are strengthened using **HKDF-SHA256**. This connection is secured by **TOR**.

### How does it work and how to use each feature?

### 1. Offline:

**a)** In **AUTO SECURE** mode, the application rejects the concept of tokens. There is no password and no `.txt` file to send. The recipient does not have (and does not receive) any token.

**b)** **MANUAL TOKEN MODE** is simpler, generating a custom steganographic code (not a QR code, but a new type created by the author). The code contains a specific text entered by the user and generates an access key for it.

### 1b. How to use the tools in Offline mode:

**a)** You must first exchange public keys with the other person (you can send them anywhere). Then, encrypt the message to a `.png` file and send it anywhere publicly. When the recipient attempts to decrypt it, they must provide the sender's public key, which will then allow them to decrypt it (**IMPORTANT!** Public keys reset along with RAM).

**b)** **MANUAL TOKEN MODE**: In the "Encrypt" field, enter the message to be sent. The program will analyze and convert the text into an encrypted `.png` file and generate a key for it, which is visible at the top of the screen and in the `out` folder in the program directory. When the recipient wants to decrypt the message, they will need the `.png` code and its key. In this case, sending the `.png` code publicly is most secure.

### 2. TOR Mailing:

**a)** I will provide an explanation in later versions.

**b)** I will provide an explanation in later versions.

### 2b. Using TOR Mailing Tools:

In this case, the recipient starts the "conversation" by clicking the **"Start Receive"** button (**IMPORTANT!** The recipient must have a TOR browser configured and connected running in the background). After clicking "Start Receive," your `.onion` address, address, and public key will appear for copying. You must forward them to the sender, who enters them in the designated fields. After completing the fields, they enter the message they wish to send, and then click **"Send via TOR."** There's also an additional, less useful option that allows you to send a key file for the encrypted code through this system.

***

*The project is not intended to support any illegal activities or other illegal activities.*

*Please, people, report bugs and I will fix them, ask questions and I will answer them, I am here to help you.*

*The project is open-source; anyone can modify it and share it, providing a visible link to the main repository in the description. Please contact me before publishing a fork.*

