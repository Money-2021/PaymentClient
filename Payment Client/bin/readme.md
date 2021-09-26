
This directory is the place holder, for the proprietry Libararies to support the InterLedger Protocol.
These will be returned by the nominated node, along with the JWToken registration file, required to bind the device to the node HSM Secure Identity.
Place the four supplied dll files inside this directory and build the Payment Client.

vm.data.library.blockchain.api.device.Model   // Device Support
vm.data.library.blockchain.cms                // IETF CMS RFC5652 Cryptographic Message snatax, with ILP Support (re-engineered into JSON).
vm.data.library.blockchain.payment.api        // InterLedger Protocol(ILP)-Payment Message Sets
vm.data.library.blockchain.secureidentity.api // HSM, Secure Identity support

The output executables will also be automatcally placed subordinate to this directory.
